package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/meshpnet/meshp/internal/logx"
)

// readTimeout bounds a single TCP exchange.
//
// A DNS client over TCP sends a length and a message and expects an answer; anything that
// opens a connection and then waits is either broken or holding a file descriptor on
// purpose. Five seconds is far longer than a loopback exchange needs.
const readTimeout = 5 * time.Second

// Server answers queries for the zones a device holds.
//
// Loopback only, and that is a decision rather than a default. The egress kill switch
// permits loopback unconditionally — its comment names "a local resolver" among the things
// it must not break — so a device that has locked itself down can still resolve. A resolver
// reachable from the network would also be one anybody on the café Wi-Fi could ask what
// machines are in your customers' networks.
type Server struct {
	zones *Zones
	log   *slog.Logger

	// bindPair is a field so the retry below can be proved by a test rather than argued
	// for. Nothing outside this package sets it.
	bindPair func(netip.AddrPort) (*net.UDPConn, *net.TCPListener, error)

	mu   sync.Mutex
	addr netip.AddrPort
	udp  *net.UDPConn
	tcp  *net.TCPListener
}

// NewServer returns a resolver serving these zones.
func NewServer(zones *Zones, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{zones: zones, log: log, bindPair: bindPair}
}

// ErrNotLoopback means somebody asked this to listen where it must not.
var ErrNotLoopback = errors.New("dns: the resolver listens on loopback only")

// Bind takes the sockets and returns, so a caller knows whether it has a resolver before it
// carries on.
//
// Separate from serving, and that separation is load-bearing rather than tidiness. When the
// two were one call the daemon had to start it in a goroutine, which meant everything after
// that line ran before the sockets existed — so `meshp status` could truthfully report no
// resolver on a device that was about to have one, and the end-to-end assertion guarding
// this feature failed on a slower machine. Binding is fast and can fail; serving is neither.
func (s *Server) Bind(addr netip.AddrPort) error {
	if !addr.Addr().IsLoopback() {
		return ErrNotLoopback
	}

	// Retried only when the kernel is the one choosing. A caller that named a port wants
	// that port, and asking again for a port somebody else holds would fail the same way
	// ten times and call it diligence.
	attempts := 1
	if addr.Port() == 0 {
		attempts = bindAttempts
	}

	var udp *net.UDPConn
	var tcp *net.TCPListener
	var err error
	for range attempts {
		udp, tcp, err = s.bindPair(addr)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}

	bound := tcp.Addr().(*net.TCPAddr).AddrPort()

	s.mu.Lock()
	s.udp, s.tcp, s.addr = udp, tcp, bound
	s.mu.Unlock()

	s.log.Info("resolver listening", "addr", bound.String())
	return nil
}

// bindAttempts bounds the search for a port that is free in both protocols.
//
// There is no call that reserves one. Asking for port zero has the kernel choose for the
// protocol being bound, knowing nothing about the other, so the second bind can fail on the
// number the first just succeeded with — and did: a CI run lost its resolver to `listen tcp
// 127.0.0.1:41230: bind: address already in use` after UDP had been given 41230. Retrying is
// the mechanism rather than a workaround, because a fresh draw is the only way to ask again.
//
// Ten because each attempt is two syscalls against a range of some 28,000 ports, so ten
// consecutive collisions means the machine is out of ports and a resolver is not its problem.
const bindAttempts = 10

// bindPair takes the same port in both protocols, or neither.
//
// TCP chooses and UDP matches, which is the way round that makes a collision rare: every
// outbound connection on the machine holds a TCP ephemeral port, while UDP's range is nearly
// empty. Asking the crowded side to pick a port it knows is free, then asking the quiet side
// for that number, is far likelier to succeed than the reverse — which is what this used to
// do.
//
// Both protocols, because DNS is both: a truncated UDP answer tells the client to retry over
// TCP, and a client that cannot is stuck with whatever fitted in 512 bytes.
func bindPair(addr netip.AddrPort) (*net.UDPConn, *net.TCPListener, error) {
	tcp, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
	if err != nil {
		return nil, nil, err
	}
	// Read back from the socket rather than from what was asked for, because a caller may
	// ask for zero and let the kernel choose — and the chosen port is both what UDP must
	// now match and what gets handed to the system resolver.
	bound := tcp.Addr().(*net.TCPAddr).AddrPort()

	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(bound))
	if err != nil {
		_ = tcp.Close()
		return nil, nil, err
	}
	return udp, tcp, nil
}

// Serve answers queries until ctx is done, then gives the sockets back.
//
// Returns immediately when nothing is bound, so a caller that ignored a Bind failure does
// not block forever on a resolver it does not have.
func (s *Server) Serve(ctx context.Context) {
	s.mu.Lock()
	udp, tcp := s.udp, s.tcp
	s.mu.Unlock()
	if udp == nil || tcp == nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.serveUDP(udp) }()
	go func() { defer wg.Done(); s.serveTCP(tcp) }()

	<-ctx.Done()
	_ = udp.Close()
	_ = tcp.Close()
	wg.Wait()

	s.mu.Lock()
	s.udp, s.tcp, s.addr = nil, nil, netip.AddrPort{}
	s.mu.Unlock()
}

// Addr is where the resolver is listening, or the zero value when it is not.
//
// Read rather than assumed, for the same reason the tunnel's listen port is: asking for any
// port means the kernel chose, and its choice is the thing the rest of the system needs.
func (s *Server) Addr() netip.AddrPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

func (s *Server) serveUDP(conn *net.UDPConn) {
	buf := make([]byte, MaxMessage)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // the listener was closed
		}
		reply := s.answer(buf[:n])
		if reply == nil {
			// Unparseable beyond the point of having an id to reply to. Dropped rather
			// than answered: there is nothing truthful to say, and replying to a forged
			// source would make this a reflector.
			continue
		}
		if _, err := conn.WriteToUDPAddrPort(reply, from); err != nil {
			s.log.Debug("could not send a reply", "error", logx.SafeError(err))
		}
	}
}

func (s *Server) serveTCP(listener *net.TCPListener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go s.serveConn(conn)
	}
}

// serveConn handles one TCP client. A single exchange per connection: this is not a
// high-traffic resolver, and keeping connections alive is state to get wrong for no gain.
func (s *Server) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(readTimeout))

	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint16(length[:])
	if n == 0 || int(n) > MaxMessage {
		// Bounded even over TCP, where the protocol would allow 65535. Nothing this
		// answers needs more, and an unbounded allocation driven by two bytes from a
		// client is a way to be made to hold memory.
		return
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	reply := s.answer(buf)
	if reply == nil {
		return
	}

	out := make([]byte, 2, 2+len(reply))
	binary.BigEndian.PutUint16(out, uint16(len(reply)))
	if _, err := conn.Write(append(out, reply...)); err != nil {
		s.log.Debug("could not send a reply", "error", logx.SafeError(err))
	}
}

// answer turns a query into a response, or nil when there is nothing truthful to send.
func (s *Server) answer(raw []byte) []byte {
	q, err := ParseQuery(raw)
	if err != nil {
		// An id is the one thing worth recovering from a malformed query: a client that
		// gets FORMERR learns it sent nonsense, where silence looks like packet loss and
		// makes it retry. Below the header there is not even that.
		if len(raw) >= 2 {
			return BuildResponse(Query{ID: binary.BigEndian.Uint16(raw[0:2])}, RCodeFormErr, nil)
		}
		return nil
	}

	if q.Class != ClassIN {
		return BuildResponse(q, RCodeRefused, nil)
	}
	switch q.Type {
	case TypeA, TypeAAAA:
	default:
		// Everything else — MX, TXT, ANY — is refused rather than answered empty. An
		// empty success says "this name has no such record", which is a claim about a
		// zone this does not own.
		return BuildResponse(q, RCodeRefused, nil)
	}

	res := s.zones.Lookup(q.Name)
	if len(res.Ambiguous) > 0 {
		// Logged, because the error a person sees is a bare REFUSED and this is the only
		// place that can say why. Through logx.Safe: the name came off a socket.
		s.log.Warn("refusing an ambiguous name rather than choosing a network",
			"name", logx.Safe(q.Name), "matches", len(res.Ambiguous),
			"alternatives", logx.Safe(joinNames(res.Ambiguous)))
	}

	answers := make([]Answer, 0, len(res.Addrs))
	for _, addr := range res.Addrs {
		answers = append(answers, Answer{Addr: addr, TTL: DefaultTTL})
	}
	return BuildResponse(q, res.Code, answers)
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
