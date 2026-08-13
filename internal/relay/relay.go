// Package relay forwards WireGuard packets between devices that cannot reach each other
// directly.
//
// The forwarding decisions live here and the socket does not: Handle takes a datagram and
// returns what to send, so every rule can be tested without a network. What is left outside
// is a read loop and a write, which is little enough to be obviously correct.
//
// A relay is the one part of meshp that anyone on the internet can send to without
// authenticating, so most of the rules here are about what it refuses to do:
//
//   - It never replies to a sender it has not authenticated with more bytes than arrived, so
//     it cannot be pointed at a spoofed source address and used to amplify traffic at
//     someone else. That is enforced here rather than left to the caller to remember.
//   - It forwards only between keys that presented a valid token for the same network. It
//     does not evaluate ACLs, because those are enforced at the destination (ADR-0007) and a
//     second implementation of the same policy would diverge quietly.
//   - It changes where a key is reachable only on a fresh authenticated hello. A public key
//     is public, so accepting a new address from a mere data frame would let anyone redirect
//     another device's traffic to themselves by asserting its key.
package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/relayproto"
)

// DefaultIdle is how long a session survives without being heard from.
//
// Long enough to outlast a quiet tunnel — agents send keepalives every 25 seconds and
// re-hello periodically — and short enough that a relay's memory reflects who is actually
// connected rather than everyone who ever was.
const DefaultIdle = 5 * time.Minute

// Authenticator decides whether a token grants the use of a key on a network.
//
// An interface because the relay must not be able to mint what it verifies: the control
// plane signs, the relay checks a signature, and the relay holds no copy of the device
// database (ADR-0016).
type Authenticator interface {
	// Authenticate reports which key and network a token grants, or an error. The error
	// text reaches a log, never the wire.
	Authenticate(token []byte) (key relayproto.Key, network string, err error)
}

// Out is a datagram to send.
type Out struct {
	// Via is which of the relay's sockets to send from, as an index into whatever the
	// caller is listening on.
	//
	// It matters because a relay listens on several ports — one is not enough, since
	// networks exist that block UDP 443 while permitting 3478 — and a peer's NAT will only
	// accept a reply whose source is the address it sent to. Forwarding a packet out of the
	// wrong socket produces a relay that works only when both peers happened to choose the
	// same port.
	Via int

	To    netip.AddrPort
	Frame relayproto.Frame
}

// Session is a connected agent.
type Session struct {
	Key     relayproto.Key
	Network string
	Addr    netip.AddrPort

	// Via is the socket this agent said hello on, and therefore the only one it will accept
	// replies from.
	Via int

	LastSeen time.Time
}

// Stats are counters worth exposing: every one of them is a question someone asks when a
// relay is not working.
type Stats struct {
	Sessions           int
	HelloAccepted      uint64
	HelloRefused       uint64
	Forwarded          uint64
	DroppedNoSession   uint64
	DroppedWrongAddr   uint64
	DroppedNoPeer      uint64
	DroppedOtherNet    uint64
	DroppedUndecodable uint64
	Expired            uint64
}

// Server is one relay.
type Server struct {
	auth Authenticator
	clk  clock.Clock
	idle time.Duration
	log  *slog.Logger

	// selfKey identifies this relay in the frames it originates, so an agent can tell a
	// welcome from this relay apart from one from another.
	selfKey relayproto.Key

	mu    sync.Mutex
	byKey map[relayproto.Key]*Session
	stats Stats
}

// Config configures a Server.
type Config struct {
	Auth    Authenticator
	SelfKey relayproto.Key
	Idle    time.Duration
	Clock   clock.Clock
	Log     *slog.Logger
}

// New returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Auth == nil {
		return nil, errors.New("relay: an authenticator is required; a relay that forwards for anyone is an open proxy")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Idle <= 0 {
		cfg.Idle = DefaultIdle
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Server{
		auth:    cfg.Auth,
		clk:     cfg.Clock,
		idle:    cfg.Idle,
		log:     cfg.Log,
		selfKey: cfg.SelfKey,
		byKey:   make(map[relayproto.Key]*Session),
	}, nil
}

// Handle processes one datagram and returns what to send in response.
//
// Returning the replies rather than writing them keeps every rule testable without a socket,
// and makes the anti-amplification property checkable: a caller can assert that nothing
// leaving is larger than what arrived.
func (s *Server) Handle(via int, from netip.AddrPort, datagram []byte) []Out {
	frame, err := relayproto.Decode(datagram)
	if err != nil {
		// Silently. Anything on a public UDP port receives noise, and answering it is both
		// pointless and a way to be used against someone else.
		s.count(func(st *Stats) { st.DroppedUndecodable++ })
		s.log.Debug("undecodable datagram", "from", from, "bytes", len(datagram), "error", err)
		return nil
	}

	switch frame.Type {
	case relayproto.TypeHello:
		return s.hello(via, from, frame)
	case relayproto.TypeSend:
		return s.forward(from, frame)
	case relayproto.TypePing:
		return s.ping(via, from, frame)
	default:
		// Welcome, refused, recv and pong are what a relay emits, not what it accepts. A
		// peer sending one is confused or probing; either way there is nothing to say.
		s.log.Debug("unexpected frame type for a relay", "from", from, "type", frame.Type)
		return nil
	}
}

// hello authenticates an agent and records where it can be reached.
func (s *Server) hello(via int, from netip.AddrPort, frame relayproto.Frame) []Out {
	// The size of what arrived, which bounds what may be sent back to a sender that has not
	// proved anything.
	arrived := relayproto.HeaderLen + len(frame.Payload)

	key, network, err := s.auth.Authenticate(frame.Payload)
	if err != nil {
		s.count(func(st *Stats) { st.HelloRefused++ })
		s.log.Info("refused a hello", "from", from, "error", err)
		return s.refuse(via, from, arrived)
	}

	// The token names the key, so only its holder can move where that key is reachable.
	if key != frame.Key {
		s.count(func(st *Stats) { st.HelloRefused++ })
		s.log.Info("hello key does not match its token", "from", from)
		return s.refuse(via, from, arrived)
	}

	now := s.clk.Now()
	s.mu.Lock()
	previous, existed := s.byKey[key]
	s.byKey[key] = &Session{Key: key, Network: network, Addr: from, Via: via, LastSeen: now}
	s.stats.HelloAccepted++
	s.mu.Unlock()

	if existed && previous.Addr != from {
		// A NAT mapping changed, or the device moved network. Worth a line: it is the
		// signal that a path is about to be renegotiated.
		s.log.Info("a key moved", "from", previous.Addr, "to", from)
	}

	// The observed address is the whole reason an agent talks to a relay before it needs
	// one: it is this device's server-reflexive candidate, and nothing else can tell it
	// (ADR-0016). The control channel's TCP source address is not the same thing.
	//
	// Unmapped before it is reported. A relay listening on [::] sees an IPv4 peer as
	// ::ffff:a.b.c.d, and that string does not equal the plain IPv4 address the agent knows
	// itself by — so comparing a reflexive candidate against a host candidate would never
	// match, and every device would be judged to be behind NAT. Found by deploying a relay
	// and reading what it actually said.
	return []Out{{Via: via, To: from, Frame: relayproto.Frame{
		Type:    relayproto.TypeWelcome,
		Key:     s.selfKey,
		Payload: []byte(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()).String()),
	}}}
}

// refuse tells a sender its hello was rejected, if that can be done without amplifying.
//
// The reason is deliberately uninformative: a relay that explains why a token failed is an
// oracle for guessing tokens. And if a refusal would be larger than the datagram that
// prompted it, nothing is sent at all — a sender that hands over a one-byte token has not
// earned a reply, and answering it would let an attacker bounce slightly larger packets off
// this relay at a spoofed victim. A real token is much larger than "refused", so a genuine
// agent with an expired token still learns what happened.
func (s *Server) refuse(via int, to netip.AddrPort, arrived int) []Out {
	frame := relayproto.Frame{
		Type:    relayproto.TypeRefused,
		Key:     s.selfKey,
		Payload: []byte("refused"),
	}
	if relayproto.HeaderLen+len(frame.Payload) > arrived {
		s.log.Debug("dropping a refusal that would be larger than the hello", "to", to)
		return nil
	}
	return []Out{{Via: via, To: to, Frame: frame}}
}

// forward carries a packet to the peer it names.
func (s *Server) forward(from netip.AddrPort, frame relayproto.Frame) []Out {
	now := s.clk.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Who is sending. Established by the source address, not by anything in the frame: the
	// frame names the destination, and a sender that has not said hello has proved nothing.
	sender := s.senderAtLocked(from)
	if sender == nil {
		s.stats.DroppedNoSession++
		return nil
	}
	sender.LastSeen = now

	dest, ok := s.byKey[frame.Key]
	if !ok {
		// Silently, and deliberately: telling a sender that a key is unknown would make the
		// relay a presence oracle for any key anyone cares to guess.
		s.stats.DroppedNoPeer++
		return nil
	}
	if dest.Network != sender.Network {
		// The one policy a relay enforces. Not ACLs — those belong at the destination
		// (ADR-0007) — but two customers must never be able to reach each other through
		// shared infrastructure.
		s.stats.DroppedOtherNet++
		s.log.Warn("refused to forward across networks",
			"from_network", sender.Network, "to_network", dest.Network)
		return nil
	}

	s.stats.Forwarded++
	// Rewritten to name the sender, because that is what tells the receiving agent which
	// peer this came from and therefore which of its sockets to deliver it on. Forwarding
	// without rewriting would send every packet back where it came from.
	// Out of the socket the destination is talking to, not the one this arrived on. A peer's
	// NAT only accepts a datagram whose source is the address it sent to, so sending from
	// the wrong socket would work only when both peers happened to pick the same port.
	return []Out{{Via: dest.Via, To: dest.Addr, Frame: relayproto.Frame{
		Type:    relayproto.TypeRecv,
		Key:     sender.Key,
		Payload: frame.Payload,
	}}}
}

// ping answers a keepalive, which is how an agent holds its NAT mapping open.
func (s *Server) ping(via int, from netip.AddrPort, frame relayproto.Frame) []Out {
	now := s.clk.Now()

	s.mu.Lock()
	sender := s.senderAtLocked(from)
	if sender == nil {
		s.stats.DroppedNoSession++
		s.mu.Unlock()
		return nil
	}
	sender.LastSeen = now
	s.mu.Unlock()

	// The payload is echoed so the agent can measure a round trip, and echoing exactly what
	// arrived means the reply can never be larger than the request.
	return []Out{{Via: via, To: from, Frame: relayproto.Frame{
		Type:    relayproto.TypePong,
		Key:     s.selfKey,
		Payload: frame.Payload,
	}}}
}

// senderAtLocked finds the live session reachable at an address.
//
// A session is only usable from the address its hello came from. A public key is public, so
// if a data frame could move a session, anyone could redirect another device's traffic to
// themselves by asserting its key — they could not decrypt it, but they could deny it and
// watch it. Moving requires a fresh authenticated hello.
func (s *Server) senderAtLocked(from netip.AddrPort) *Session {
	for _, sess := range s.byKey {
		if sess.Addr != from {
			continue
		}
		if s.clk.Now().Sub(sess.LastSeen) > s.idle {
			return nil
		}
		return sess
	}
	return nil
}

// Expire forgets sessions nothing has been heard from, and reports how many went.
//
// Called on a timer by the caller rather than on every datagram: a relay's hot path should
// not walk every session it holds.
func (s *Server) Expire() int {
	cutoff := s.clk.Now().Add(-s.idle)

	s.mu.Lock()
	defer s.mu.Unlock()
	var gone int
	for key, sess := range s.byKey {
		if sess.LastSeen.Before(cutoff) {
			delete(s.byKey, key)
			gone++
		}
	}
	s.stats.Expired += uint64(gone)
	return gone
}

// Stats returns a snapshot of the counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	out.Sessions = len(s.byKey)
	return out
}

// Session reports what the relay knows about a key, for diagnostics.
func (s *Server) Session(key relayproto.Key) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byKey[key]
	if !ok {
		return Session{}, false
	}
	return *sess, true
}

func (s *Server) count(f func(*Stats)) {
	s.mu.Lock()
	f(&s.stats)
	s.mu.Unlock()
}

// String renders stats for a log line.
func (st Stats) String() string {
	return fmt.Sprintf("sessions=%d forwarded=%d hello_ok=%d hello_refused=%d "+
		"dropped(no_session=%d wrong_addr=%d no_peer=%d other_net=%d undecodable=%d) expired=%d",
		st.Sessions, st.Forwarded, st.HelloAccepted, st.HelloRefused,
		st.DroppedNoSession, st.DroppedWrongAddr, st.DroppedNoPeer,
		st.DroppedOtherNet, st.DroppedUndecodable, st.Expired)
}
