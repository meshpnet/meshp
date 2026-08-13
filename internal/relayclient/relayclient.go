// Package relayclient is an agent's side of the relay protocol.
//
// It connects to a relay, learns the address the relay sees it at, and carries opaque packets
// to and from other keys. It knows nothing about WireGuard: what it moves are bytes the agent
// took off a socket, which is what keeps a relay unable to read anything (Invariant 3).
//
// A relay offers several ports and this tries them in order, because one port is not enough.
// UDP 443 looks like the friendliest choice and is the one most likely to be filtered — it
// carries QUIC, and networks that want to inspect HTTP block it to force a fallback. That is
// measured rather than assumed: on the network this was developed on, 443 is dropped and 3478
// passes.
package relayclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/relayproto"
)

// DefaultHelloTimeout is how long one endpoint gets to answer before the next is tried.
//
// Short, because the common failure is a filtered port that will never answer, and an agent
// working through three of them should not take a minute to find the one that works.
const DefaultHelloTimeout = 2 * time.Second

// KeepaliveInterval is how often a ping holds the NAT mapping to the relay open.
//
// Twenty seconds, inside the shortest NAT UDP timeouts commonly seen. A mapping that lapses
// does not break the tunnel visibly — it breaks it the next time the peer sends something,
// which is much harder to attribute.
const KeepaliveInterval = 20 * time.Second

// Errors callers distinguish.
var (
	// ErrNoEndpoint means no advertised endpoint answered.
	ErrNoEndpoint = errors.New("relayclient: no relay endpoint answered")
	// ErrRefused means the relay rejected our token.
	ErrRefused = errors.New("relayclient: the relay refused our token")
	// ErrClosed means the client has been closed.
	ErrClosed = errors.New("relayclient: closed")
)

// Client is one connection to one relay.
type Client struct {
	key   relayproto.Key
	token []byte
	log   *slog.Logger

	// endpoint is the address that answered, kept so a log line and a reconnect can name it.
	endpoint string

	mu        sync.Mutex
	conn      *net.UDPConn
	reflexive netip.AddrPort
	closed    bool

	// out is the write buffer. Guarded by mu because a datagram must be encoded and sent
	// without another goroutine interleaving into the same bytes.
	out []byte
}

// Options configures a Dial.
type Options struct {
	// Endpoints are the relay's addresses, best first. Tried in order.
	Endpoints []string

	// Key is this device's WireGuard public key, which is what the relay knows it by.
	Key relayproto.Key

	// Token is the capability the control plane issued for this key and network.
	Token []byte

	HelloTimeout time.Duration
	Log          *slog.Logger
}

// Dial connects to the first endpoint that answers, and returns a client that has already
// been welcomed.
//
// Sequential rather than parallel: the endpoints are ordered by preference, and racing them
// would mean deliberately opening sessions on relays we then abandon — which is work for the
// relay and noise in its counters, to save a second on a path that is then used for hours.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if len(opts.Endpoints) == 0 {
		return nil, errors.New("relayclient: no endpoints to try")
	}
	if len(opts.Token) == 0 {
		return nil, errors.New("relayclient: no token; a relay will refuse an unauthenticated hello")
	}
	if opts.HelloTimeout <= 0 {
		opts.HelloTimeout = DefaultHelloTimeout
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}

	var refused bool
	for _, endpoint := range opts.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		c, err := dialOne(ctx, endpoint, opts)
		if err == nil {
			opts.Log.Info("relay connected",
				"endpoint", endpoint, "reflexive", c.Reflexive().String())
			return c, nil
		}
		if errors.Is(err, ErrRefused) {
			// A refusal is about the token, not the path, so the next endpoint will refuse
			// too. Recorded and the remaining endpoints still tried, because a relay that
			// refuses could also be one that is misconfigured while a sibling is not.
			refused = true
		}
		opts.Log.Debug("relay endpoint did not answer",
			"endpoint", endpoint, "error", logx.SafeError(err))
	}

	if refused {
		return nil, ErrRefused
	}
	return nil, fmt.Errorf("%w: tried %d", ErrNoEndpoint, len(opts.Endpoints))
}

func dialOne(ctx context.Context, endpoint string, opts Options) (*Client, error) {
	raddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("relayclient: %q: %w", endpoint, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("relayclient: dialling %s: %w", endpoint, err)
	}

	c := &Client{
		key:      opts.Key,
		token:    opts.Token,
		log:      opts.Log,
		endpoint: endpoint,
		conn:     conn,
		out:      make([]byte, relayproto.HeaderLen+relayproto.MaxPayload),
	}

	if err := c.hello(ctx, opts.HelloTimeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

// hello authenticates and records the address the relay reports seeing us at.
func (c *Client) hello(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	if err := c.send(relayproto.Frame{
		Type: relayproto.TypeHello, Key: c.key, Payload: c.token,
	}); err != nil {
		return err
	}

	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	in := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)
	for {
		n, err := c.conn.Read(in)
		if err != nil {
			return fmt.Errorf("relayclient: %s did not answer: %w", c.endpoint, err)
		}
		frame, err := relayproto.Decode(in[:n])
		if err != nil {
			// Noise, or a relay speaking a protocol we do not. Keep waiting until the
			// deadline rather than giving up on the endpoint for one bad datagram.
			continue
		}

		switch frame.Type {
		case relayproto.TypeWelcome:
			// The address the relay sees is this device's server-reflexive candidate — the
			// thing nothing else can tell it, and the reason to talk to a relay before
			// needing one (ADR-0016).
			seen, err := netip.ParseAddrPort(string(frame.Payload))
			if err != nil {
				return fmt.Errorf("relayclient: %s welcomed us with an unparseable address %q: %w",
					c.endpoint, logx.Safe(string(frame.Payload)), err)
			}
			c.mu.Lock()
			c.reflexive = seen
			c.mu.Unlock()
			return nil

		case relayproto.TypeRefused:
			return fmt.Errorf("%w: %s", ErrRefused, c.endpoint)

		default:
			// Something else arriving before the welcome is not fatal.
			continue
		}
	}
}

// Reflexive is the address the relay reports seeing this device at.
func (c *Client) Reflexive() netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reflexive
}

// Endpoint is the relay address that answered.
func (c *Client) Endpoint() string { return c.endpoint }

// Send carries a packet to a peer through the relay.
func (c *Client) Send(peer relayproto.Key, payload []byte) error {
	if len(payload) > relayproto.MaxPayload {
		// Refused rather than truncated: a truncated WireGuard packet fails authentication
		// at the far end, so the symptom would be a peer that handshakes and goes quiet.
		return fmt.Errorf("relayclient: %d bytes is more than a relayed packet may carry (%d)",
			len(payload), relayproto.MaxPayload)
	}
	return c.send(relayproto.Frame{Type: relayproto.TypeSend, Key: peer, Payload: payload})
}

// Ping asks the relay to answer, which holds the NAT mapping open and measures the path.
func (c *Client) Ping(nonce []byte) error {
	return c.send(relayproto.Frame{Type: relayproto.TypePing, Key: c.key, Payload: nonce})
}

func (c *Client) send(frame relayproto.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	n, err := frame.Encode(c.out)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(c.out[:n]); err != nil {
		return fmt.Errorf("relayclient: sending to %s: %w", c.endpoint, err)
	}
	return nil
}

// Receive waits for one relayed packet and reports which peer it came from.
//
// The payload is copied into buf rather than aliasing an internal buffer, because the caller
// hands it to a kernel socket and a shared buffer would be overwritten by the next read.
//
// A pong is consumed here rather than returned: it exists to keep a mapping open, and a
// caller waiting for peer traffic should not have to know that.
func (c *Client) Receive(buf []byte) (relayproto.Key, int, error) {
	in := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)
	for {
		c.mu.Lock()
		closed, conn := c.closed, c.conn
		c.mu.Unlock()
		if closed {
			return relayproto.Key{}, 0, ErrClosed
		}

		n, err := conn.Read(in)
		if err != nil {
			return relayproto.Key{}, 0, err
		}
		frame, err := relayproto.Decode(in[:n])
		if err != nil {
			continue // noise on a public port
		}

		switch frame.Type {
		case relayproto.TypeRecv:
			if len(frame.Payload) > len(buf) {
				return relayproto.Key{}, 0, fmt.Errorf(
					"relayclient: a %d-byte packet does not fit a %d-byte buffer",
					len(frame.Payload), len(buf))
			}
			return frame.Key, copy(buf, frame.Payload), nil

		case relayproto.TypePong, relayproto.TypeWelcome:
			continue

		case relayproto.TypeRefused:
			// The relay has stopped accepting us — most likely the token expired. The caller
			// has to get another and reconnect, so this is worth reporting rather than
			// looping on.
			return relayproto.Key{}, 0, ErrRefused

		default:
			continue
		}
	}
}

// SetReadDeadline bounds a Receive.
func (c *Client) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	return c.conn.SetReadDeadline(t)
}

// Close releases the socket. Safe to call twice, because the agent closes on shutdown and on
// every error path and should not have to remember which came first.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}
