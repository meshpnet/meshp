package relayclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/relay"
	"github.com/meshpnet/meshp/internal/relayproto"
	"github.com/meshpnet/meshp/internal/relaytoken"
)

// These run against a real relay over real sockets. A fake relay would only prove the client
// agrees with my idea of the protocol; the point is that it agrees with the relay.

func key(b byte) relayproto.Key {
	var k relayproto.Key
	for i := range k {
		k[i] = b
	}
	return k
}

var network = func() [16]byte {
	var n [16]byte
	copy(n[:], "acme------------")
	return n
}()

type fixture struct {
	t         *testing.T
	priv      ed25519.PrivateKey
	endpoints []string
	server    *relay.Server
}

// start runs a relay on the given number of ephemeral ports and returns their addresses.
func start(t *testing.T, ports int) *fixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv, err := relay.New(relay.Config{
		Auth:    tokenAuth{public: pub},
		SelfKey: key(0xFF),
		Clock:   clock.System{},
		Log:     discard,
	})
	if err != nil {
		t.Fatal(err)
	}

	var conns []*net.UDPConn
	var endpoints []string
	for range ports {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		endpoints = append(endpoints, conn.LocalAddr().String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, len(conns))
	for i, conn := range conns {
		go func(via int, conn *net.UDPConn) {
			defer func() { done <- struct{}{} }()
			in := make([]byte, 4096)
			out := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)
			for {
				n, from, err := conn.ReadFromUDPAddrPort(in)
				if err != nil {
					return
				}
				for _, o := range srv.Handle(via, from, in[:n]) {
					written, err := o.Frame.Encode(out)
					if err != nil {
						continue
					}
					_, _ = conns[o.Via].WriteToUDPAddrPort(out[:written], o.To)
				}
			}
		}(i, conn)
	}
	t.Cleanup(func() {
		cancel()
		for _, c := range conns {
			_ = c.Close()
		}
		for range conns {
			<-done
		}
	})
	_ = ctx

	return &fixture{t: t, priv: priv, endpoints: endpoints, server: srv}
}

type tokenAuth struct{ public ed25519.PublicKey }

func (a tokenAuth) Authenticate(token []byte) (relayproto.Key, string, error) {
	grant, err := relaytoken.Verify(a.public, token, time.Now())
	if err != nil {
		return relayproto.Key{}, "", err
	}
	return grant.Key, grant.Network(), nil
}

func (f *fixture) token(k byte) []byte {
	f.t.Helper()
	tok, err := relaytoken.Issue(f.priv, key(k), network, time.Now().Add(time.Minute))
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func (f *fixture) dial(k byte, endpoints []string) *Client {
	f.t.Helper()
	c, err := Dial(context.Background(), Options{
		Endpoints: endpoints,
		Key:       key(k),
		Token:     f.token(k),
	})
	if err != nil {
		f.t.Fatalf("Dial: %v", err)
	}
	f.t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestAClientIsWelcomedAndLearnsItsOwnAddress(t *testing.T) {
	f := start(t, 1)
	c := f.dial(1, f.endpoints)

	if c.Endpoint() != f.endpoints[0] {
		t.Errorf("connected to %s, want %s", c.Endpoint(), f.endpoints[0])
	}
	// The reflexive address: what the relay sees, which over loopback is this socket itself.
	if !c.Reflexive().IsValid() {
		t.Error("no reflexive address was learned, which is the reason to talk to a relay at all")
	}
	if c.Reflexive().Port() == 0 {
		t.Error("the reflexive address has no port")
	}
}

func TestAPacketReachesAnotherClient(t *testing.T) {
	f := start(t, 1)
	a := f.dial(1, f.endpoints)
	b := f.dial(2, f.endpoints)

	payload := []byte("a wireguard packet, notionally")
	if err := a.Send(key(2), payload); err != nil {
		t.Fatal(err)
	}

	if err := b.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	from, n, err := b.Receive(buf)
	if err != nil {
		t.Fatalf("B received nothing: %v", err)
	}
	if from != key(1) {
		t.Error("the packet does not name A, so B cannot tell which peer sent it")
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("payload is %q, want %q", buf[:n], payload)
	}
}

// The reason a relay offers several ports: a filtered one must not stop an agent connecting.
// Here the first two endpoints are dead, standing in for a network that drops UDP 443.
func TestABlockedPortIsSkipped(t *testing.T) {
	f := start(t, 1)

	// Two addresses nothing is listening on. Discard-prefix documentation addresses would
	// hang; unbound loopback ports refuse or drop quickly.
	dead1 := freeLoopbackAddr(t)
	dead2 := freeLoopbackAddr(t)

	c, err := Dial(context.Background(), Options{
		Endpoints:    []string{dead1, dead2, f.endpoints[0]},
		Key:          key(1),
		Token:        f.token(1),
		HelloTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Dial did not fall through to the working endpoint: %v", err)
	}
	defer func() { _ = c.Close() }()

	if c.Endpoint() != f.endpoints[0] {
		t.Errorf("connected to %s, want the working endpoint %s", c.Endpoint(), f.endpoints[0])
	}
}

func TestNoEndpointAnsweringIsReportedAsSuch(t *testing.T) {
	f := start(t, 1)

	_, err := Dial(context.Background(), Options{
		Endpoints:    []string{freeLoopbackAddr(t), freeLoopbackAddr(t)},
		Key:          key(1),
		Token:        f.token(1),
		HelloTimeout: 200 * time.Millisecond,
	})
	if !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("got %v, want ErrNoEndpoint", err)
	}
}

// A refused token is a different problem from an unreachable relay, and an agent has to tell
// them apart: one means get a new token, the other means try another path.
func TestARefusedTokenIsDistinctFromAnUnreachableRelay(t *testing.T) {
	f := start(t, 1)

	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := relaytoken.Issue(other, key(1), network, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	_, err = Dial(context.Background(), Options{
		Endpoints:    f.endpoints,
		Key:          key(1),
		Token:        forged,
		HelloTimeout: time.Second,
	})
	if !errors.Is(err, ErrRefused) {
		t.Errorf("got %v, want ErrRefused", err)
	}
	if errors.Is(err, ErrNoEndpoint) {
		t.Error("a refusal was reported as an unreachable relay, which would send an agent retrying forever")
	}
}

func TestDiallingWithoutATokenIsRefusedLocally(t *testing.T) {
	f := start(t, 1)
	if _, err := Dial(context.Background(), Options{Endpoints: f.endpoints, Key: key(1)}); err == nil {
		t.Error("dialling with no token was attempted; a relay would only refuse it")
	}
	if _, err := Dial(context.Background(), Options{Key: key(1), Token: []byte("x")}); err == nil {
		t.Error("dialling with no endpoints was attempted")
	}
}

// A ping keeps the NAT mapping open. Its pong must not surface as peer traffic, or a caller
// waiting for a packet would be woken by every keepalive.
func TestAPongDoesNotLookLikePeerTraffic(t *testing.T) {
	f := start(t, 1)
	a := f.dial(1, f.endpoints)
	b := f.dial(2, f.endpoints)

	if err := a.Ping([]byte("nonce")); err != nil {
		t.Fatal(err)
	}
	// B sends a real packet after A's ping; A must see the packet, not the pong.
	if err := b.Send(key(1), []byte("real")); err != nil {
		t.Fatal(err)
	}

	if err := a.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	from, n, err := a.Receive(buf)
	if err != nil {
		t.Fatalf("A received nothing: %v", err)
	}
	if from != key(2) || string(buf[:n]) != "real" {
		t.Errorf("A received %q from %x, want \"real\" from B", buf[:n], from[:2])
	}
}

// Two peers on different relay ports, which is the case the relay's socket routing exists for
// and the one an agent will hit whenever a network filters one of the ports.
func TestPeersOnDifferentPortsCanTalk(t *testing.T) {
	f := start(t, 2)
	a := f.dial(1, []string{f.endpoints[0]})
	b := f.dial(2, []string{f.endpoints[1]})

	if err := a.Send(key(2), []byte("across ports")); err != nil {
		t.Fatal(err)
	}
	if err := b.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	from, n, err := b.Receive(buf)
	if err != nil {
		t.Fatalf("nothing crossed between relay ports: %v", err)
	}
	if from != key(1) || string(buf[:n]) != "across ports" {
		t.Errorf("got %q from %x", buf[:n], from[:2])
	}
}

// An oversized packet is refused rather than truncated: a truncated WireGuard packet fails
// authentication far from here, so the symptom would be a peer that handshakes and goes quiet.
func TestAnOversizedPacketIsRefusedRatherThanTruncated(t *testing.T) {
	f := start(t, 1)
	a := f.dial(1, f.endpoints)

	if err := a.Send(key(2), make([]byte, relayproto.MaxPayload+1)); err == nil {
		t.Error("an oversized packet was accepted")
	}
	if err := a.Send(key(2), make([]byte, relayproto.MaxPayload)); err != nil {
		t.Errorf("a packet of exactly the maximum was refused: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	f := start(t, 1)
	c := f.dial(1, f.endpoints)

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("closing twice returned %v; an agent closes on every error path", err)
	}
	if err := c.Send(key(2), []byte("x")); !errors.Is(err, ErrClosed) {
		t.Errorf("sending after close gave %v, want ErrClosed", err)
	}
	buf := make([]byte, 16)
	if _, _, err := c.Receive(buf); !errors.Is(err, ErrClosed) {
		t.Errorf("receiving after close gave %v, want ErrClosed", err)
	}
}

// freeLoopbackAddr returns a loopback address with nothing listening on it.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// The case that matters, and the one an unbound loopback port does not reproduce: a filtered
// endpoint that swallows the datagram and never answers.
//
// An unbound port replies with ICMP port-unreachable, so falling through takes no time and
// exercises the error path rather than the timeout. A firewall drops silently — which is what
// UDP 443 does on the network this was developed on — so the client has to give up on a
// deadline and move on. Without a black hole in the test, "tries the next endpoint" is only
// half tested.
func TestASilentlyFilteredPortIsSkippedOnTimeout(t *testing.T) {
	f := start(t, 1)

	// Bound, so nothing rejects, and never read from, so nothing answers.
	blackHole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blackHole.Close() }()

	const timeout = 400 * time.Millisecond
	started := time.Now()
	c, err := Dial(context.Background(), Options{
		Endpoints:    []string{blackHole.LocalAddr().String(), f.endpoints[0]},
		Key:          key(1),
		Token:        f.token(1),
		HelloTimeout: timeout,
	})
	if err != nil {
		t.Fatalf("Dial gave up instead of trying the next endpoint: %v", err)
	}
	defer func() { _ = c.Close() }()

	if c.Endpoint() != f.endpoints[0] {
		t.Errorf("connected to %s, want the working endpoint", c.Endpoint())
	}
	// It really waited, so this went through the timeout rather than an error.
	if elapsed := time.Since(started); elapsed < timeout {
		t.Errorf("fell through in %s, less than the %s timeout — the black hole answered something",
			elapsed, timeout)
	}
}

// And when every endpoint is a black hole, the failure is reported as nothing answering rather
// than hanging forever.
func TestAllEndpointsFilteredFailsWithinTheTimeouts(t *testing.T) {
	f := start(t, 1)

	var holes []string
	for range 3 {
		h, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = h.Close() }()
		holes = append(holes, h.LocalAddr().String())
	}

	const timeout = 200 * time.Millisecond
	started := time.Now()
	_, err := Dial(context.Background(), Options{
		Endpoints: holes, Key: key(1), Token: f.token(1), HelloTimeout: timeout,
	})
	if !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("got %v, want ErrNoEndpoint", err)
	}
	// Bounded: three endpoints, not an unbounded wait.
	if elapsed := time.Since(started); elapsed > 3*timeout+time.Second {
		t.Errorf("took %s for three endpoints at %s each", elapsed, timeout)
	}
}

// A cancelled context stops the attempt, so a daemon shutting down does not sit through every
// endpoint's timeout.
func TestACancelledContextStopsDialling(t *testing.T) {
	f := start(t, 1)

	hole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hole.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Dial(ctx, Options{
		Endpoints: []string{hole.LocalAddr().String(), f.endpoints[0]},
		Key:       key(1), Token: f.token(1), HelloTimeout: 5 * time.Second,
	}); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
}
