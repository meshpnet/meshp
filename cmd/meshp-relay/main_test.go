package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

// These drive a real relay over real sockets. The unit tests in internal/relay decide what
// should happen; this checks that the wiring between them and a UDP socket is right — in
// particular that a reply leaves by the socket its destination is using, which no amount of
// testing the core can establish.

func testKey(b byte) relayproto.Key {
	var k relayproto.Key
	for i := range k {
		k[i] = b
	}
	return k
}

var testNetwork = func() [16]byte {
	var n [16]byte
	copy(n[:], "acme------------")
	return n
}()

type harness struct {
	t      *testing.T
	priv   ed25519.PrivateKey
	ports  []string
	server *relay.Server
}

// startRelay brings up a relay on two ephemeral ports and returns their addresses.
//
// Ephemeral rather than fixed, because a test that picks a port number is a test that fails
// when something else on the machine happened to want it.
func startRelay(t *testing.T) *harness {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := relay.New(relay.Config{
		Auth:    issuerAuth{public: pub, clk: clock.System{}},
		SelfKey: testKey(0xFF),
		Clock:   clock.System{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	h, err := listenAll("127.0.0.1:0,127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := serve(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), srv, h)
	t.Cleanup(func() {
		cancel()
		for _, c := range h.conns {
			_ = c.Close()
		}
		wg.Wait()
	})

	ports := make([]string, 0, len(h.conns))
	for _, c := range h.conns {
		ports = append(ports, c.LocalAddr().String())
	}
	return &harness{t: t, priv: priv, ports: ports, server: srv}
}

// client is one agent's socket.
type client struct {
	t    *testing.T
	conn *net.UDPConn
}

func (h *harness) dial(port string) *client {
	h.t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", port)
	if err != nil {
		h.t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return &client{t: h.t, conn: conn}
}

func (c *client) send(frame relayproto.Frame) {
	c.t.Helper()
	buf := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)
	n, err := frame.Encode(buf)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.conn.Write(buf[:n]); err != nil {
		c.t.Fatal(err)
	}
}

// recv waits for one frame, or reports that nothing came.
func (c *client) recv(within time.Duration) (relayproto.Frame, bool) {
	c.t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		c.t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := c.conn.Read(buf)
	if err != nil {
		return relayproto.Frame{}, false
	}
	frame, err := relayproto.Decode(buf[:n])
	if err != nil {
		c.t.Fatalf("the relay sent something undecodable: %v", err)
	}
	return frame, true
}

// hello authenticates a client and returns the address the relay observed.
func (h *harness) hello(c *client, k byte) string {
	h.t.Helper()
	token, err := relaytoken.Issue(h.priv, testKey(k), testNetwork, time.Now().Add(time.Minute))
	if err != nil {
		h.t.Fatal(err)
	}
	c.send(relayproto.Frame{Type: relayproto.TypeHello, Key: testKey(k), Payload: token})

	frame, ok := c.recv(3 * time.Second)
	if !ok {
		h.t.Fatalf("no welcome for key %d", k)
	}
	if frame.Type != relayproto.TypeWelcome {
		h.t.Fatalf("got %s, want welcome", frame.Type)
	}
	return string(frame.Payload)
}

// The reason a relay exists, over a real socket: a packet reaches a peer that is talking to a
// different port. If replies left by the socket they arrived on, this would fail — and it
// would pass whenever both peers happened to choose the same port, which is most of the time
// by hand and rarely in the field.
func TestAPacketReachesAPeerOnADifferentPort(t *testing.T) {
	h := startRelay(t)
	a := h.dial(h.ports[0])
	b := h.dial(h.ports[1])

	seenA := h.hello(a, 1)
	seenB := h.hello(b, 2)
	if seenA == "" || seenB == "" {
		t.Fatal("the relay did not report the addresses it observed")
	}
	t.Logf("relay sees A at %s (port %s) and B at %s (port %s)", seenA, h.ports[0], seenB, h.ports[1])

	payload := []byte("a wireguard packet, notionally")
	a.send(relayproto.Frame{Type: relayproto.TypeSend, Key: testKey(2), Payload: payload})

	frame, ok := b.recv(3 * time.Second)
	if !ok {
		t.Fatal("the packet never reached B; a reply left by the wrong socket")
	}
	if frame.Type != relayproto.TypeRecv {
		t.Errorf("B got %s, want recv", frame.Type)
	}
	if frame.Key != testKey(1) {
		t.Error("the forwarded frame does not name A, so B cannot tell who sent it")
	}
	if string(frame.Payload) != string(payload) {
		t.Error("the payload changed in transit")
	}

	// And back the other way, which uses the other socket.
	b.send(relayproto.Frame{Type: relayproto.TypeSend, Key: testKey(1), Payload: []byte("reply")})
	if frame, ok := a.recv(3 * time.Second); !ok {
		t.Error("the reverse direction did not arrive")
	} else if string(frame.Payload) != "reply" {
		t.Errorf("A got %q", frame.Payload)
	}
}

// The address in a welcome is the reflexive candidate — what an agent cannot learn any other
// way, and the reason it talks to a relay before it needs one.
func TestTheWelcomeReportsTheAddressTheRelayActuallySees(t *testing.T) {
	h := startRelay(t)
	c := h.dial(h.ports[0])

	seen := h.hello(c, 1)
	local := c.conn.LocalAddr().String()
	if seen != local {
		t.Errorf("the relay reports %s, but this socket is %s", seen, local)
	}
}

func TestATokenFromAnotherIssuerIsRefusedOverTheWire(t *testing.T) {
	h := startRelay(t)
	c := h.dial(h.ports[0])

	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := relaytoken.Issue(other, testKey(3), testNetwork, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	c.send(relayproto.Frame{Type: relayproto.TypeHello, Key: testKey(3), Payload: token})

	frame, ok := c.recv(3 * time.Second)
	if !ok {
		t.Fatal("no answer to a forged hello")
	}
	if frame.Type != relayproto.TypeRefused {
		t.Errorf("got %s, want refused", frame.Type)
	}
	if h.server.Stats().HelloRefused == 0 {
		t.Error("the refusal was not counted")
	}
}

// An unauthenticated sender gets nothing at all, so the relay cannot be used as a reflector.
func TestAnUnauthenticatedSenderGetsNothing(t *testing.T) {
	h := startRelay(t)
	known := h.dial(h.ports[0])
	h.hello(known, 1)

	stranger := h.dial(h.ports[0])
	stranger.send(relayproto.Frame{Type: relayproto.TypeSend, Key: testKey(1), Payload: []byte("packet")})
	if frame, ok := stranger.recv(time.Second); ok {
		t.Errorf("the relay answered a stranger with %s", frame.Type)
	}
	// And the known peer was not sent anything either.
	if frame, ok := known.recv(500 * time.Millisecond); ok {
		t.Errorf("a stranger's packet was delivered as %s", frame.Type)
	}
}

func TestAPingIsAnswered(t *testing.T) {
	h := startRelay(t)
	c := h.dial(h.ports[0])
	h.hello(c, 1)

	c.send(relayproto.Frame{Type: relayproto.TypePing, Key: testKey(1), Payload: []byte("nonce")})
	frame, ok := c.recv(3 * time.Second)
	if !ok {
		t.Fatal("no pong")
	}
	if frame.Type != relayproto.TypePong || string(frame.Payload) != "nonce" {
		t.Errorf("got %s %q, want a pong echoing the nonce", frame.Type, frame.Payload)
	}
}

// A full-sized packet has to survive the socket as well as the encoder: if the read buffer
// were a byte short, only large packets would be lost, which is the hardest failure to
// attribute.
func TestAFullSizedPacketSurvivesTheSocket(t *testing.T) {
	h := startRelay(t)
	a := h.dial(h.ports[0])
	b := h.dial(h.ports[1])
	h.hello(a, 1)
	h.hello(b, 2)

	payload := make([]byte, relayproto.MaxPayload)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	a.send(relayproto.Frame{Type: relayproto.TypeSend, Key: testKey(2), Payload: payload})

	frame, ok := b.recv(3 * time.Second)
	if !ok {
		t.Fatal("a full-sized packet did not arrive")
	}
	if len(frame.Payload) != relayproto.MaxPayload {
		t.Fatalf("arrived with %d bytes, want %d", len(frame.Payload), relayproto.MaxPayload)
	}
	for i, b := range frame.Payload {
		if b != byte(i%251) {
			t.Fatalf("byte %d is %d, want %d", i, b, i%251)
		}
	}
}

// Garbage on a public port must not disturb anything.
func TestGarbageDoesNotDisturbTheRelay(t *testing.T) {
	h := startRelay(t)
	a := h.dial(h.ports[0])
	b := h.dial(h.ports[1])
	h.hello(a, 1)
	h.hello(b, 2)

	noise := h.dial(h.ports[0])
	for _, junk := range [][]byte{{}, {0}, make([]byte, 7), make([]byte, 3000), []byte("GET / HTTP/1.1\r\n\r\n")} {
		if _, err := noise.conn.Write(junk); err != nil {
			t.Fatal(err)
		}
	}
	if frame, ok := noise.recv(500 * time.Millisecond); ok {
		t.Errorf("garbage was answered with %s", frame.Type)
	}

	// The relay still works afterwards.
	a.send(relayproto.Frame{Type: relayproto.TypeSend, Key: testKey(2), Payload: []byte("still here")})
	if frame, ok := b.recv(3 * time.Second); !ok {
		t.Error("the relay stopped forwarding after receiving garbage")
	} else if string(frame.Payload) != "still here" {
		t.Errorf("got %q", frame.Payload)
	}
}

func TestAnIssuerKeyIsRequired(t *testing.T) {
	if _, err := parseIssuerKey(""); err == nil {
		t.Error("an empty issuer key was accepted, which would mean an open proxy")
	}
	if _, err := parseIssuerKey("not base64"); err == nil {
		t.Error("a malformed issuer key was accepted")
	}
	if _, err := parseIssuerKey("c2hvcnQ="); err == nil {
		t.Error("a short issuer key was accepted")
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseIssuerKey(relaytoken.Encode(pub)); err != nil {
		t.Errorf("a valid key was refused: %v", err)
	}
}

// All or nothing: a relay that came up on two of its three ports would advertise one that
// silently does not work, and agents would spend their retries on it.
func TestListeningIsAllOrNothing(t *testing.T) {
	first, err := listenAll("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	taken := first.conns[0].LocalAddr().String()
	defer func() { _ = first.conns[0].Close() }()

	// One good address and one already in use.
	if _, err := listenAll("127.0.0.1:0," + taken); err == nil {
		t.Error("listening succeeded although one address was unavailable")
	}
	if _, err := listenAll(""); err == nil {
		t.Error("an empty listen list was accepted")
	}
	if _, err := listenAll("not an address"); err == nil {
		t.Error("a malformed address was accepted")
	}
}
