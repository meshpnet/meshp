package relayforward_test

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
	"github.com/meshpnet/meshp/internal/relayclient"
	"github.com/meshpnet/meshp/internal/relayforward"
	"github.com/meshpnet/meshp/internal/relayproto"
	"github.com/meshpnet/meshp/internal/relaytoken"
)

// The whole design, end to end, with nothing faked but the kernel:
//
//	kernel A -> forwarder A -> relay client A -> RELAY -> client B -> forwarder B -> kernel B
//
// Everything between the two ends is the shipping code. The kernel is stood in for by an
// ordinary UDP socket, which is all it is from the outside — something that sends to a peer's
// endpoint and receives from it — and that is what makes this runnable without privileges.
//
// What it proves is the claim ADR-0016 rests on: that giving the kernel a loopback endpoint
// and serving it is enough to carry a packet between two hosts through a relay.

func testKey(b byte) relayproto.Key {
	var k relayproto.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func startRelay(t *testing.T) (endpoint string, signer ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv, err := relay.New(relay.Config{
		Auth: authFunc(func(token []byte) (relayproto.Key, string, error) {
			grant, err := relaytoken.Verify(pub, token, time.Now())
			if err != nil {
				return relayproto.Key{}, "", err
			}
			return grant.Key, grant.Network(), nil
		}),
		SelfKey: testKey(0xFF),
		Clock:   clock.System{},
		Log:     discard,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		in := make([]byte, 4096)
		out := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(in)
			if err != nil {
				return
			}
			for _, o := range srv.Handle(0, from, in[:n]) {
				written, err := o.Frame.Encode(out)
				if err != nil {
					continue
				}
				_, _ = conn.WriteToUDPAddrPort(out[:written], o.To)
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })

	return conn.LocalAddr().String(), priv
}

type authFunc func([]byte) (relayproto.Key, string, error)

func (f authFunc) Authenticate(token []byte) (relayproto.Key, string, error) { return f(token) }

// end is one device: a stand-in kernel, a forwarder and a relay connection.
type end struct {
	t         *testing.T
	kernel    *net.UDPConn
	forwarder *relayforward.Forwarder
	client    *relayclient.Client
}

func newEnd(t *testing.T, relayAddr string, signer ed25519.PrivateKey, self relayproto.Key) *end {
	t.Helper()

	kernel, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = kernel.Close() })

	var networkID [16]byte
	copy(networkID[:], "acme------------")
	token, err := relaytoken.Issue(signer, self, networkID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	client, err := relayclient.Dial(context.Background(), relayclient.Options{
		Endpoints: []string{relayAddr},
		Key:       self,
		Token:     token,
	})
	if err != nil {
		t.Fatalf("dialling the relay: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	fwd, err := relayforward.New(kernel.LocalAddr().(*net.UDPAddr).Port, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fwd.Close() })

	e := &end{t: t, kernel: kernel, forwarder: fwd, client: client}

	// The inbound loop the agent will run: read from the relay, hand to the forwarder.
	go func() {
		buf := make([]byte, relayproto.MaxPayload)
		for {
			peer, n, err := client.Receive(buf)
			if err != nil {
				return
			}
			_ = fwd.Deliver(peer, buf[:n])
		}
	}()
	return e
}

func TestAPacketCrossesARelayThroughTheLoopbackPath(t *testing.T) {
	relayAddr, signer := startRelay(t)

	a := newEnd(t, relayAddr, signer, testKey(1))
	b := newEnd(t, relayAddr, signer, testKey(2))

	// Each side is told where to send for the other, exactly as wgplan would configure a
	// relayed peer's endpoint.
	aToB, err := a.forwarder.Endpoint(testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.forwarder.Endpoint(testKey(1)); err != nil {
		t.Fatal(err)
	}

	// A's kernel sends to B's endpoint on A's host.
	payload := []byte("a wireguard packet, notionally, via a relay")
	if _, err := a.kernel.WriteToUDPAddrPort(payload, aToB); err != nil {
		t.Fatal(err)
	}

	// B's kernel receives it, and the source must be the endpoint B has configured for A —
	// otherwise the kernel would not associate it with A and the tunnel silently fails.
	if err := b.kernel.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, from, err := b.kernel.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("the packet never arrived at B: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("B received %q", buf[:n])
	}

	wantFrom, err := b.forwarder.Endpoint(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if from != wantFrom {
		t.Errorf("arrived from %s, want %s — the endpoint B has configured for A", from, wantFrom)
	}

	// And back, which uses the other direction of both sockets.
	bToA, err := b.forwarder.Endpoint(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.kernel.WriteToUDPAddrPort([]byte("and back again"), bToA); err != nil {
		t.Fatal(err)
	}
	if err := a.kernel.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err = a.kernel.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("the reply never arrived at A: %v", err)
	}
	if string(buf[:n]) != "and back again" {
		t.Errorf("A received %q", buf[:n])
	}
	if from != aToB {
		t.Errorf("the reply arrived from %s, want %s", from, aToB)
	}
}

// A full-sized packet has to survive every hop: two loopback sockets, the relay framing and
// the relay itself. One byte lost anywhere and only large packets fail.
func TestAFullSizedPacketCrossesTheWholeChain(t *testing.T) {
	relayAddr, signer := startRelay(t)
	a := newEnd(t, relayAddr, signer, testKey(1))
	b := newEnd(t, relayAddr, signer, testKey(2))

	aToB, err := a.forwarder.Endpoint(testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.forwarder.Endpoint(testKey(1)); err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, relayproto.MaxPayload)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := a.kernel.WriteToUDPAddrPort(payload, aToB); err != nil {
		t.Fatal(err)
	}

	if err := b.kernel.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := b.kernel.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("a full-sized packet did not cross: %v", err)
	}
	if n != relayproto.MaxPayload {
		t.Fatalf("arrived with %d bytes, want %d", n, relayproto.MaxPayload)
	}
	for i := range n {
		if buf[i] != byte(i%251) {
			t.Fatalf("byte %d is %d, want %d", i, buf[i], i%251)
		}
	}
}
