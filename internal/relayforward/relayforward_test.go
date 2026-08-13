package relayforward

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/relayproto"
)

func key(b byte) relayproto.Key {
	var k relayproto.Key
	for i := range k {
		k[i] = b
	}
	return k
}

// fakeKernel stands in for the kernel's WireGuard socket.
//
// It can be an ordinary UDP socket because that is all the kernel's is, from the outside:
// something that sends to a peer's endpoint and receives from it. Standing in for it here is
// what lets the whole loopback path be tested without privileges, and lets a test assert the
// thing that actually matters — the source address inbound packets arrive from.
type fakeKernel struct {
	t    *testing.T
	conn *net.UDPConn
}

func newFakeKernel(t *testing.T) *fakeKernel {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &fakeKernel{t: t, conn: conn}
}

func (k *fakeKernel) port() int { return k.conn.LocalAddr().(*net.UDPAddr).Port }

// sendTo is what WireGuard does when it has something for a peer: send to its endpoint.
func (k *fakeKernel) sendTo(endpoint netip.AddrPort, payload []byte) {
	k.t.Helper()
	if _, err := k.conn.WriteToUDPAddrPort(payload, endpoint); err != nil {
		k.t.Fatal(err)
	}
}

// recv returns a packet and the address it came from, which is the assertion that matters.
func (k *fakeKernel) recv(within time.Duration) ([]byte, netip.AddrPort, bool) {
	k.t.Helper()
	if err := k.conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		k.t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, from, err := k.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, netip.AddrPort{}, false
	}
	return buf[:n], from, true
}

// recordingSender captures what would have gone to a relay.
type recordingSender struct {
	mu   sync.Mutex
	sent []struct {
		peer    relayproto.Key
		payload []byte
	}
	ch  chan struct{}
	err error
}

func newRecordingSender() *recordingSender {
	return &recordingSender{ch: make(chan struct{}, 64)}
}

func (r *recordingSender) Send(peer relayproto.Key, payload []byte) error {
	if r.err != nil {
		return r.err
	}
	r.mu.Lock()
	cp := make([]byte, len(payload))
	copy(cp, payload)
	r.sent = append(r.sent, struct {
		peer    relayproto.Key
		payload []byte
	}{peer, cp})
	r.mu.Unlock()
	select {
	case r.ch <- struct{}{}:
	default:
	}
	return nil
}

func (r *recordingSender) wait(t *testing.T, within time.Duration) bool {
	t.Helper()
	select {
	case <-r.ch:
		return true
	case <-time.After(within):
		return false
	}
}

func (r *recordingSender) last() (relayproto.Key, []byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sent) == 0 {
		return relayproto.Key{}, nil, false
	}
	s := r.sent[len(r.sent)-1]
	return s.peer, s.payload, true
}

// waitFor polls until a condition holds, so a test can synchronise on something observable
// rather than on a sleep long enough to usually work.
func waitFor(t *testing.T, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition did not hold within %s", within)
}

func newForwarder(t *testing.T, wgPort int, s Sender) *Forwarder {
	t.Helper()
	f, err := New(wgPort, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// What the kernel sends to a peer's endpoint reaches the relay, named for that peer.
func TestWhatTheKernelSendsGoesToTheRelay(t *testing.T) {
	kernel := newFakeKernel(t)
	sender := newRecordingSender()
	f := newForwarder(t, kernel.port(), sender)

	endpoint, err := f.Endpoint(key(2))
	if err != nil {
		t.Fatal(err)
	}
	if !endpoint.Addr().IsLoopback() {
		t.Fatalf("endpoint %s is not a loopback address", endpoint)
	}

	kernel.sendTo(endpoint, []byte("a wireguard packet"))
	if !sender.wait(t, 3*time.Second) {
		t.Fatal("nothing reached the relay")
	}
	peer, payload, ok := sender.last()
	if !ok {
		t.Fatal("nothing recorded")
	}
	if peer != key(2) {
		t.Error("the packet was relayed for the wrong peer")
	}
	if string(payload) != "a wireguard packet" {
		t.Errorf("payload is %q", payload)
	}
}

// The assertion the whole design turns on: an inbound packet must reach the WireGuard port
// with a source address of exactly the endpoint that peer is configured with. Anything else
// and the kernel will not associate it with the peer, and the tunnel silently does not work.
func TestAnInboundPacketArrivesFromThePeersConfiguredEndpoint(t *testing.T) {
	kernel := newFakeKernel(t)
	f := newForwarder(t, kernel.port(), newRecordingSender())

	endpoint, err := f.Endpoint(key(2))
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Deliver(key(2), []byte("from the relay")); err != nil {
		t.Fatal(err)
	}
	payload, from, ok := kernel.recv(3 * time.Second)
	if !ok {
		t.Fatal("nothing was delivered to the WireGuard port")
	}
	if string(payload) != "from the relay" {
		t.Errorf("payload is %q", payload)
	}
	if from != endpoint {
		t.Errorf("arrived from %s, want the peer's configured endpoint %s — the kernel would\n"+
			"not associate this with the peer", from, endpoint)
	}
}

// Each peer gets its own socket, because the source address is how the kernel tells them
// apart. One shared socket would make every relayed peer look like the same peer.
func TestEachPeerHasItsOwnEndpoint(t *testing.T) {
	kernel := newFakeKernel(t)
	f := newForwarder(t, kernel.port(), newRecordingSender())

	a, err := f.Endpoint(key(1))
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.Endpoint(key(2))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two peers share an endpoint; the kernel could not tell them apart")
	}

	// And each delivers from its own.
	for peer, want := range map[relayproto.Key]netip.AddrPort{key(1): a, key(2): b} {
		if err := f.Deliver(peer, []byte("x")); err != nil {
			t.Fatal(err)
		}
		_, from, ok := kernel.recv(3 * time.Second)
		if !ok {
			t.Fatal("nothing delivered")
		}
		if from != want {
			t.Errorf("a packet for one peer arrived from %s, want %s", from, want)
		}
	}
}

// The endpoint must not move: it is what the kernel has been configured with, and a new port
// would leave the kernel sending to a socket nobody reads.
func TestAnEndpointIsStableForAPeer(t *testing.T) {
	f := newForwarder(t, newFakeKernel(t).port(), newRecordingSender())

	first, err := f.Endpoint(key(1))
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		again, err := f.Endpoint(key(1))
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("the endpoint moved from %s to %s", first, again)
		}
	}
}

func TestForgettingAPeerReleasesItsSocket(t *testing.T) {
	kernel := newFakeKernel(t)
	f := newForwarder(t, kernel.port(), newRecordingSender())

	if _, err := f.Endpoint(key(1)); err != nil {
		t.Fatal(err)
	}
	if len(f.Peers()) != 1 {
		t.Fatalf("%d peers served, want 1", len(f.Peers()))
	}

	f.Forget(key(1))
	if len(f.Peers()) != 0 {
		t.Errorf("%d peers still served after forgetting", len(f.Peers()))
	}
	// Delivering for a peer nobody serves is reported rather than silently dropped.
	if err := f.Deliver(key(1), []byte("x")); err == nil {
		t.Error("delivering to a forgotten peer was reported as success")
	}
}

// A relay connection that has gone away must not stop the sockets: WireGuard retransmits, and
// dropping is right — queueing would deliver packets long after they stopped meaning anything.
func TestPacketsAreDroppedWhileThereIsNoRelay(t *testing.T) {
	kernel := newFakeKernel(t)
	f := newForwarder(t, kernel.port(), nil)

	endpoint, err := f.Endpoint(key(2))
	if err != nil {
		t.Fatal(err)
	}
	kernel.sendTo(endpoint, []byte("goes nowhere"))

	// Wait for the drop to be recorded before reconnecting. Without this the test races its
	// own subject: the socket may read the first packet after SetSender and relay it with the
	// new sender, which is exactly the flake this test had when it was written.
	waitFor(t, 3*time.Second, func() bool { return f.Stats().DroppedNoRelay == 1 })

	// Reconnected, and now it flows again.
	sender := newRecordingSender()
	f.SetSender(sender)
	kernel.sendTo(endpoint, []byte("goes somewhere"))

	if !sender.wait(t, 3*time.Second) {
		t.Fatal("nothing reached the relay after reconnecting")
	}
	_, payload, _ := sender.last()
	if string(payload) != "goes somewhere" {
		t.Errorf("relayed %q, want the packet sent after reconnecting", payload)
	}
}

// A failing relay must not kill the socket, or one transient error would leave a peer
// permanently unable to send even after the relay came back.
func TestASendFailureDoesNotStopTheSocket(t *testing.T) {
	kernel := newFakeKernel(t)
	failing := newRecordingSender()
	failing.err = errors.New("relay unreachable")
	f := newForwarder(t, kernel.port(), failing)

	endpoint, err := f.Endpoint(key(2))
	if err != nil {
		t.Fatal(err)
	}
	kernel.sendTo(endpoint, []byte("fails"))
	time.Sleep(100 * time.Millisecond)

	working := newRecordingSender()
	f.SetSender(working)
	kernel.sendTo(endpoint, []byte("works"))

	if !working.wait(t, 3*time.Second) {
		t.Fatal("the socket stopped after a send failure")
	}
}

// A full-sized packet has to survive the read buffer. One byte short and only large packets
// are lost, which is the hardest fault to attribute.
func TestAFullSizedPacketSurvives(t *testing.T) {
	kernel := newFakeKernel(t)
	sender := newRecordingSender()
	f := newForwarder(t, kernel.port(), sender)

	endpoint, err := f.Endpoint(key(2))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, relayproto.MaxPayload)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	kernel.sendTo(endpoint, payload)

	if !sender.wait(t, 3*time.Second) {
		t.Fatal("a full-sized packet did not reach the relay")
	}
	_, got, _ := sender.last()
	if len(got) != relayproto.MaxPayload {
		t.Fatalf("relayed %d bytes, want %d", len(got), relayproto.MaxPayload)
	}
	for i, b := range got {
		if b != byte(i%251) {
			t.Fatalf("byte %d is %d, want %d", i, b, i%251)
		}
	}
}

// A device that has just joined does not know its WireGuard port: the interface asks the
// kernel for any port, so the answer arrives after the first convergence. Refusing to build
// a forwarder until then would mean no relayed peer could be configured on the very first
// run after a join, which is exactly when relaying matters most.
func TestAForwarderCanBeBuiltBeforeThePortIsKnown(t *testing.T) {
	f, err := New(0, newRecordingSender(), nil)
	if err != nil {
		t.Fatalf("New(0): %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	// Outbound works immediately; it does not involve the WireGuard port.
	if _, err := f.Endpoint(key(1)); err != nil {
		t.Fatalf("Endpoint: %v", err)
	}

	// Inbound has nowhere to go, and says so rather than vanishing.
	if err := f.Deliver(key(1), []byte("too early")); err == nil {
		t.Error("delivered a packet with no port to deliver it to")
	}
	if got := f.Stats().DroppedNoPort; got != 1 {
		t.Errorf("DroppedNoPort = %d, want 1 — a silent drop looks like a relay fault", got)
	}

	// And starts working the moment the interface reports its port.
	kernel := newFakeKernel(t)
	f.SetWireGuardPort(kernel.port())
	if err := f.Deliver(key(1), []byte("now")); err != nil {
		t.Fatalf("Deliver after the port was known: %v", err)
	}
	payload, _, ok := kernel.recv(time.Second)
	if !ok {
		t.Fatal("the kernel port received nothing after the port was set")
	}
	if got := string(payload); got != "now" {
		t.Errorf("the kernel port got %q", got)
	}
}

// A negative port is a caller bug rather than a port that is not known yet, and treating it
// as "not known" would hide it until packets started disappearing.
func TestANegativePortIsRefused(t *testing.T) {
	if _, err := New(-1, newRecordingSender(), nil); err == nil {
		t.Error("built a forwarder for a negative port")
	}
}

func TestCloseIsIdempotentAndStopsEverything(t *testing.T) {
	f := newForwarder(t, newFakeKernel(t).port(), newRecordingSender())
	if _, err := f.Endpoint(key(1)); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("closing twice returned %v", err)
	}
	if len(f.Peers()) != 0 {
		t.Error("peers are still served after close")
	}
	if _, err := f.Endpoint(key(2)); err == nil {
		t.Error("a socket was opened after close")
	}
}
