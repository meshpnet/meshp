package relaylink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/relay"
	"github.com/meshpnet/meshp/internal/relayclient"
	"github.com/meshpnet/meshp/internal/relayproto"
	"github.com/meshpnet/meshp/internal/relaytoken"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// These run against a real relay over real sockets, for the same reason relayclient's do: a
// fake relay would only prove this package agrees with my idea of the protocol.

var network = func() [16]byte {
	var n [16]byte
	copy(n[:], "acme------------")
	return n
}()

type fixture struct {
	t         *testing.T
	priv      ed25519.PrivateKey
	endpoints []string

	// stop cuts the relay off mid-session, so a test can watch a link notice.
	stop func()

	// mute makes the relay stop answering while staying bound.
	//
	// Distinct from stop, and the distinction is the whole point: closing the socket makes
	// the host send an ICMP port-unreachable, and the client's next read fails with a real
	// error. That exercises the operating system, not this package. A relay that is still
	// listening and no longer answering — restarted, session forgotten, NAT rebound — is
	// the case only the liveness check catches, and UDP reports it as nothing at all.
	mute func()
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func startRelay(t *testing.T) *fixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(relay.Config{
		Auth:    tokenAuth{public: pub},
		SelfKey: relayproto.Key{0xFF},
		Clock:   clock.System{},
		Log:     discardLog(),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var muted atomic.Bool
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
			if muted.Load() {
				continue // still bound, saying nothing
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

	f := &fixture{
		t:         t,
		priv:      priv,
		endpoints: []string{conn.LocalAddr().String()},
		stop:      func() { _ = conn.Close(); <-done },
		mute:      func() { muted.Store(true) },
	}
	t.Cleanup(func() { _ = conn.Close() })
	return f
}

type tokenAuth struct{ public ed25519.PublicKey }

func (a tokenAuth) Authenticate(token []byte) (relayproto.Key, string, error) {
	grant, err := relaytoken.Verify(a.public, token, time.Now())
	if err != nil {
		return relayproto.Key{}, "", err
	}
	return grant.Key, grant.Network(), nil
}

// device is one WireGuard identity, in both the spellings this package has to bridge.
type device struct {
	encoded string
	raw     relayproto.Key
}

func newDevice(t *testing.T) device {
	t.Helper()
	pair, err := keys.NewWireGuardPair()
	if err != nil {
		t.Fatal(err)
	}
	var raw relayproto.Key
	copy(raw[:], pair.Public[:])
	return device{encoded: pair.Public.String(), raw: raw}
}

func (f *fixture) token(d device) []byte {
	f.t.Helper()
	tok, err := relaytoken.Issue(f.priv, d.raw, network, time.Now().Add(time.Minute))
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func (f *fixture) relayConfig(id string) *meshpv1.RelayConfig {
	return &meshpv1.RelayConfig{Relays: []*meshpv1.RelayConfig_Relay{
		{Id: id, Endpoints: f.endpoints},
	}}
}

// fakeKernel stands in for the WireGuard listen port: relayforward delivers inbound packets
// to it, and its port is what a Link is built with.
type fakeKernel struct {
	conn *net.UDPConn
	port int
}

func newFakeKernel(t *testing.T) *fakeKernel {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &fakeKernel{conn: conn, port: conn.LocalAddr().(*net.UDPAddr).Port}
}

// awaits one datagram, and reports the address it came from.
func (k *fakeKernel) await(t *testing.T, within time.Duration) ([]byte, netAddr) {
	t.Helper()
	_ = k.conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 2048)
	n, from, err := k.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the kernel port received nothing: %v", err)
	}
	return buf[:n], netAddr{IP: from.IP.String(), Port: from.Port}
}

type netAddr struct {
	IP   string
	Port int
}

func newLink(t *testing.T, d device, port int, clk clock.Clock) *Link {
	t.Helper()
	l, err := New(Options{Key: d.encoded, WireGuardPort: port, Log: discardLog(), Clock: clk})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// run starts the dial loop and returns once it is attached, or fails.
func run(t *testing.T, l *Link) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = l.Run(ctx) }()
	return cancel
}

func awaitConnected(t *testing.T, l *Link, want bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if l.Status().Connected == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("connected = %v, want %v (last error: %q)", !want, want, l.Status().LastError)
}

// ---------------------------------------------------------------------------
// Credentials

// The control channel asks only when the link says it needs one.
func TestNeedsTokenTracksExpiry(t *testing.T) {
	clk := clock.NewFake()
	l := newLink(t, newDevice(t), 51820, clk)

	if !l.NeedsToken() {
		t.Error("a link with no token did not ask for one")
	}

	l.SetToken([]byte("tok"), clk.Now().Add(30*time.Minute))
	if l.NeedsToken() {
		t.Error("a link holding a fresh token asked for another")
	}

	// Inside the renewal window, and so inside the control plane's reissue window: asking
	// now is what gets a genuinely new token rather than the same one back.
	clk.Advance(30*time.Minute - renewWithin + time.Second)
	if !l.NeedsToken() {
		t.Error("a token about to expire was not renewed")
	}
}

// A refusal usually means the deployment has no signing key, which asking again does not
// fix. Retrying it on every heartbeat is how one misconfiguration becomes a request loop.
func TestARefusalIsBackedOff(t *testing.T) {
	clk := clock.NewFake()
	l := newLink(t, newDevice(t), 51820, clk)

	l.TokenRefused("relaying is not available")
	if l.NeedsToken() {
		t.Fatal("kept asking straight after a refusal")
	}
	if got := l.Status().Refusal; got != "relaying is not available" {
		t.Errorf("refusal = %q", got)
	}

	clk.Advance(refusalBackoff - time.Second)
	if l.NeedsToken() {
		t.Error("stopped honouring the backoff early")
	}
	clk.Advance(2 * time.Second)
	if !l.NeedsToken() {
		t.Error("never asked again; configuring a relay would need every agent restarted")
	}
}

// Whatever the control plane was declining for, it is not declining now.
func TestATokenClearsARefusal(t *testing.T) {
	clk := clock.NewFake()
	l := newLink(t, newDevice(t), 51820, clk)

	l.TokenRefused("relaying is not available")
	l.SetToken([]byte("tok"), clk.Now().Add(30*time.Minute))

	if got := l.Status().Refusal; got != "" {
		t.Errorf("refusal = %q, want it cleared", got)
	}
	clk.Advance(refusalBackoff + time.Minute)
	if l.NeedsToken() {
		t.Error("the refusal backoff outlived the token that resolved it")
	}
}

// ---------------------------------------------------------------------------
// Endpoints

// A peer's endpoint must not depend on a relay being reachable. It is what the kernel is
// configured with, and rewriting every peer on each reconnect is exactly what ADR-0016
// avoids by giving relayforward a socket per peer.
func TestAPeerGetsAnEndpointBeforeAnythingIsConnected(t *testing.T) {
	f := startRelay(t)
	l := newLink(t, newDevice(t), 51820, clock.System{})
	peer := newDevice(t)

	if _, err := l.Endpoint(peer.encoded, "relay1"); err == nil {
		t.Fatal("served an endpoint for a relay desired state never mentioned")
	}

	l.SetRelays(f.relayConfig("relay1"))

	first, err := l.Endpoint(peer.encoded, "relay1")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if !first.IsValid() || !first.Addr().IsLoopback() {
		t.Fatalf("endpoint = %v, want a loopback address", first)
	}
	if l.Status().Connected {
		t.Fatal("reported connected without a relay connection")
	}

	// Stable, because it is what the kernel has been told.
	second, err := l.Endpoint(peer.encoded, "relay1")
	if err != nil || second != first {
		t.Errorf("endpoint moved from %v to %v (err %v)", first, second, err)
	}
}

// A peer relayed through somewhere this device is not attached to has no usable endpoint.
// Inventing one gives the kernel somewhere to send that goes nowhere, which looks like a
// working relayed peer right up until traffic is tried.
func TestAPeerOnAnotherRelayGetsNothing(t *testing.T) {
	f := startRelay(t)
	l := newLink(t, newDevice(t), 51820, clock.System{})
	l.SetRelays(f.relayConfig("relay1"))

	if _, err := l.Endpoint(newDevice(t).encoded, "relay2"); err == nil {
		t.Error("served an endpoint for a relay this link is not attached to")
	}
	if _, err := l.Endpoint(newDevice(t).encoded, ""); err == nil {
		t.Error("served an endpoint to a peer that named no relay at all")
	}
}

// Retain is how a peer that has stopped being relayed gives its socket back.
func TestRetainClosesRetiredPeers(t *testing.T) {
	f := startRelay(t)
	l := newLink(t, newDevice(t), 51820, clock.System{})
	l.SetRelays(f.relayConfig("relay1"))

	keep, drop := newDevice(t), newDevice(t)
	for _, d := range []device{keep, drop} {
		if _, err := l.Endpoint(d.encoded, "relay1"); err != nil {
			t.Fatalf("Endpoint: %v", err)
		}
	}
	if got := l.Status().Forwarder.Peers; got != 2 {
		t.Fatalf("serving %d peers, want 2", got)
	}

	l.Retain([]string{keep.encoded})

	if got := l.Status().Forwarder.Peers; got != 1 {
		t.Fatalf("serving %d peers after Retain, want 1", got)
	}
	// The kept peer keeps the address the kernel already has.
	if _, err := l.Endpoint(keep.encoded, "relay1"); err != nil {
		t.Errorf("the retained peer lost its socket: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The connection

func TestItDialsOnceItHasBothARelayAndAToken(t *testing.T) {
	f := startRelay(t)
	me := newDevice(t)
	l := newLink(t, me, newFakeKernel(t).port, clock.System{})
	run(t, l)

	// Neither on its own is enough.
	l.SetRelays(f.relayConfig("relay1"))
	time.Sleep(100 * time.Millisecond)
	if st := l.Status(); st.Connected {
		t.Fatal("dialled a relay with no token to present")
	} else if st.LastError != "" {
		// Waiting, not failing. relayclient refuses an empty token on its own, so a link
		// that dialled anyway would still not connect — it would sit in a retry loop
		// logging an error every second, and status would blame the relay for a credential
		// that has simply not arrived.
		t.Fatalf("tried to dial before it had a token: %q", st.LastError)
	}

	l.SetToken(f.token(me), time.Now().Add(time.Minute))
	awaitConnected(t, l, true, 5*time.Second)

	st := l.Status()
	if st.Endpoint != f.endpoints[0] {
		t.Errorf("endpoint = %q, want %q", st.Endpoint, f.endpoints[0])
	}
	if st.Reflexive == "" {
		t.Error("no reflexive address; the relay is the only thing that can report one")
	}
	if !st.HasToken {
		t.Error("status does not show the token it is using")
	}
}

// An expired token will be refused, and presenting one teaches the relay nothing except
// that this device is misbehaving. Waiting costs an idle poll; the control channel is
// already asking for a replacement, and a refusal would show in status as a relay problem
// when the credential is the problem.
func TestAnExpiredTokenIsNotPresented(t *testing.T) {
	f := startRelay(t)
	me := newDevice(t)
	clk := clock.NewFake()
	l := newLink(t, me, newFakeKernel(t).port, clk)
	run(t, l)

	l.SetRelays(f.relayConfig("relay1"))
	// A token the relay would still accept — it is this link's own clock that has moved
	// past the expiry it was told about, which is what an agent knows before it dials.
	l.SetToken(f.token(me), clk.Now().Add(-time.Second))

	time.Sleep(100 * time.Millisecond)
	if st := l.Status(); st.Connected {
		t.Fatal("dialled with a token it knew had expired")
	} else if st.LastError != "" {
		t.Fatalf("tried to dial with an expired token: %q", st.LastError)
	}

	// And it recovers the moment a live one arrives.
	l.SetToken(f.token(me), clk.Now().Add(time.Minute))
	awaitConnected(t, l, true, 5*time.Second)
}

// The whole chain: a packet written to a peer's loopback endpoint leaves through the relay
// and arrives at the far end, and one coming back is delivered to the WireGuard port from
// that same peer's socket.
func TestAPacketMakesTheRoundTrip(t *testing.T) {
	f := startRelay(t)
	me, peer := newDevice(t), newDevice(t)
	kernel := newFakeKernel(t)

	l := newLink(t, me, kernel.port, clock.System{})
	l.SetRelays(f.relayConfig("relay1"))
	l.SetToken(f.token(me), time.Now().Add(time.Minute))
	run(t, l)
	awaitConnected(t, l, true, 5*time.Second)

	// The far end, speaking to the same relay directly.
	far, err := relayclient.Dial(context.Background(), relayclient.Options{
		Endpoints: f.endpoints, Key: peer.raw, Token: f.token(peer), Log: discardLog(),
	})
	if err != nil {
		t.Fatalf("the far end could not reach the relay: %v", err)
	}
	defer func() { _ = far.Close() }()

	// Outbound: the kernel would write to the endpoint configured for this peer.
	endpoint, err := l.Endpoint(peer.encoded, "relay1")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	out, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(endpoint))
	if err != nil {
		t.Fatalf("dialling the peer's socket: %v", err)
	}
	defer func() { _ = out.Close() }()

	if _, err := out.Write([]byte("handshake-initiation")); err != nil {
		t.Fatalf("writing: %v", err)
	}

	buf := make([]byte, 2048)
	_ = far.SetReadDeadline(time.Now().Add(5 * time.Second))
	from, n, err := far.Receive(buf)
	if err != nil {
		t.Fatalf("the far end received nothing: %v", err)
	}
	if got := string(buf[:n]); got != "handshake-initiation" {
		t.Errorf("far end got %q", got)
	}
	if from != me.raw {
		t.Error("the relay did not name this device as the sender")
	}

	// Inbound: the reply must reach the WireGuard port from the peer's own socket, or the
	// kernel would not associate it with the peer.
	if err := far.Send(me.raw, []byte("handshake-response")); err != nil {
		t.Fatalf("far end sending: %v", err)
	}
	payload, source := kernel.await(t, 5*time.Second)
	if got := string(payload); got != "handshake-response" {
		t.Errorf("the kernel port got %q", got)
	}
	if source.Port != int(endpoint.Port()) {
		t.Errorf("delivered from port %d, but the peer's configured endpoint is %v — "+
			"the kernel would not recognise it", source.Port, endpoint)
	}

	// Polled rather than read once: both counters are incremented just after the packet is
	// handed on, so the far end and the kernel port can both have seen theirs before the
	// forwarder has finished counting it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st := l.Status(); st.Forwarder.Relayed == 1 && st.Forwarder.Delivered == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	st := l.Status()
	t.Errorf("counters: relayed=%d delivered=%d, want 1 and 1",
		st.Forwarder.Relayed, st.Forwarder.Delivered)
}

// UDP does not report a session ending, so a relay that is still listening and no longer
// answering would otherwise leave this device attached to nothing and reporting itself
// connected. Nothing but the liveness check notices: there is no error to observe.
func TestASilentRelayIsGivenUpOn(t *testing.T) {
	f := startRelay(t)
	me := newDevice(t)
	l := newLink(t, me, newFakeKernel(t).port, clock.System{})
	l.keepalive = 20 * time.Millisecond
	l.deadAfter = 60 * time.Millisecond

	l.SetRelays(f.relayConfig("relay1"))
	l.SetToken(f.token(me), time.Now().Add(time.Minute))
	run(t, l)
	awaitConnected(t, l, true, 5*time.Second)

	f.mute()

	awaitConnected(t, l, false, 5*time.Second)
	if got := l.Status().LastError; got == "" {
		t.Error("gave up on the relay without saying why")
	}
}

// A relay whose socket has gone is a different failure, reported by the host rather than
// inferred. Both have to end the session, and only one of them involves this package's
// liveness check — so both are worth pinning.
func TestAnUnreachableRelayEndsTheSession(t *testing.T) {
	f := startRelay(t)
	me := newDevice(t)
	l := newLink(t, me, newFakeKernel(t).port, clock.System{})
	l.keepalive = 20 * time.Millisecond

	l.SetRelays(f.relayConfig("relay1"))
	l.SetToken(f.token(me), time.Now().Add(time.Minute))
	run(t, l)
	awaitConnected(t, l, true, 5*time.Second)

	f.stop()

	awaitConnected(t, l, false, 5*time.Second)
}

// A relay being replaced in desired state must not leave the device talking to the old one.
func TestChangingTheRelayDropsTheOldConnection(t *testing.T) {
	first, second := startRelay(t), startRelay(t)
	me := newDevice(t)
	l := newLink(t, me, newFakeKernel(t).port, clock.System{})

	l.SetRelays(first.relayConfig("relay1"))
	l.SetToken(first.token(me), time.Now().Add(time.Minute))
	run(t, l)
	awaitConnected(t, l, true, 5*time.Second)
	if got := l.Status().Endpoint; got != first.endpoints[0] {
		t.Fatalf("attached to %q, want %q", got, first.endpoints[0])
	}

	// A different relay, and a token minted by it: the two relays do not share a signer.
	l.SetToken(second.token(me), time.Now().Add(time.Minute))
	l.SetRelays(second.relayConfig("relay2"))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := l.Status(); st.Connected && st.Endpoint == second.endpoints[0] {
			if st.RelayID != "relay2" {
				t.Errorf("relay id = %q, want relay2", st.RelayID)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never moved to the new relay (status %+v)", l.Status())
}

// preferred_relay_id is the control plane's answer to "which one", and ignoring it would
// scatter a fleet across relays it was not asked to use.
func TestThePreferredRelayIsHonoured(t *testing.T) {
	cfg := &meshpv1.RelayConfig{
		Relays: []*meshpv1.RelayConfig_Relay{
			{Id: "a", Endpoints: []string{"a.example:3478"}},
			{Id: "b", Endpoints: []string{"b.example:3478"}},
		},
		PreferredRelayId: "b",
	}
	if got := preferred(cfg).GetId(); got != "b" {
		t.Errorf("chose %q, want b", got)
	}

	cfg.PreferredRelayId = "missing"
	if got := preferred(cfg).GetId(); got != "a" {
		t.Errorf("with an unknown preference chose %q, want the first (a)", got)
	}
	if preferred(&meshpv1.RelayConfig{}) != nil {
		t.Error("found a relay in an empty configuration")
	}
	if preferred(nil) != nil {
		t.Error("found a relay in no configuration at all")
	}
}

// A relay refusing a session mid-flight means the credential is spent, so the link has to
// stop presenting it or it will loop on the same rejection.
func TestARefusedSessionDropsTheToken(t *testing.T) {
	f := startRelay(t)
	me := newDevice(t)
	l := newLink(t, me, 51820, clock.System{})
	l.SetRelays(f.relayConfig("relay1"))

	// A token this relay's signer never minted.
	other := startRelay(t)
	l.SetToken(other.token(me), time.Now().Add(time.Minute))
	run(t, l)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !l.Status().HasToken {
			if !l.NeedsToken() {
				t.Fatal("dropped the refused token but did not ask for another")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("kept presenting a token the relay refused (status %+v)", l.Status())
}

// Closing has to release the sockets: they are the endpoints the kernel was told about, and
// a daemon shutting down and starting again would otherwise leak one per peer.
func TestCloseReleasesEverything(t *testing.T) {
	f := startRelay(t)
	l := newLink(t, newDevice(t), 51820, clock.System{})
	l.SetRelays(f.relayConfig("relay1"))
	if _, err := l.Endpoint(newDevice(t).encoded, "relay1"); err != nil {
		t.Fatal(err)
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := l.Status().Forwarder.Peers; got != 0 {
		t.Errorf("still serving %d peers after Close", got)
	}
	if _, err := l.Endpoint(newDevice(t).encoded, "relay1"); err == nil {
		t.Error("served an endpoint after Close")
	}
	if l.NeedsToken() {
		t.Error("a closed link asked for a token")
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close is not idempotent: %v", err)
	}
}

// Stopping is not failing. The watchdog closes the connection to unblock the read, so the
// error on the way out says "closed" — recorded as the last error it would leave every
// stopped agent claiming its relay broke.
func TestShuttingDownIsNotRecordedAsAFailure(t *testing.T) {
	f := startRelay(t)
	me := newDevice(t)
	l := newLink(t, me, newFakeKernel(t).port, clock.System{})

	l.SetRelays(f.relayConfig("relay1"))
	l.SetToken(f.token(me), time.Now().Add(time.Minute))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	awaitConnected(t, l, true, 5*time.Second)

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return when its context ended")
	}

	if st := l.Status(); st.LastError != "" {
		t.Errorf("last error = %q after a clean shutdown", st.LastError)
	}
}

// A link something has finished with has nothing left to dial for, and a loop that kept
// idling on it would outlive the membership it belonged to.
func TestRunReturnsOnceTheLinkIsClosed(t *testing.T) {
	l := newLink(t, newDevice(t), 51820, clock.System{})

	done := make(chan error, 1)
	go func() { done <- l.Run(context.Background()) }()

	// Give the loop a moment to reach its idle wait, then take the link away.
	time.Sleep(50 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l.wakeDialer()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept looping on a closed link")
	}
}
