package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/routeprobe"
	"github.com/meshpnet/meshp/internal/wglink"
	"github.com/meshpnet/meshp/internal/wgplan"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// fakeLink records what it was asked to do and answers as a device would.
//
// A fake here, unlike in wglink, because what is under test is the sequencing and the
// translation — not the kernel. wglink's own tests use a real interface for the parts only
// a kernel can answer.
type fakeLink struct {
	observed wgplan.Observed
	applied  []wgplan.Op
	kind     wglink.Kind

	observeErr error
	failOn     wgplan.OpKind
	failErr    error
	closed     bool
}

func newFakeLink() *fakeLink {
	return &fakeLink{kind: wglink.KindKernel, failOn: -1}
}

func (f *fakeLink) Observe(string) (wgplan.Observed, error) {
	if f.observeErr != nil {
		return wgplan.Observed{}, f.observeErr
	}
	return f.observed, nil
}

func (f *fakeLink) Apply(_ string, op wgplan.Op) error {
	if op.Kind == f.failOn {
		return f.failErr
	}
	f.applied = append(f.applied, op)

	// Enough of a device to make a second reconcile meaningful.
	switch op.Kind {
	case wgplan.CreateDevice:
		f.observed.Exists = true
	case wgplan.DestroyDevice:
		f.observed = wgplan.Observed{}
	case wgplan.BringUp:
		f.observed.Up = true
	case wgplan.SetDevice:
		f.observed.PrivateKey = op.Device.PrivateKey
		f.observed.MTU = op.Device.MTU
		f.observed.ListenPort = 43521 // as a kernel does when asked for any
	case wgplan.SetPeer:
		// Replace by key, and treat an empty endpoint as "leave the endpoint alone" — both
		// as the kernel does. A fake that appended instead would hold duplicates, and one
		// that cleared the endpoint would hide the roaming case entirely.
		next := op.Peer
		replaced := false
		for i, existing := range f.observed.Peers {
			if existing.PublicKey != next.PublicKey {
				continue
			}
			if next.Endpoint == "" {
				next.Endpoint = existing.Endpoint
				next.HasHandshake = existing.HasHandshake
				next.HandshakeAge = existing.HandshakeAge
			}
			f.observed.Peers[i] = next
			replaced = true
			break
		}
		if !replaced {
			f.observed.Peers = append(f.observed.Peers, next)
		}
	case wgplan.RemovePeer:
		var kept []wgplan.Peer
		for _, p := range f.observed.Peers {
			if p.PublicKey != op.Peer.PublicKey {
				kept = append(kept, p)
			}
		}
		f.observed.Peers = kept
	case wgplan.AddAddress:
		f.observed.Addresses = append(f.observed.Addresses, op.Prefix)
	case wgplan.AddRoute:
		f.observed.Routes = append(f.observed.Routes, op.Prefix)
	case wgplan.RemoveAddress:
		f.observed.Addresses = without(f.observed.Addresses, op.Prefix)
	case wgplan.RemoveRoute:
		f.observed.Routes = without(f.observed.Routes, op.Prefix)
	}
	return nil
}

func without(prefixes []netip.Prefix, drop netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range prefixes {
		if p != drop {
			out = append(out, p)
		}
	}
	return out
}

func (f *fakeLink) Kind(string) (wglink.Kind, error) { return f.kind, nil }
func (f *fakeLink) Close() error                     { f.closed = true; return nil }

func (f *fakeLink) count(kind wgplan.OpKind) int {
	var n int
	for _, op := range f.applied {
		if op.Kind == kind {
			n++
		}
	}
	return n
}

// A real WireGuard key, because wgplan does not parse keys but the translation must carry
// them through unchanged.
const (
	ourKey   = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	bobKey   = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	carolKey = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
)

func membership() Membership {
	return Membership{
		InterfaceName: "meshp0",
		PrivateKey:    ourKey,
		AddressV4:     "100.90.0.1",
		AddressV6:     "fd7c::1",
	}
}

// stateWith builds what the control plane would have sent.
func stateWith(version uint64, peers ...*meshpv1.Peer) *peerset.Set {
	s := peerset.New()
	s.Apply(&meshpv1.StateDelta{
		FromVersion: 0,
		ToVersion:   version,
		UpsertPeers: peers,
		Tunnel:      &meshpv1.TunnelConfig{Mtu: 1420},
	})
	return s
}

func peer(key string, ips ...string) *meshpv1.Peer {
	return &meshpv1.Peer{
		PublicKey:                  key,
		AllowedIps:                 ips,
		PersistentKeepaliveSeconds: 25,
		DeviceName:                 "device-" + key[:4],
	}
}

func TestApplyBringsUpAnInterfaceAndReportsIt(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)

	state := stateWith(7, peer(bobKey, "100.90.0.2/32", "fd7c::2/128"))
	unapplied, err := r.Apply(context.Background(), state)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(unapplied) != 0 {
		t.Errorf("reported %v as unapplied", unapplied)
	}

	if link.count(wgplan.CreateDevice) != 1 {
		t.Error("the interface was not created")
	}
	if link.count(wgplan.SetPeer) != 1 {
		t.Errorf("%d peers configured, want 1", link.count(wgplan.SetPeer))
	}
	if link.count(wgplan.AddAddress) != 2 {
		t.Errorf("%d addresses added, want 2", link.count(wgplan.AddAddress))
	}
	if link.count(wgplan.AddRoute) != 2 {
		t.Errorf("%d routes added, want 2", link.count(wgplan.AddRoute))
	}

	status := r.Status()
	if !status.Up {
		t.Error("the tunnel is not reported as up")
	}
	if status.Kind != wglink.KindKernel {
		t.Errorf("kind is %q, want kernel", status.Kind)
	}
	if status.AppliedVersion != 7 {
		t.Errorf("applied version is %d, want 7", status.AppliedVersion)
	}
	if status.LastError != "" {
		t.Errorf("last error is %q, want empty", status.LastError)
	}
}

// Invariant 18, through the whole stack: the second time round there is nothing to do.
func TestApplyingTheSameStateTwiceTouchesNothingTheSecondTime(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)
	state := stateWith(7, peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	first := len(link.applied)
	if first == 0 {
		t.Fatal("the first apply did nothing")
	}

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if len(link.applied) != first {
		t.Errorf("the second apply did %d more operations: %v",
			len(link.applied)-first, link.applied[first:])
	}
}

// A failure part-way through must be reported as not applied, and must not claim the
// version: an agent that says it reached a state it did not is invisible to the one metric
// that would show it is broken.
func TestAFailedApplyIsReportedAndDoesNotClaimTheVersion(t *testing.T) {
	link := newFakeLink()
	link.failOn = wgplan.AddRoute
	link.failErr = errors.New("network is down")

	r := New(link, membership(), nil, nil, nil)
	unapplied, err := r.Apply(context.Background(), stateWith(9, peer(bobKey, "100.90.0.2/32")))
	if err == nil {
		t.Fatal("a failing operation was reported as success")
	}
	if len(unapplied) == 0 {
		t.Error("nothing was reported as unapplied")
	}

	status := r.Status()
	if status.Up {
		t.Error("the tunnel is reported up after a failed apply")
	}
	if status.AppliedVersion == 9 {
		t.Error("the failed version was recorded as applied")
	}
	if !strings.Contains(status.LastError, "network is down") {
		t.Errorf("the last error does not carry the cause: %q", status.LastError)
	}
	// And it says which operation, because "apply failed" on a long plan is not actionable.
	if !strings.Contains(err.Error(), "add-route") {
		t.Errorf("the error does not name the operation that failed: %v", err)
	}
}

// A platform with no implementation is a normal state, not a crash: the device is enrolled,
// holds an address, and has no tunnel. It has to be able to say so.
func TestAnUnsupportedPlatformIsReportedRatherThanFatal(t *testing.T) {
	link := newFakeLink()
	link.observeErr = wglink.ErrUnsupported

	r := New(link, membership(), nil, nil, nil)
	unapplied, err := r.Apply(context.Background(), stateWith(3, peer(bobKey, "100.90.0.2/32")))
	if !errors.Is(err, wglink.ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
	if len(unapplied) == 0 {
		t.Error("nothing was reported as unapplied")
	}
	if status := r.Status(); status.Up {
		t.Error("a tunnel is reported up on a platform that cannot make one")
	}
}

// A peer whose description cannot be applied stops the whole update. Skipping it would leave
// a device unreachable with everything reporting success.
func TestAPeerThatCannotBeTranslatedRefusesTheUpdate(t *testing.T) {
	cases := map[string]*meshpv1.Peer{
		"an allowed IP that is not a prefix": {
			PublicKey:  bobKey,
			AllowedIps: []string{"not-a-prefix"},
		},
		"an endpoint that is not an address and port": {
			PublicKey:  bobKey,
			AllowedIps: []string{"100.90.0.2/32"},
			Endpoints:  []string{"example.com"},
		},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			link := newFakeLink()
			r := New(link, membership(), nil, nil, nil)
			if _, err := r.Apply(context.Background(), stateWith(4, p)); err == nil {
				t.Fatal("the update was accepted")
			}
			if len(link.applied) != 0 {
				t.Errorf("operations were applied despite the refusal: %v", link.applied)
			}
		})
	}
}

// Invariant 20.
func TestTeardownRemovesTheInterface(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)
	if _, err := r.Apply(context.Background(), stateWith(2, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}

	if err := r.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if link.count(wgplan.DestroyDevice) != 1 {
		t.Error("the interface was not destroyed")
	}
	if link.observed.Exists {
		t.Error("the interface still exists")
	}
	if r.Status().Up {
		t.Error("the tunnel is still reported up")
	}
}

// --- translation ------------------------------------------------------------

func TestDesiredRendersAddressesAsHostPrefixes(t *testing.T) {
	m := membership()
	m.AddressV4 = "100.90.0.1"
	m.AddressV6 = "fd7c::1"

	iface, _, err := Desired(m, stateWith(1), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"100.90.0.1/32", "fd7c::1/128"}
	if len(iface.Addresses) != len(want) {
		t.Fatalf("%d addresses, want %d", len(iface.Addresses), len(want))
	}
	for i, w := range want {
		if got := iface.Addresses[i].String(); got != w {
			t.Errorf("address %d is %s, want %s", i, got, w)
		}
	}
}

// A pool prefix where a host prefix belongs would create a connected route for the whole
// pool, so traffic to an unassigned address is swallowed by the tunnel (ADR-0015).
func TestDesiredRefusesAnAddressThatIsNotOneHost(t *testing.T) {
	for _, addr := range []string{"100.90.0.1/24", "fd7c::1/64"} {
		m := membership()
		m.AddressV4 = addr
		m.AddressV6 = ""
		if _, _, err := Desired(m, stateWith(1), nil, nil, nil); err == nil {
			t.Errorf("%s was accepted", addr)
		}
	}
}

// An address already carrying /32 is what the daemon's state file may hold, and must be
// accepted rather than rejected as malformed.
func TestDesiredAcceptsAnAddressThatAlreadyCarriesItsPrefix(t *testing.T) {
	m := membership()
	m.AddressV4 = "100.90.0.1/32"
	m.AddressV6 = "fd7c::1/128"

	iface, _, err := Desired(m, stateWith(1), nil, nil, nil)
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(iface.Addresses) != 2 {
		t.Fatalf("%d addresses, want 2", len(iface.Addresses))
	}
}

func TestDesiredRefusesAMembershipWithNothingToWorkFrom(t *testing.T) {
	t.Run("no private key", func(t *testing.T) {
		m := membership()
		m.PrivateKey = ""
		if _, _, err := Desired(m, stateWith(1), nil, nil, nil); err == nil {
			t.Error("a membership with no private key was accepted")
		}
	})
	t.Run("no addresses", func(t *testing.T) {
		m := membership()
		m.AddressV4, m.AddressV6 = "", ""
		if _, _, err := Desired(m, stateWith(1), nil, nil, nil); err == nil {
			t.Error("a membership with no addresses was accepted")
		}
	})
}

// The MTU comes from the server when it says one, because the server is what knows about
// the path (ADR-0011 will make this matter more).
func TestDesiredTakesTheMTUFromTheServer(t *testing.T) {
	state := peerset.New()
	state.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: 1,
		Tunnel: &meshpv1.TunnelConfig{Mtu: 1280},
	})

	iface, _, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if iface.MTU != 1280 {
		t.Errorf("MTU is %d, want the server's 1280", iface.MTU)
	}
}

// And a sane default when it does not, rather than zero — which wgplan rejects, so an
// interface would never come up at all.
func TestDesiredFallsBackToADefaultMTU(t *testing.T) {
	state := peerset.New()
	state.Apply(&meshpv1.StateDelta{FromVersion: 0, ToVersion: 1})

	iface, _, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if iface.MTU != defaultMTU {
		t.Errorf("MTU is %d, want the default %d", iface.MTU, defaultMTU)
	}
	if err := iface.Validate(); err != nil {
		t.Errorf("the default does not produce a usable interface: %v", err)
	}
}

// A peer with no endpoint is configured and unreachable, which is the honest state of every
// peer today: nothing discovers endpoints yet.
func TestAPeerWithNoEndpointIsStillConfigured(t *testing.T) {
	iface, _, err := Desired(membership(), stateWith(1, peer(bobKey, "100.90.0.2/32")), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(iface.Peers) != 1 {
		t.Fatalf("%d peers, want 1", len(iface.Peers))
	}
	if iface.Peers[0].Endpoint != "" {
		t.Errorf("endpoint is %q, want empty", iface.Peers[0].Endpoint)
	}
	if len(iface.Peers[0].AllowedIPs) != 1 {
		t.Error("the peer's allowed IPs were lost")
	}
}

// The server sends endpoints best-first; WireGuard holds one. Choosing among them is the
// agent's job once there is something to choose with (ADR-0003).
func TestTheFirstEndpointIsUsed(t *testing.T) {
	p := peer(bobKey, "100.90.0.2/32")
	p.Endpoints = []string{"203.0.113.2:51820", "198.51.100.2:51820"}

	iface, _, err := Desired(membership(), stateWith(1, p), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := iface.Peers[0].Endpoint; got != "203.0.113.2:51820" {
		t.Errorf("endpoint is %q, want the first one offered", got)
	}
}

// The key is carried through untouched. wgplan does not parse keys, so a translation that
// mangled one would only fail at the kernel, on a real host, with a confusing message.
func TestKeysArePassedThroughUnchanged(t *testing.T) {
	iface, _, err := Desired(membership(), stateWith(1, peer(bobKey, "100.90.0.2/32")), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(iface.PrivateKey) != ourKey {
		t.Errorf("the private key was altered: %q", iface.PrivateKey)
	}
	if string(iface.Peers[0].PublicKey) != bobKey {
		t.Errorf("the peer's key was altered: %q", iface.Peers[0].PublicKey)
	}
}

// Applying the same state again repairs an interface that something else changed.
//
// This is what the daemon's periodic reconcile relies on: nothing arrives from the control
// plane when an operator takes an interface down or another process removes an address, so
// convergence has to come from re-applying what is already known. Verified end to end in the
// tunnel e2e, where a second daemon takes the interface over and the first puts it back.
func TestReapplyingTheSameStateRepairsADamagedInterface(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)
	state := stateWith(5, peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	// Something else has been at it: an address gone, a peer gone, the link down.
	link.observed.Addresses = nil
	link.observed.Peers = link.observed.Peers[:1]
	link.observed.Up = false
	link.applied = nil

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatalf("re-applying: %v", err)
	}

	if link.count(wgplan.AddAddress) == 0 {
		t.Error("the missing address was not put back")
	}
	if link.count(wgplan.BringUp) == 0 {
		t.Error("the interface was left down")
	}
	if link.count(wgplan.SetPeer) == 0 {
		t.Error("the missing peer was not put back")
	}

	// And it is now correct: a further pass finds nothing to do.
	link.applied = nil
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if len(link.applied) != 0 {
		t.Errorf("the repair did not converge; a third pass still wants: %v", link.applied)
	}
}

// The reconciler must not undo roaming. A peer that moved and is talking from its new
// address keeps it, even though the control plane still names the old one — otherwise every
// reconcile tick would break a working path (see wgplan's endpoint rules, and wglink's
// TestALearnedEndpointIsNotTreatedAsDrift against a real kernel).
func TestReconcilingDoesNotUndoRoaming(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)

	p := peer(bobKey, "100.90.0.2/32")
	p.Endpoints = []string{"203.0.113.2:51820"}
	state := stateWith(3, p)

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	// Bob has moved, and the device knows because his traffic arrives from somewhere else.
	for i := range link.observed.Peers {
		link.observed.Peers[i].Endpoint = "198.51.100.9:33445"
		link.observed.Peers[i].HasHandshake = true
		link.observed.Peers[i].HandshakeAge = 20 * time.Second
	}
	link.applied = nil

	// The control plane has not caught up and still says the old address.
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if len(link.applied) != 0 {
		t.Errorf("reconciling replaced a working endpoint with a stale one: %v", link.applied)
	}
	if got := link.observed.Peers[0].Endpoint; got != "198.51.100.9:33445" {
		t.Errorf("the peer's endpoint is now %q, want where it actually is", got)
	}
}

// The port the device settled on is reported back, so the daemon can keep it. Asking for any
// port means the kernel chooses, and its choice is the thing worth remembering.
func TestTheSettledListenPortIsReported(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil) // no port asked for

	if _, err := r.Apply(context.Background(), stateWith(1, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if got := r.Status().ListenPort; got != 43521 {
		t.Errorf("reported listen port %d, want the one the device chose (43521)", got)
	}
}

// A membership that already has a port asks for it again. Without this, every restart moves
// the port, which invalidates the endpoint every peer holds and drops any NAT mapping that
// was keeping a path open.
func TestARememberedPortIsAskedForAgain(t *testing.T) {
	m := membership()
	m.ListenPort = 51999

	iface, _, err := Desired(m, stateWith(1), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if iface.ListenPort != 51999 {
		t.Errorf("asked for port %d, want the remembered 51999", iface.ListenPort)
	}
}

// A membership that has never come up asks for any port.
func TestAMembershipWithNoPortAsksForAny(t *testing.T) {
	iface, _, err := Desired(membership(), stateWith(1), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if iface.ListenPort != 0 {
		t.Errorf("asked for port %d, want 0 meaning any", iface.ListenPort)
	}
}

// ---------------------------------------------------------------------------
// Relayed peers

// fakeRelay hands out loopback endpoints and records what it was asked to keep.
type fakeRelay struct {
	// serving is the relay id this device is attached to. A peer naming any other gets
	// nothing, exactly as relaylink behaves.
	serving string

	next      int
	endpoints map[string]netip.AddrPort
	retained  [][]string
	port      int
}

func newFakeRelay(serving string) *fakeRelay {
	return &fakeRelay{serving: serving, next: 40000, endpoints: map[string]netip.AddrPort{}}
}

func (f *fakeRelay) Endpoint(publicKey, relayID string) (netip.AddrPort, error) {
	if relayID != f.serving {
		return netip.AddrPort{}, errors.New("not attached to that relay")
	}
	if have, ok := f.endpoints[publicKey]; ok {
		return have, nil
	}
	f.next++
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(f.next))
	f.endpoints[publicKey] = addr
	return addr, nil
}

func (f *fakeRelay) Retain(keys []string) {
	f.retained = append(f.retained, append([]string(nil), keys...))
}

func (f *fakeRelay) SetWireGuardPort(port int) { f.port = port }

func relayedPeer(key, relayID string, ips ...string) *meshpv1.Peer {
	p := peer(key, ips...)
	p.RelayId = relayID
	return p
}

// The ordinary path today: no peer has a discovered endpoint, so every peer is reached
// through a relay (ADR-0002). The kernel is given a local socket to send to, and the peer
// is marked relayed so wgplan does not mistake a loopback endpoint for drift.
func TestARelayedPeerIsGivenItsLoopbackEndpoint(t *testing.T) {
	relay := newFakeRelay("relay1")

	iface, _, err := Desired(membership(),
		stateWith(1, relayedPeer(bobKey, "relay1", "100.90.0.2/32")), relay, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(iface.Peers) != 1 {
		t.Fatalf("%d peers, want 1", len(iface.Peers))
	}

	p := iface.Peers[0]
	if !p.Relayed {
		t.Error("the peer was not marked relayed; wgplan would refuse a loopback endpoint")
	}
	addr, err := netip.ParseAddrPort(p.Endpoint)
	if err != nil {
		t.Fatalf("endpoint %q does not parse: %v", p.Endpoint, err)
	}
	if !addr.Addr().IsLoopback() {
		t.Errorf("endpoint %v is not on this host", addr)
	}
}

// A discovered endpoint beats a relay. Relay-first is about never depending on hole
// punching, not about preferring a relay to a path that works.
func TestADirectEndpointWinsOverARelay(t *testing.T) {
	relay := newFakeRelay("relay1")
	p := relayedPeer(bobKey, "relay1", "100.90.0.2/32")
	p.Endpoints = []string{"203.0.113.2:51820"}

	iface, _, err := Desired(membership(), stateWith(1, p), relay, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := iface.Peers[0].Endpoint; got != "203.0.113.2:51820" {
		t.Errorf("endpoint = %q, want the direct one", got)
	}
	if iface.Peers[0].Relayed {
		t.Error("a peer with a direct endpoint was marked relayed")
	}
	if len(relay.endpoints) != 0 {
		t.Error("opened a relay socket for a peer that does not need one")
	}
}

// One peer relayed through somewhere this device is not attached to must not take down the
// interface every other peer is reached through.
func TestAPeerOnAnUnreachableRelayDoesNotBreakTheOthers(t *testing.T) {
	relay := newFakeRelay("relay1")

	iface, _, err := Desired(membership(), stateWith(1,
		relayedPeer(bobKey, "relay1", "100.90.0.2/32"),
		relayedPeer(carolKey, "relay2", "100.90.0.3/32"),
	), relay, nil, nil)
	if err != nil {
		t.Fatalf("one unreachable relay refused the whole interface: %v", err)
	}
	if len(iface.Peers) != 2 {
		t.Fatalf("%d peers, want 2", len(iface.Peers))
	}

	byKey := map[string]wgplan.Peer{}
	for _, p := range iface.Peers {
		byKey[string(p.PublicKey)] = p
	}
	if p := byKey[bobKey]; !p.Relayed || p.Endpoint == "" {
		t.Error("the reachable peer lost its relayed path")
	}
	if p := byKey[carolKey]; p.Relayed || p.Endpoint != "" {
		t.Errorf("the peer on the other relay was given an endpoint %q that goes nowhere", p.Endpoint)
	}
}

// With no relay at all — no data plane, or a deployment that has not configured one — a
// relayed peer is unreachable rather than refused.
func TestNoRelayLeavesRelayedPeersWithoutEndpoints(t *testing.T) {
	iface, _, err := Desired(membership(),
		stateWith(1, relayedPeer(bobKey, "relay1", "100.90.0.2/32")), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := iface.Peers[0].Endpoint; got != "" {
		t.Errorf("endpoint = %q, want none", got)
	}
	if iface.Peers[0].Relayed {
		t.Error("marked relayed with nothing relaying it")
	}
}

// Retain runs after the kernel has been given the new endpoints, never before: wgctrl
// cannot clear an endpoint, so closing a socket the kernel still points at leaves a peer
// that looks configured and goes nowhere (ADR-0016).
func TestRetainNamesTheStillRelayedPeersAfterApplying(t *testing.T) {
	link := newFakeLink()
	relay := newFakeRelay("relay1")
	r := New(link, membership(), relay, nil, nil)

	if _, err := r.Apply(context.Background(), stateWith(1,
		relayedPeer(bobKey, "relay1", "100.90.0.2/32"),
		relayedPeer(carolKey, "relay1", "100.90.0.3/32"),
	)); err != nil {
		t.Fatal(err)
	}
	if len(relay.retained) != 1 {
		t.Fatalf("Retain called %d times, want 1", len(relay.retained))
	}
	if got := len(relay.retained[0]); got != 2 {
		t.Fatalf("retained %d peers, want 2", got)
	}

	// Carol goes direct; her socket is no longer needed and must be named out of the set.
	carol := relayedPeer(carolKey, "relay1", "100.90.0.3/32")
	carol.Endpoints = []string{"203.0.113.3:51820"}
	if _, err := r.Apply(context.Background(), stateWith(2,
		relayedPeer(bobKey, "relay1", "100.90.0.2/32"), carol,
	)); err != nil {
		t.Fatal(err)
	}
	last := relay.retained[len(relay.retained)-1]
	if len(last) != 1 || last[0] != bobKey {
		t.Errorf("retained %v, want only the still-relayed peer", last)
	}
}

// A plan that did not fully apply may have left the kernel pointing at a socket Retain
// would take away, so it is skipped entirely on the failure path.
func TestRetainIsSkippedWhenApplyingFails(t *testing.T) {
	link := newFakeLink()
	link.failOn = wgplan.SetPeer
	link.failErr = errors.New("the kernel refused")
	relay := newFakeRelay("relay1")
	r := New(link, membership(), relay, nil, nil)

	if _, err := r.Apply(context.Background(),
		stateWith(1, relayedPeer(bobKey, "relay1", "100.90.0.2/32"))); err == nil {
		t.Fatal("a failing apply reported success")
	}
	if len(relay.retained) != 0 {
		t.Errorf("Retain ran after a failed apply: %v", relay.retained)
	}
}

// The port a relayed peer's packets come back to is the kernel's choice, so nothing can be
// told it until the interface exists. A forwarder left without it drops everything inbound.
// This membership has never come up, so it asks for any port and the kernel chooses. The
// relay has to be told that choice and not the zero it asked with, or every packet coming
// back from a peer is delivered nowhere.
func TestTheListenPortIsHandedToTheRelayAfterConverging(t *testing.T) {
	link := newFakeLink()
	relay := newFakeRelay("relay1")
	m := membership()
	if m.ListenPort != 0 {
		t.Fatalf("this test is about a membership with no port yet, got %d", m.ListenPort)
	}
	r := New(link, m, relay, nil, nil)

	if _, err := r.Apply(context.Background(),
		stateWith(1, relayedPeer(bobKey, "relay1", "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}

	want := r.Status().ListenPort
	if want == 0 {
		t.Fatal("the interface reported no listen port")
	}
	if relay.port != want {
		t.Errorf("the relay was told port %d, but the interface listens on %d", relay.port, want)
	}
}

// ---------------------------------------------------------------------------
// Policy enforcement

// fakeFilter records what it was asked to enforce.
type fakeFilter struct {
	applied   []*meshpv1.PacketFilter
	forwarded [][]*meshpv1.AdvertisedRoutes_Group
	iface     string
	failErr   error
	fwdErr    error

	// locks records every lock applied, by the interface it named. An empty name is a
	// removal, so the sequence shows the order the lock went on and came off — which is
	// the property that matters most about it.
	locks     []string
	lockErr   error
	endpoints [][]netip.AddrPort
	excluded  [][]netip.Prefix

	// order, when set, is shared with the egress fake. Separate slices per fake record what
	// each of them did and cannot show which happened first, and "the lock before the route"
	// is the whole property under test — a mutation that swapped them survived until this
	// existed.
	order *[]string
}

func (f *fakeFilter) ApplyLock(_ context.Context, iface string, endpoints []netip.AddrPort, excluded []netip.Prefix) error {
	if f.lockErr != nil {
		return f.lockErr
	}
	f.locks = append(f.locks, iface)
	f.endpoints = append(f.endpoints, endpoints)
	f.excluded = append(f.excluded, excluded)
	if f.order != nil {
		if iface == "" {
			*f.order = append(*f.order, "unlock")
		} else {
			*f.order = append(*f.order, "lock "+iface)
		}
	}
	return nil
}

// fakeEgress records claims and releases in order, which is what the ordering assertions
// read: a claim that happened before its lock is the bug the whole feature is built around.
type fakeEgress struct {
	events   []string
	claimErr error
	relErr   error
	order    *[]string
}

func (e *fakeEgress) Claim(iface string) error {
	if e.claimErr != nil {
		return e.claimErr
	}
	e.events = append(e.events, "claim "+iface)
	if e.order != nil {
		*e.order = append(*e.order, "claim "+iface)
	}
	return nil
}

func (e *fakeEgress) Release() error {
	if e.relErr != nil {
		return e.relErr
	}
	e.events = append(e.events, "release")
	if e.order != nil {
		*e.order = append(*e.order, "release")
	}
	return nil
}

func (f *fakeFilter) ApplyForward(_ context.Context, _ string, groups []*meshpv1.AdvertisedRoutes_Group) error {
	if f.fwdErr != nil {
		return f.fwdErr
	}
	f.forwarded = append(f.forwarded, groups)
	return nil
}

func (f *fakeFilter) Apply(_ context.Context, iface string, filter *meshpv1.PacketFilter) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.iface = iface
	f.applied = append(f.applied, filter)
	return nil
}

func stateWithFilter(version uint64, filter *meshpv1.PacketFilter, peers ...*meshpv1.Peer) *peerset.Set {
	s := peerset.New()
	s.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: version, UpsertPeers: peers,
		Tunnel: &meshpv1.TunnelConfig{Mtu: 1420},
		Filter: filter,
	})
	return s
}

func allowAll() *meshpv1.PacketFilter {
	return &meshpv1.PacketFilter{
		DefaultDeny: true,
		Inbound: []*meshpv1.PacketFilter_Rule{{
			SrcPrefixes: []string{"100.90.0.2/32"}, DstPrefixes: []string{"100.90.0.1/32"},
			Protocol: "any", Allow: true,
		}},
	}
}

func TestThePolicyIsEnforcedAfterTheInterfaceExists(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)

	if _, err := r.Apply(context.Background(),
		stateWithFilter(1, allowAll(), peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.applied) != 1 {
		t.Fatalf("the filter was applied %d times, want 1", len(filter.applied))
	}
	if filter.iface != "meshp0" {
		t.Errorf("enforced on %q, want meshp0", filter.iface)
	}
	// A ruleset naming an interface that does not exist loads happily and matches nothing,
	// so the interface has to be there first.
	if link.count(wgplan.CreateDevice) == 0 {
		t.Error("the interface was never created")
	}
}

// Loading is atomic and cheap, but it resets the counters on the drop rules — and an
// operator watching "is this policy denying anything" would see them return to zero on
// every reconcile tick.
func TestAnUnchangedPolicyIsNotReloaded(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)
	state := stateWithFilter(1, allowAll(), peer(bobKey, "100.90.0.2/32"))

	for range 3 {
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if len(filter.applied) != 1 {
		t.Errorf("an unchanged policy was reloaded %d times", len(filter.applied))
	}

	// A changed policy is loaded.
	changed := allowAll()
	changed.Inbound[0].Protocol = "tcp"
	changed.Inbound[0].Ports = []string{"22"}
	if _, err := r.Apply(context.Background(),
		stateWithFilter(2, changed, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.applied) != 2 {
		t.Errorf("a changed policy was not loaded: %d applies", len(filter.applied))
	}
}

// A withdrawn policy must stop being enforced. The nil reaches the filter so it can remove
// its ruleset; leaving it would go on denying traffic the network no longer denies.
func TestAWithdrawnPolicyIsRemoved(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)

	if _, err := r.Apply(context.Background(),
		stateWithFilter(1, allowAll(), peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(context.Background(),
		stateWithFilter(2, nil, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.applied) != 2 {
		t.Fatalf("%d applies, want 2", len(filter.applied))
	}
	if filter.applied[1] != nil {
		t.Error("withdrawing a policy did not reach the filter as a removal")
	}
}

// A network with no policy on a host that cannot filter is entirely normal and must not be
// reported as a problem.
func TestNoPolicyAndNoFilterIsNotAFailure(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)

	unapplied, err := r.Apply(context.Background(), stateWith(1, peer(bobKey, "100.90.0.2/32")))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(unapplied) != 0 {
		t.Errorf("reported %v as unapplied with no policy to enforce", unapplied)
	}
}

// A policy arriving at a host that cannot enforce it must be reported, or the device looks
// converged while permitting everything its policy denies (ADR-0007).
func TestAPolicyOnAHostThatCannotFilterIsReported(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)

	unapplied, err := r.Apply(context.Background(),
		stateWithFilter(1, allowAll(), peer(bobKey, "100.90.0.2/32")))
	if err == nil {
		t.Fatal("a host that cannot filter accepted a policy silently")
	}
	if len(unapplied) != 1 || unapplied[0] != "filter" {
		t.Errorf("unapplied = %v, want [filter]", unapplied)
	}

	// The peers still converged, so the honest report is "peers but not policy" rather
	// than nothing applied at all.
	if link.count(wgplan.SetPeer) == 0 {
		t.Error("the peers were abandoned because the policy could not be enforced")
	}
}

// The same when the filter exists and refuses.
func TestAFilterThatFailsIsReportedRatherThanIgnored(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{failErr: errors.New("nft: syntax error")}
	r := New(link, membership(), nil, filter, nil)

	unapplied, err := r.Apply(context.Background(),
		stateWithFilter(1, allowAll(), peer(bobKey, "100.90.0.2/32")))
	if err == nil {
		t.Fatal("a filter that would not load was reported as applied")
	}
	if len(unapplied) != 1 || unapplied[0] != "filter" {
		t.Errorf("unapplied = %v, want [filter]", unapplied)
	}

	// And it is retried rather than remembered as done.
	filter.failErr = nil
	if _, err := r.Apply(context.Background(),
		stateWithFilter(1, allowAll(), peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	if len(filter.applied) != 1 {
		t.Error("a policy that failed to load was never retried")
	}
}

// A ruleset outliving the interface it names would match nothing while an operator reads a
// table meshp installed and no longer maintains (Invariant 20).
func TestTeardownRemovesThePolicy(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)

	if _, err := r.Apply(context.Background(),
		stateWithFilter(1, allowAll(), peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if err := r.Teardown(); err != nil {
		t.Fatal(err)
	}
	if len(filter.applied) != 2 || filter.applied[1] != nil {
		t.Errorf("teardown did not remove the policy: %d applies", len(filter.applied))
	}
}

// ---------------------------------------------------------------------------
// Carried prefixes

func assignmentTo(name, carrier string, prefixes ...string) *meshpv1.RouteGroupAssignment {
	return &meshpv1.RouteGroupAssignment{
		RouteGroupId: "group-" + name, Name: name, Prefixes: prefixes,
		Candidates: []*meshpv1.RouteCandidate{{PeerPublicKey: carrier, Priority: 1}},
	}
}

func stateWithRoutes(version uint64, assignments []*meshpv1.RouteGroupAssignment, peers ...*meshpv1.Peer) *peerset.Set {
	s := peerset.New()
	s.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: version, UpsertPeers: peers,
		Tunnel:      &meshpv1.TunnelConfig{Mtu: 1420},
		RouteGroups: assignments,
	})
	return s
}

func allowedIPsOf(iface wgplan.Interface, key string) []string {
	for _, p := range iface.Peers {
		if string(p.PublicKey) == key {
			out := make([]string, 0, len(p.AllowedIPs))
			for _, a := range p.AllowedIPs {
				out = append(out, a.String())
			}
			return out
		}
	}
	return nil
}

// The MSP case, end to end through the translation: a branch LAN becomes both cryptokey
// routing on the carrier and a system route at the interface. Both are required — WireGuard
// will not carry a packet for a prefix outside AllowedIPs, and the kernel will not send one
// to the interface without a route.
func TestACarriedPrefixReachesTheCarrierAndTheRoutingTable(t *testing.T) {
	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("branch-lan", bobKey, "192.168.10.0/24")},
		peer(bobKey, "100.90.0.2/32"))

	iface, unhonoured, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unhonoured) != 0 {
		t.Fatalf("reported %v as unhonoured", unhonoured)
	}

	got := allowedIPsOf(iface, bobKey)
	if !slicesContain(got, "192.168.10.0/24") {
		t.Fatalf("the carrier's allowed IPs are %v; the prefix is missing", got)
	}
	if !slicesContain(got, "100.90.0.2/32") {
		t.Errorf("the carrier lost its own address: %v", got)
	}

	// And the route follows, because wgplan derives what it installs from these.
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	routed := false
	for _, op := range link.applied {
		if op.Kind == wgplan.AddRoute && op.Prefix.String() == "192.168.10.0/24" {
			routed = true
		}
	}
	if !routed {
		t.Errorf("no route was installed for the carried prefix: %v", link.applied)
	}
}

// A peer carrying a default route needs it in its allowed IPs, because WireGuard will not
// send a packet to a peer whose allowed IPs do not cover the destination. The system route
// is a separate question, answered in wgplan and in the egress table.
func TestAnEgressGroupPutsTheDefaultInAllowedIPs(t *testing.T) {
	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("exit", bobKey, "0.0.0.0/0", "::/0")},
		peer(bobKey, "100.90.0.2/32"))

	iface, unhonoured, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatalf("an egress group made the whole description fail: %v", err)
	}
	if len(unhonoured) != 0 {
		t.Fatalf("unhonoured = %v, want none", unhonoured)
	}
	got := allowedIPsOf(iface, bobKey)
	for _, want := range []string{"0.0.0.0/0", "::/0"} {
		if !slicesContain(got, want) {
			t.Errorf("%s is not in the exit peer's allowed IPs: %v", want, got)
		}
	}
}

// And no system route in the main table for it. A default route there would capture the
// outer packets carrying this very tunnel and route them into it — the tunnel never comes
// up, and the kill switch is already installed by then.
func TestNoMainTableRouteIsInstalledForADefaultRoute(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)
	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("exit", bobKey, "0.0.0.0/0", "::/0")},
		peer(bobKey, "100.90.0.2/32"))

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	for _, op := range link.applied {
		if op.Kind == wgplan.AddRoute && op.Prefix.Bits() == 0 {
			t.Errorf("a default route was installed in the main table: %v", op)
		}
	}
}

// Nothing can be routed to a peer the interface does not have, and inventing one here would
// add a peer the control plane never sent.
func TestACarrierThatIsNotAPeerIsReported(t *testing.T) {
	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("branch-lan", carolKey, "192.168.10.0/24")},
		peer(bobKey, "100.90.0.2/32"))

	iface, unhonoured, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unhonoured) != 1 {
		t.Fatalf("unhonoured = %v, want the group named", unhonoured)
	}
	if len(iface.Peers) != 1 {
		t.Errorf("%d peers, want 1 — a peer was invented for the carrier", len(iface.Peers))
	}
}

// A prefix that does not parse must not be approximated into one that does: these reach the
// kernel's routing table.
func TestAnUnparseablePrefixIsReportedRatherThanGuessed(t *testing.T) {
	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("branch-lan", bobKey, "not-a-prefix")},
		peer(bobKey, "100.90.0.2/32"))

	_, unhonoured, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unhonoured) != 1 {
		t.Errorf("unhonoured = %v, want the group named", unhonoured)
	}
}

// The server orders the candidates and withdraws a group nobody can carry, so an empty list
// means the two ends disagree.
func TestAGroupWithNoCandidatesIsReported(t *testing.T) {
	assignment := &meshpv1.RouteGroupAssignment{
		RouteGroupId: "g", Name: "branch-lan", Prefixes: []string{"192.168.10.0/24"},
	}
	state := stateWithRoutes(1, []*meshpv1.RouteGroupAssignment{assignment},
		peer(bobKey, "100.90.0.2/32"))

	_, unhonoured, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unhonoured) != 1 {
		t.Errorf("unhonoured = %v", unhonoured)
	}
}

// The server orders candidates best first and the agent takes that order until it probes
// (ADR-0003).
func TestTheFirstCandidateCarriesIt(t *testing.T) {
	assignment := &meshpv1.RouteGroupAssignment{
		RouteGroupId: "g", Name: "branch-lan", Prefixes: []string{"192.168.10.0/24"},
		Candidates: []*meshpv1.RouteCandidate{
			{PeerPublicKey: bobKey, Priority: 1},
			{PeerPublicKey: carolKey, Priority: 5},
		},
	}
	state := stateWithRoutes(1, []*meshpv1.RouteGroupAssignment{assignment},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	iface, _, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(allowedIPsOf(iface, bobKey), "192.168.10.0/24") {
		t.Error("the preferred candidate is not carrying the prefix")
	}
	// And only one carries it: two peers claiming the same prefix is a configuration the
	// kernel resolves arbitrarily.
	if slicesContain(allowedIPsOf(iface, carolKey), "192.168.10.0/24") {
		t.Error("a second candidate is also carrying the prefix")
	}
}

// Withdrawing an assignment has to take the route with it, or the device keeps sending a
// prefix into a tunnel nobody is carrying it through.
func TestARemovedAssignmentRemovesItsRoute(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)

	with := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("branch-lan", bobKey, "192.168.10.0/24")},
		peer(bobKey, "100.90.0.2/32"))
	if _, err := r.Apply(context.Background(), with); err != nil {
		t.Fatal(err)
	}

	without := stateWithRoutes(2, nil, peer(bobKey, "100.90.0.2/32"))
	if _, err := r.Apply(context.Background(), without); err != nil {
		t.Fatal(err)
	}

	removed := false
	for _, op := range link.applied {
		if op.Kind == wgplan.RemoveRoute && op.Prefix.String() == "192.168.10.0/24" {
			removed = true
		}
	}
	if !removed {
		t.Errorf("the route survived its assignment: %v", link.applied)
	}
}

func slicesContain(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func stateAdvertising(version uint64, advertised *meshpv1.AdvertisedRoutes, peers ...*meshpv1.Peer) *peerset.Set {
	s := peerset.New()
	s.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: version, UpsertPeers: peers,
		Tunnel:     &meshpv1.TunnelConfig{Mtu: 1420},
		Advertised: advertised,
	})
	return s
}

func advertising(prefixes ...string) *meshpv1.AdvertisedRoutes {
	return &meshpv1.AdvertisedRoutes{Groups: []*meshpv1.AdvertisedRoutes_Group{
		{RouteGroupId: "g", Name: "branch", Prefixes: prefixes},
	}}
}

func TestAnAdvertiserIsMadeToForward(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)

	if _, err := r.Apply(context.Background(),
		stateAdvertising(1, advertising("192.168.10.0/24"), peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.forwarded) != 1 || len(filter.forwarded[0]) != 1 {
		t.Fatalf("forwarding was configured %d times: %+v", len(filter.forwarded), filter.forwarded)
	}
}

// A network that has never mentioned route groups says nothing about forwarding, and that
// must not be read as "stop".
func TestSilenceAboutForwardingIsLeftAlone(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)

	if _, err := r.Apply(context.Background(),
		stateAdvertising(1, nil, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.forwarded) != 0 {
		t.Errorf("silence was read as an instruction: %+v", filter.forwarded)
	}
}

// An explicit empty list means stop, and has to reach the kernel — otherwise a withdrawn
// gateway keeps forwarding for a network that no longer routes to it.
func TestBeingToldToCarryNothingStopsForwarding(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)

	if _, err := r.Apply(context.Background(),
		stateAdvertising(1, advertising("192.168.10.0/24"), peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(context.Background(),
		stateAdvertising(2, &meshpv1.AdvertisedRoutes{}, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.forwarded) != 2 {
		t.Fatalf("%d forwarding applies, want 2", len(filter.forwarded))
	}
	if len(filter.forwarded[1]) != 0 {
		t.Errorf("stopping did not reach the kernel: %+v", filter.forwarded[1])
	}
}

// Rebuilding the NAT table is not free for traffic already crossing it.
func TestUnchangedForwardingIsNotReapplied(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)
	state := stateAdvertising(1, advertising("192.168.10.0/24"), peer(bobKey, "100.90.0.2/32"))

	for range 3 {
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if len(filter.forwarded) != 1 {
		t.Errorf("forwarding was rebuilt %d times for an unchanged assignment", len(filter.forwarded))
	}
}

// A device meant to carry prefixes on a host that cannot forward must say so, or it looks
// like a working gateway that drops everything.
func TestAHostThatCannotForwardReportsIt(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)

	unapplied, err := r.Apply(context.Background(),
		stateAdvertising(1, advertising("192.168.10.0/24"), peer(bobKey, "100.90.0.2/32")))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(unapplied) != 1 || unapplied[0] != "forwarding" {
		t.Errorf("unapplied = %v, want [forwarding]", unapplied)
	}
}

// And a failure to load is reported rather than remembered as done.
func TestForwardingThatFailsIsRetried(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{fwdErr: errors.New("nft: no such table")}
	r := New(link, membership(), nil, filter, nil)
	state := stateAdvertising(1, advertising("192.168.10.0/24"), peer(bobKey, "100.90.0.2/32"))

	unapplied, err := r.Apply(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(unapplied) != 1 || unapplied[0] != "forwarding" {
		t.Fatalf("unapplied = %v", unapplied)
	}

	filter.fwdErr = nil
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if len(filter.forwarded) != 1 {
		t.Error("forwarding that failed to load was never retried")
	}
}

// Forwarding rules outliving the interface would leave the host a gateway for a network it
// has left (Invariant 20).
func TestTeardownStopsForwarding(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil)

	if _, err := r.Apply(context.Background(),
		stateAdvertising(1, advertising("192.168.10.0/24"), peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if err := r.Teardown(); err != nil {
		t.Fatal(err)
	}
	if len(filter.forwarded) != 2 || len(filter.forwarded[1]) != 0 {
		t.Errorf("teardown did not stop forwarding: %+v", filter.forwarded)
	}
}

// ---------------------------------------------------------------------------
// Local failover

func twoCandidates(name, first, second string, prefixes ...string) *meshpv1.RouteGroupAssignment {
	return &meshpv1.RouteGroupAssignment{
		RouteGroupId: "group-" + name, Name: name, Prefixes: prefixes,
		Candidates: []*meshpv1.RouteCandidate{
			{PeerPublicKey: first, AdvertiserId: "adv-first", Priority: 1},
			{PeerPublicKey: second, AdvertiserId: "adv-second", Priority: 2},
		},
		LocalFailover: &meshpv1.LocalFailoverPolicy{Enabled: true, FailThreshold: 1},
	}
}

// A device fails over from a gateway that has gone silent, without asking the control plane
// and without sending a packet the reconciler was not already going to send.
func TestADeviceFailsOverFromASilentAdvertiser(t *testing.T) {
	clk := clock.NewFake()
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil).WithChooser(routeprobe.New(clk))

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{twoCandidates("branch", bobKey, carolKey, "192.168.10.0/24")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	// Both peers handshaking: the first preference carries it.
	for i := range link.observed.Peers {
		link.observed.Peers[i].HasHandshake = true
		link.observed.Peers[i].HandshakeAge = time.Second
	}
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	for i := range link.observed.Peers {
		link.observed.Peers[i].HasHandshake = true
		link.observed.Peers[i].HandshakeAge = time.Second
	}
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	iface, _, err := Desired(membership(), state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = iface

	// Now the first advertiser goes silent. The reconciler already reads this.
	for i := range link.observed.Peers {
		if string(link.observed.Peers[i].PublicKey) == bobKey {
			link.observed.Peers[i].HandshakeAge = time.Hour
		}
	}
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	// The prefix is now carried by the second candidate.
	if !slicesContain(allowedIPsOf(currentInterface(t, r, state), carolKey), "192.168.10.0/24") {
		t.Error("the device did not move to the second advertiser")
	}
}

// currentInterface recomputes what the reconciler would configure now.
func currentInterface(t *testing.T, r *Reconciler, state *peerset.Set) wgplan.Interface {
	t.Helper()
	iface, _, err := Desired(r.membership, state, r.relay, r.chooser, r.log)
	if err != nil {
		t.Fatal(err)
	}
	return iface
}

// A peer that has just been configured has not had time to handshake, and counting that
// against the advertiser would fail a device over before it had ever tried.
func TestNoHandshakeYetIsNotAFailure(t *testing.T) {
	clk := clock.NewFake()
	link := newFakeLink()
	chooser := routeprobe.New(clk)
	r := New(link, membership(), nil, nil, nil).WithChooser(chooser)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{twoCandidates("branch", bobKey, carolKey, "192.168.10.0/24")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	// HasHandshake stays false throughout.
	for range 5 {
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if !slicesContain(allowedIPsOf(currentInterface(t, r, state), bobKey), "192.168.10.0/24") {
		t.Error("a device moved away from an advertiser that had not had time to handshake")
	}
}

// Without a chooser the server's order is taken verbatim, which is what every device did
// before local failover existed.
func TestWithoutAChooserTheServersOrderStands(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{twoCandidates("branch", bobKey, carolKey, "192.168.10.0/24")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))
	for i := range link.observed.Peers {
		link.observed.Peers[i].HasHandshake = true
		link.observed.Peers[i].HandshakeAge = time.Hour
	}

	for range 5 {
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if !slicesContain(allowedIPsOf(currentInterface(t, r, state), bobKey), "192.168.10.0/24") {
		t.Error("a build with no chooser moved off the server's first preference")
	}
}

// A handshake within the grace window is reachable; one well outside it is not.
func TestTheHandshakeGraceIsHonoured(t *testing.T) {
	observed := wgplan.Observed{Peers: []wgplan.Peer{
		{PublicKey: wgplan.Key(bobKey), HasHandshake: true, HandshakeAge: livenessGrace - time.Second},
		{PublicKey: wgplan.Key(carolKey), HasHandshake: true, HandshakeAge: livenessGrace + time.Minute},
	}}

	if result, ok := probeFromHandshake(observed, bobKey); !ok || !result.Reachable {
		t.Errorf("a fresh handshake was read as unreachable: %+v ok=%v", result, ok)
	}
	if result, ok := probeFromHandshake(observed, carolKey); !ok || result.Reachable {
		t.Errorf("a stale handshake was read as reachable: %+v ok=%v", result, ok)
	}
	// A peer that is not on the interface is a different problem, already reported.
	if _, ok := probeFromHandshake(observed, ourKey); ok {
		t.Error("a peer that is not configured produced a verdict")
	}
}

// The middle link of the failover loop: a reconcile pass has to leave the control plane
// something to read. The chooser deciding locally is only half the point — the other half is
// every other device being reordered away from the same dead gateway, and that needs the
// verdict to leave this one.
func TestAReconcilePassQueuesAVerdictForTheControlPlane(t *testing.T) {
	clk := clock.NewFake()
	link := newFakeLink()
	chooser := routeprobe.New(clk)
	r := New(link, membership(), nil, nil, nil).WithChooser(chooser)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{twoCandidates("branch", bobKey, carolKey, "192.168.10.0/24")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	// The first pass configures the peers; there is nothing on the interface to read yet.
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if got := chooser.Pending(); len(got) != 0 {
		t.Fatalf("queued %d verdicts about peers that were not on the interface yet", len(got))
	}

	// Both answering, so this pass is a healthy verdict about the first preference.
	for i := range link.observed.Peers {
		link.observed.Peers[i].HasHandshake = true
		link.observed.Peers[i].HandshakeAge = time.Second
	}
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	first := chooser.Pending()
	if len(first) != 1 {
		t.Fatalf("a reconcile pass queued %d verdicts, want one per group", len(first))
	}
	if !first[0].GetReachable() || first[0].GetAdvertiserId() != "adv-first" {
		t.Errorf("verdict = %+v, want a healthy one about the first advertiser", first[0])
	}

	// Now the advertiser in use goes silent.
	for i := range link.observed.Peers {
		if string(link.observed.Peers[i].PublicKey) == bobKey {
			link.observed.Peers[i].HandshakeAge = time.Hour
		}
	}
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	moved := chooser.Pending()
	if len(moved) != 1 {
		t.Fatalf("the move queued %d verdicts", len(moved))
	}
	if moved[0].GetSwitchedFromAdvertiserId() != "adv-first" || moved[0].GetAdvertiserId() != "adv-second" {
		t.Errorf("verdict = %+v, want the move reported with both ends", moved[0])
	}
	if moved[0].GetSwitchReason() == "" {
		t.Error("the move was queued with no reason for anyone reading an audit log later")
	}
}

// A device taken out of a group must not still be reporting on its advertisers: the server
// would fold that into the advertiser's health on behalf of a device no longer behind it.
//
// Run twice against the same setup, keeping the group and then withdrawing it, because
// "nothing was queued" is the answer a broken version of this test gives too.
func TestAVerdictIsNotQueuedForAGroupTheDeviceHasLeft(t *testing.T) {
	queuedAfterWithdrawing := func(t *testing.T, withdraw bool) int {
		t.Helper()
		link := newFakeLink()
		chooser := routeprobe.New(clock.NewFake())
		r := New(link, membership(), nil, nil, nil).WithChooser(chooser)

		assigned := []*meshpv1.RouteGroupAssignment{
			twoCandidates("branch", bobKey, carolKey, "192.168.10.0/24"),
		}
		peers := []*meshpv1.Peer{peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32")}

		// The first pass puts the peers on the interface; the second observes them and
		// queues a verdict that nothing has drained.
		if _, err := r.Apply(context.Background(), stateWithRoutes(1, assigned, peers...)); err != nil {
			t.Fatal(err)
		}
		for i := range link.observed.Peers {
			link.observed.Peers[i].HasHandshake = true
			link.observed.Peers[i].HandshakeAge = time.Second
		}
		if _, err := r.Apply(context.Background(), stateWithRoutes(2, assigned, peers...)); err != nil {
			t.Fatal(err)
		}

		next := assigned
		if withdraw {
			next = nil
		}
		if _, err := r.Apply(context.Background(), stateWithRoutes(3, next, peers...)); err != nil {
			t.Fatal(err)
		}
		return len(chooser.Pending())
	}

	if got := queuedAfterWithdrawing(t, false); got != 1 {
		t.Fatalf("a device still in the group queued %d verdicts, want one", got)
	}
	if got := queuedAfterWithdrawing(t, true); got != 0 {
		t.Errorf("queued %d verdicts about a group this device has left", got)
	}
}
