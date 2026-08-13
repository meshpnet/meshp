package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/peerset"
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
		f.observed.Peers = append(f.observed.Peers, op.Peer)
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
	r := New(link, membership(), nil)

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
	r := New(link, membership(), nil)
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

	r := New(link, membership(), nil)
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

	r := New(link, membership(), nil)
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
			r := New(link, membership(), nil)
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
	r := New(link, membership(), nil)
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

	iface, err := Desired(m, stateWith(1))
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
		if _, err := Desired(m, stateWith(1)); err == nil {
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

	iface, err := Desired(m, stateWith(1))
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
		if _, err := Desired(m, stateWith(1)); err == nil {
			t.Error("a membership with no private key was accepted")
		}
	})
	t.Run("no addresses", func(t *testing.T) {
		m := membership()
		m.AddressV4, m.AddressV6 = "", ""
		if _, err := Desired(m, stateWith(1)); err == nil {
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

	iface, err := Desired(membership(), state)
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

	iface, err := Desired(membership(), state)
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
	iface, err := Desired(membership(), stateWith(1, peer(bobKey, "100.90.0.2/32")))
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

	iface, err := Desired(membership(), stateWith(1, p))
	if err != nil {
		t.Fatal(err)
	}
	if got := iface.Peers[0].Endpoint; got != "203.0.113.2:51820" {
		t.Errorf("endpoint is %q, want the first one offered", got)
	}
}

// Any port, because a device in several networks needs an interface for each (ADR-0004) and
// they cannot all ask for the same one.
func TestNoParticularPortIsRequested(t *testing.T) {
	iface, err := Desired(membership(), stateWith(1))
	if err != nil {
		t.Fatal(err)
	}
	if iface.ListenPort != 0 {
		t.Errorf("listen port is %d, want 0 meaning any", iface.ListenPort)
	}
}

// The key is carried through untouched. wgplan does not parse keys, so a translation that
// mangled one would only fail at the kernel, on a real host, with a confusing message.
func TestKeysArePassedThroughUnchanged(t *testing.T) {
	iface, err := Desired(membership(), stateWith(1, peer(bobKey, "100.90.0.2/32")))
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
	r := New(link, membership(), nil)
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
