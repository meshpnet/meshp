//go:build windows

package wglink

import (
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// Which routes a release takes off, including the case where it has to guess.
//
// The guess is why this is a function: a release reached with nothing remembered and nothing
// recorded is one whose caller checked EgressHeld first, so something is holding the routing.
// Getting it wrong in one direction leaves a machine sending every packet into a tunnel that
// is gone; in the other it deletes routes meshp never made.
func TestWhatAReleaseTakesOff(t *testing.T) {
	half := netip.MustParsePrefix("0.0.0.0/1")
	endpoint := netip.MustParsePrefix("192.0.2.7/32")

	if got := releaseTargets([]netip.Prefix{half, endpoint}, nil); len(got) != 2 {
		t.Errorf("an ordinary release took off %d routes, want 2: %v", len(got), got)
	}
	if got := releaseTargets(nil, []netip.Prefix{half, endpoint}); !slices.Contains(got, endpoint) {
		t.Error("a restarted daemon left behind the host route pinning an endpoint to a gateway")
	}
	if got := releaseTargets([]netip.Prefix{half}, []netip.Prefix{half}); len(got) != 1 {
		t.Errorf("the same route was counted twice: %v", got)
	}

	guessed := releaseTargets(nil, nil)
	for _, half := range append(append([]netip.Prefix{}, egressHalves...), egressHalves6...) {
		if !slices.Contains(guessed, half) {
			t.Errorf("%s was not taken off, so half the address space still points at a "+
				"tunnel that is gone", half)
		}
	}
	if slices.Contains(guessed, endpoint) {
		t.Error("a release with nothing to go on invented a host route to delete")
	}
}

// A claim is written down so that a process which did not make it can undo it.
//
// ADR-0011 keeps the routing in place across a crash on purpose, and Invariant 20 says the
// agent must never leave a host without networking. What joins them is meshpd finding the
// claim again at start-up, and on a platform with no firewall mark the only record of which
// host routes are meshp's is the one meshp keeps.
func TestAClaimIsWrittenDownSoAnotherProcessCanUndoIt(t *testing.T) {
	egressRecordPath = filepath.Join(t.TempDir(), "egress-routes")

	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("0.0.0.0/1")}
	recordClaim(want)

	got := recordedClaim()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("wrote %v and read back %v", want, got)
	}
	forgetClaim()
	if left := recordedClaim(); len(left) != 0 {
		t.Errorf("the record survived the release it describes: %v", left)
	}
}

// Nothing is holding a default route on a machine where nothing claimed one.
func TestEgressIsNotHeldWhenNothingClaimedIt(t *testing.T) {
	held, err := EgressHeld()
	if err != nil {
		t.Fatalf("EgressHeld: %v", err)
	}
	if held {
		t.Skip("something has already claimed a default route on this machine; " +
			"this test cannot tell that from a fault")
	}
}

// The gateway is read from the routing table, not remembered.
//
// A laptop that changed networks has a different one, and pinning the tunnel's own endpoints
// to the old one would send them nowhere — which on this platform means the tunnel stops
// carrying anything and the machine is inside it.
func TestTheDefaultGatewayIsReadFromTheRoutingTable(t *testing.T) {
	luid, gateway, err := defaultGateway(0)
	if err != nil {
		t.Skipf("this machine has no IPv4 default route: %v", err)
	}
	if !gateway.IsValid() || gateway.IsUnspecified() {
		t.Errorf("the default gateway came back as %v", gateway)
	}
	if luid == 0 {
		t.Error("the default gateway is on no interface")
	}
}

// A route that is already there but points somewhere else is corrected.
//
// The failure this guards against cost macOS a release: route(8) reported an existing
// destination as success without touching it, so a carve-out pinned to the gateway of a
// network the laptop had left was never corrected, once a minute, forever (#171). The API
// here is different and the trap is the same shape.
func TestARouteThatPointsSomewhereElseIsCorrected(t *testing.T) {
	requireAdmin(t)

	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const name = "meshptestrt0"
	t.Cleanup(func() { _ = l.Apply(name, wgplan.Op{Kind: wgplan.DestroyDevice}) })
	if err := l.Apply(name, wgplan.Op{Kind: wgplan.CreateDevice,
		Device: wgplan.Device{MTU: 1380}}); err != nil {
		t.Fatalf("creating an adapter: %v", err)
	}
	tunnelLUID, err := luidFor(name)
	if err != nil {
		t.Fatalf("finding the adapter: %v", err)
	}

	gatewayLUID, gateway, err := defaultGateway(tunnelLUID)
	if err != nil {
		t.Skipf("this machine has no IPv4 default route: %v", err)
	}

	// TEST-NET-1: reserved, routed nowhere, and nothing on this machine wants it. This test
	// deliberately does not touch the halves — what is under test is whether a route is
	// corrected, and proving that does not need the machine's own traffic.
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	t.Cleanup(func() { _ = deleteRoute(prefix) })

	if err := addRoute(tunnelLUID, prefix, netip.IPv4Unspecified()); err != nil {
		t.Fatalf("routing %s at the tunnel: %v", prefix, err)
	}
	if err := addRoute(gatewayLUID, prefix, gateway); err != nil {
		t.Fatalf("re-pointing %s at the gateway: %v", prefix, err)
	}

	if err := addRoute(gatewayLUID, prefix, gateway); err != nil {
		t.Errorf("asking for a route that is already right was an error: %v", err)
	}
}

// The whole claim, and back again.
//
// This one deliberately takes the machine's traffic. Between Claim and Release every packet
// with no more specific route goes into an adapter with no peers, which is a blackhole — so
// the window is as short as it can be made, nothing does network I/O inside it, and the
// release is registered before the claim so a failure between them still puts the routes
// back. Do not add anything to this test that talks to the network.
func TestClaimingAndReleasingTheDefaultRoute(t *testing.T) {
	requireAdmin(t)
	egressRecordPath = filepath.Join(t.TempDir(), "egress-routes")

	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const name = "meshptestrt1"
	t.Cleanup(func() { _ = l.Apply(name, wgplan.Op{Kind: wgplan.DestroyDevice}) })
	if err := l.Apply(name, wgplan.Op{Kind: wgplan.CreateDevice,
		Device: wgplan.Device{MTU: 1380}}); err != nil {
		t.Fatalf("creating an adapter: %v", err)
	}
	if err := l.Apply(name, wgplan.Op{Kind: wgplan.AddAddress,
		Prefix: netip.MustParsePrefix("100.90.90.1/32")}); err != nil {
		t.Fatalf("addressing the adapter: %v", err)
	}

	router := NewRouter()
	t.Cleanup(func() { _ = router.Release() })

	endpoint := netip.MustParseAddrPort("198.51.100.9:51820")
	if err := router.Claim(name, []netip.AddrPort{endpoint}, nil); err != nil {
		t.Fatalf("claiming: %v", err)
	}

	held, err := EgressHeld()
	if err != nil {
		t.Fatalf("EgressHeld: %v", err)
	}
	if !held {
		t.Error("a default route was claimed and nothing reports one held")
	}
	if recorded := recordedClaim(); len(recorded) == 0 {
		t.Error("the claim was not written down, so a restarted daemon could not undo it")
	}

	if err := router.Release(); err != nil {
		t.Fatalf("releasing: %v", err)
	}
	held, err = EgressHeld()
	if err != nil {
		t.Fatalf("EgressHeld after release: %v", err)
	}
	if held {
		t.Error("the routing was released and this machine still sends everything to a tunnel")
	}
	if left := recordedClaim(); len(left) != 0 {
		t.Errorf("the record outlived the routes it named: %v", left)
	}
}

// The commands printed for somebody at a console have to be typeable as they stand.
func TestTheUndoCommandsAreTypeable(t *testing.T) {
	commands := egressUndo()
	if len(commands) == 0 {
		t.Fatal("this platform can claim a default route and offers no way to undo one by hand")
	}
	for _, command := range commands {
		if len(command) == 0 || command[:5] != "route" {
			t.Errorf("%q does not name a program every Windows has", command)
		}
	}
}
