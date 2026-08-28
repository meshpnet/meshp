//go:build darwin

package wglink

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/route"

	"github.com/meshpnet/meshp/internal/wgplan"
)

func opCreate() wgplan.Op {
	return wgplan.Op{Kind: wgplan.CreateDevice, Device: wgplan.Device{MTU: 1380}}
}

func opDestroy() wgplan.Op { return wgplan.Op{Kind: wgplan.DestroyDevice} }

// The gateway is read from the kernel, not remembered.
//
// A laptop that changed networks since the last pass has a different one, and pinning the
// tunnel's own endpoints to the old gateway would send them nowhere — which on this platform
// means the tunnel stops carrying anything and the machine is inside it.
func TestTheDefaultGatewayIsReadFromTheRoutingTable(t *testing.T) {
	gateway, err := defaultGateway()
	if err != nil {
		t.Skipf("this machine has no IPv4 default route: %v", err)
	}
	if !gateway.IsValid() || !gateway.Is4() {
		t.Errorf("gateway = %v, want a v4 address", gateway)
	}
	if gateway.IsUnspecified() {
		t.Error("the gateway is 0.0.0.0, which is the destination rather than the gateway — " +
			"the routing message's fields are being read in the wrong order")
	}
}

// Nothing is claimed on a machine meshp is not running on.
func TestEgressIsNotHeldWhenNothingClaimedIt(t *testing.T) {
	held, err := EgressHeld()
	if err != nil {
		t.Fatalf("EgressHeld: %v", err)
	}
	if held {
		t.Skip("something has already claimed a default route on this machine; " +
			"this test cannot say whether it was meshp")
	}
}

// Adding a route that is already there is success, because the reconciler adds them every
// pass. route(8) reports it as "File exists" and exits non-zero, which is not a failure of
// anything.
func TestAddingARouteTwiceIsSuccess(t *testing.T) {
	requireRoot(t)

	// TEST-NET-1, which is reserved for documentation and reaches nothing. Chosen over any
	// of the halves deliberately: this test is about the idempotence of one operation, and
	// it should not need the machine's default route to prove it.
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	t.Cleanup(func() { _ = deleteRoute(prefix) })

	for range 2 {
		if err := addRoute(prefix, "-interface", "lo0"); err != nil {
			t.Fatalf("adding %s: %v", prefix, err)
		}
	}

	present, err := routeExists(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Error("the route was added twice and is not in the table")
	}
}

// Removing a route that is not there is success, for the reason teardown always runs: a
// membership going away asks for a release whether or not a claim was ever made.
func TestDeletingARouteThatIsNotThereIsSuccess(t *testing.T) {
	requireRoot(t)

	if err := deleteRoute(netip.MustParsePrefix("198.51.100.0/24")); err != nil {
		t.Errorf("deleting a route that was never added: %v", err)
	}
}

// The whole claim, and back again.
//
// This one deliberately takes the machine's traffic. Between Claim and Release every packet
// with no more specific route goes into a utun with no peers, which is a blackhole — so the
// window is as short as it can be made, nothing does network I/O inside it, and the release
// is registered before the claim so that a failure between them still puts the routes back.
//
// The risk is real and bounded: on a CI runner the worst case is a job that fails loudly on
// a machine that is thrown away afterwards, which is a better trade than never exercising
// the one function this file exists for. Do not add anything to this test that talks to the
// network.
func TestClaimingAndReleasingTheDefaultRoute(t *testing.T) {
	requireRoot(t)

	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const iface = "meshptest-egress"
	if err := l.Apply(iface, opCreate()); err != nil {
		t.Fatalf("creating the interface: %v", err)
	}
	t.Cleanup(func() { _ = l.Apply(iface, opDestroy()) })

	// Addressed, because a real claim is only ever made on a tunnel that has one — and
	// because Claim now decides which address families to take from what the interface
	// actually carries. A bare utun was not a realistic fixture and hid that.
	if err := l.Apply(iface, wgplan.Op{
		Kind: wgplan.AddAddress, Prefix: netip.MustParsePrefix("100.90.77.1/32"),
	}); err != nil {
		t.Fatalf("addressing the interface: %v", err)
	}

	real, ok, err := l.(*darwinLink).resolve(iface)
	if err != nil || !ok {
		t.Fatalf("resolving the interface: %v", err)
	}

	router := NewRouter()
	// Registered before the claim, so a failure inside it still gives the routing back.
	t.Cleanup(func() { _ = router.Release() })

	endpoint := netip.MustParseAddrPort("198.51.100.7:51820")
	if err := router.Claim(real, []netip.AddrPort{endpoint}, nil); err != nil {
		t.Fatalf("claiming: %v", err)
	}

	// Read from the kernel, not from the Router's own memory: what matters is what the
	// machine will do with a packet, not what this process believes it asked for.
	for _, half := range egressHalves {
		present, err := routeExists(half)
		if err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Errorf("%s is not in the table after claiming", half)
		}
	}
	pinned := netip.PrefixFrom(endpoint.Addr(), 32)
	if present, err := routeExists(pinned); err != nil {
		t.Fatal(err)
	} else if !present {
		t.Error("the tunnel's own endpoint was not routed around the tunnel, so the outer " +
			"packets would go into the tunnel they carry")
	}

	held, err := EgressHeld()
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Error("EgressHeld says nothing is claimed while a claim is in place; " +
			"meshp doctor would tell somebody their machine is fine")
	}

	if err := router.Release(); err != nil {
		t.Fatalf("releasing: %v", err)
	}
	for _, half := range append(append([]netip.Prefix{}, egressHalves...), pinned) {
		if present, err := routeExists(half); err != nil {
			t.Fatal(err)
		} else if present {
			t.Errorf("%s is still in the table after releasing", half)
		}
	}
}

// A netmask is read correctly whatever its length.
//
// Written after the round-trip test failed with "0.0.0.0/1 is not in the table after
// claiming" — the routes were there and the reader could not see them. The contiguity check
// rejected every mask whose length was not a multiple of eight, so a /24 was found and a /1
// and a /12 were not.
//
// That is not only this file's problem: interfaceRoutes uses the same parsing for Observe,
// so a route with a length like /12 was invisible to the reconciler and could never be
// withdrawn. Pinned here because the failure looks like "the route was not added" and is
// nothing of the sort.
func TestNetmasksOfEveryLengthAreRead(t *testing.T) {
	for _, tc := range []struct {
		mask [4]byte
		want int
	}{
		{[4]byte{0x00, 0, 0, 0}, 0},
		{[4]byte{0x80, 0, 0, 0}, 1}, // the halves this file claims with
		{[4]byte{0xff, 0xf0, 0, 0}, 12},
		{[4]byte{0xff, 0xff, 0xff, 0}, 24},
		{[4]byte{0xff, 0xff, 0xff, 0xff}, 32},
	} {
		addr := &route.Inet4Addr{IP: tc.mask}
		if got := maskBits(addr, 32); got != tc.want {
			t.Errorf("maskBits(%v) = %d, want %d", tc.mask, got, tc.want)
		}
	}

	// And a mask that is not contiguous is refused rather than rounded into a length it
	// does not have.
	if got := maskBits(&route.Inet4Addr{IP: [4]byte{0xff, 0x0f, 0, 0}}, 32); got != -1 {
		t.Errorf("a non-contiguous mask read as /%d", got)
	}
}

// A claim has to be undoable by a process that did not make it.
//
// ADR-0011 keeps a full tunnel's routing in place across a crash on purpose, and Invariant 20
// says the agent must never leave a host without networking. What joins those two is
// meshpd finding the claim again on start-up and taking it off — and until this was written
// down, macOS could not: Release removed what its own Router remembered, a restarted daemon
// remembered nothing, and reclaimEgressLock logged that it had found a stale claim, deleted
// nothing, and reported success.
//
// Linux has never had this problem because it finds its claim by the firewall mark, which is
// a constant the kernel holds. This is that, for a platform with no marks.
func TestAClaimIsWrittenDownSoAnotherProcessCanUndoIt(t *testing.T) {
	egressRecordPath = filepath.Join(t.TempDir(), "egress-routes")

	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("0.0.0.0/1"),
	}
	recordClaim(want)

	got := recordedClaim()
	if len(got) != len(want) {
		t.Fatalf("wrote %d routes and read back %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("route %d is %s, want %s", i, got[i], want[i])
		}
	}

	forgetClaim()
	if left := recordedClaim(); len(left) != 0 {
		t.Errorf("the record survived the release it describes: %v", left)
	}
}

// A record that has been damaged still names the routes it can.
//
// Refusing the whole file over one bad line would leave a machine holding every route in it,
// which is the outcome the record exists to prevent.
func TestADamagedRecordStillNamesWhatItCan(t *testing.T) {
	egressRecordPath = filepath.Join(t.TempDir(), "egress-routes")
	if err := os.WriteFile(egressRecordPath,
		[]byte("0.0.0.0/1\nnot a prefix\n\n128.0.0.0/1\n"), 0o600); err != nil {
		t.Fatalf("writing a damaged record: %v", err)
	}

	got := recordedClaim()
	if len(got) != 2 {
		t.Fatalf("read %d routes out of a damaged record, want 2: %v", len(got), got)
	}
}

// And the whole of it against the routing table: one Router claims, a different one releases.
//
// The second Router stands in for a restarted daemon. It shares nothing with the first but
// the record on disk, which is exactly what reclaimEgressLock has to work from.
func TestARestartedDaemonCanReleaseAClaimItDidNotMake(t *testing.T) {
	requireRoot(t)
	egressRecordPath = filepath.Join(t.TempDir(), "egress-routes")

	// TEST-NET-1 rather than the halves: this is about whether the record is enough to find
	// a route again, and it should not need to take the machine's traffic to prove it.
	pinned := netip.MustParsePrefix("192.0.2.0/24")
	t.Cleanup(func() { _ = deleteRoute(pinned) })

	if err := addRoute(pinned, "-interface", "lo0"); err != nil {
		t.Fatalf("adding %s: %v", pinned, err)
	}
	recordClaim([]netip.Prefix{pinned})

	// A Router that has claimed nothing, which is what a daemon has after a kill -9.
	if err := (&Router{}).Release(); err != nil {
		t.Fatalf("releasing a claim this process did not make: %v", err)
	}

	present, err := routeExists(pinned)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("a restarted daemon could not take off the route a previous one left; " +
			"this machine keeps sending traffic into a tunnel that is gone")
	}
	if left := recordedClaim(); len(left) != 0 {
		t.Errorf("the record outlived the routes it named: %v", left)
	}
}

// Which routes a release takes off, including the case where it has to guess.
//
// The guess is the interesting one and the reason this is a function rather than three lines
// inside releaseLocked: getting it wrong in one direction leaves a machine sending every
// packet into a tunnel that is gone, and in the other deletes routes meshp never made.
func TestWhatAReleaseTakesOff(t *testing.T) {
	halves := netip.MustParsePrefix("0.0.0.0/1")
	endpoint := netip.MustParsePrefix("192.0.2.7/32")
	excluded := netip.MustParsePrefix("192.168.1.0/24")

	t.Run("the ordinary release takes off what this process installed", func(t *testing.T) {
		got := releaseTargets([]netip.Prefix{halves, endpoint}, nil)
		if len(got) != 2 || got[0] != halves || got[1] != endpoint {
			t.Errorf("got %v", got)
		}
	})

	t.Run("a restarted daemon takes off what was written down", func(t *testing.T) {
		got := releaseTargets(nil, []netip.Prefix{halves, endpoint})
		if len(got) != 2 {
			t.Fatalf("a release with nothing but a record took off %d routes: %v", len(got), got)
		}
		if !slices.Contains(got, endpoint) {
			t.Error("the host route pinning an endpoint to the old gateway was left behind")
		}
	})

	t.Run("what is remembered and what is recorded are not counted twice", func(t *testing.T) {
		got := releaseTargets([]netip.Prefix{halves, endpoint}, []netip.Prefix{halves, excluded})
		if len(got) != 3 {
			t.Errorf("got %d routes, want 3 distinct: %v", len(got), got)
		}
	})

	t.Run("with nothing to go on it takes off the halves", func(t *testing.T) {
		got := releaseTargets(nil, nil)
		if len(got) == 0 {
			t.Fatal("a release with no record took nothing off, which is the bug this " +
				"whole mechanism exists to fix: the machine goes on sending every packet " +
				"into a tunnel that is gone")
		}
		for _, half := range append(append([]netip.Prefix{}, egressHalves...), egressHalves6...) {
			if !slices.Contains(got, half) {
				t.Errorf("%s was not taken off, so half the address space still points at "+
					"a tunnel that is gone", half)
			}
		}
		if slices.Contains(got, endpoint) {
			t.Error("a release with nothing to go on invented a host route to delete")
		}
	})
}

// routeVia reports what the routing table says about a destination — the value of one of
// route(8)'s "key: value" lines, such as `interface` or `gateway`.
func routeVia(t *testing.T, destination, key string) string {
	t.Helper()
	out, err := exec.Command("/sbin/route", "-n", "get", destination).CombinedOutput()
	if err != nil {
		t.Fatalf("route -n get %s: %v: %s", destination, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if found && name == key {
			return strings.TrimSpace(value)
		}
	}
	t.Fatalf("route -n get %s printed no %s:\n%s", destination, key, out)
	return ""
}

// A route that is already there but points somewhere else is corrected.
//
// This is the one that made a macOS laptop unable to survive changing networks. The carve-out
// keeping the relay and the control plane off the tunnel is a set of host routes pinned to
// whatever gateway was current when the claim was made, and every reconcile re-makes the
// claim against the gateway the machine is using *now* — which was the whole design. But
// route(8) reports an existing destination as "File exists" without touching it, and addRoute
// read that as success. So the correcting pass corrected nothing, once a minute, forever.
//
// With fail-closed egress in force since ADR-0026, the consequence is not a slow tunnel. It
// is a laptop that moved to another network and has no way out of it at all.
func TestARouteThatPointsSomewhereElseIsCorrected(t *testing.T) {
	requireRoot(t)

	elsewhere := routeVia(t, "default", "interface")
	if elsewhere == "lo0" {
		t.Skip("this machine's default route is on loopback, so there is no second " +
			"interface to be wrong about")
	}

	// TEST-NET-1: reserved, routed nowhere, and nothing on this machine wants it.
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	t.Cleanup(func() { _ = deleteRoute(prefix) })

	if err := addRoute(prefix, "-interface", "lo0"); err != nil {
		t.Fatalf("adding %s: %v", prefix, err)
	}
	if got := routeVia(t, "192.0.2.1", "interface"); got != "lo0" {
		t.Fatalf("the route was added and points at %q, so this test is not measuring what "+
			"it thinks", got)
	}

	// The same destination, somewhere else. This is what a laptop changing networks asks
	// for on the next reconcile.
	if err := addRoute(prefix, "-interface", elsewhere); err != nil {
		t.Fatalf("re-pointing %s: %v", prefix, err)
	}
	if got := routeVia(t, "192.0.2.1", "interface"); got != elsewhere {
		t.Errorf("the route still points at %q rather than %q.\n"+
			"A carve-out pinned to a gateway the machine has left is never corrected, so a "+
			"laptop that changes networks while failing closed has no way out of the new one.",
			got, elsewhere)
	}
}

// And the same for a route named by gateway rather than by interface, which is the form the
// carve-out actually uses.
func TestAHostRoutePinnedToTheWrongGatewayIsRepinned(t *testing.T) {
	requireRoot(t)

	gateway, err := defaultGateway()
	if err != nil {
		t.Skipf("this machine has no IPv4 default route: %v", err)
	}

	prefix := netip.MustParsePrefix("192.0.2.9/32")
	t.Cleanup(func() { _ = deleteRoute(prefix) })

	// Loopback stands in for the gateway of a network the laptop has left: on-link, so the
	// route can be installed, and not where anything should be sent.
	if err := addRoute(prefix, "-gateway", "127.0.0.1"); err != nil {
		t.Fatalf("pinning %s to loopback: %v", prefix, err)
	}
	if err := addRoute(prefix, "-gateway", gateway.String()); err != nil {
		t.Fatalf("re-pinning %s to %s: %v", prefix, gateway, err)
	}

	if got := routeVia(t, "192.0.2.9", "gateway"); got != gateway.String() {
		t.Errorf("the host route still goes via %q rather than %q; the endpoint it keeps off "+
			"the tunnel is unreachable and the tunnel cannot come back up", got, gateway)
	}
}
