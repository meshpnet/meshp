//go:build darwin

package wglink

import (
	"net/netip"
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
