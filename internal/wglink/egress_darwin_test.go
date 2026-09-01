//go:build darwin

package wglink

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/route"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/meshpnet/meshp/internal/egress"
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

	// Both families, because a real membership has both and the halves are taken per family.
	// A v4-only fixture exercised half the claim.
	for _, addr := range []string{"100.90.77.1/32", "fd7c:6d65:7368:77::1/128"} {
		if err := l.Apply(iface, wgplan.Op{
			Kind: wgplan.AddAddress, Prefix: netip.MustParsePrefix(addr),
		}); err != nil {
			t.Fatalf("addressing the interface with %s: %v", addr, err)
		}
	}

	router := NewRouter()
	// Registered before the claim, so a failure inside it still gives the routing back.
	t.Cleanup(func() { _ = router.Release() })

	endpoint := netip.MustParseAddrPort("198.51.100.7:51820")

	// Claimed with what the reconciler passes, and this is the whole point of the change
	// that added it (#200). This test used to resolve the interface itself and hand Claim
	// the kernel's name, and to pass nil exclusions — so it did the translation the
	// production code was missing, and never offered the prefixes the production caller
	// offers. Five bugs lived in that gap and every one of them was found on a laptop:
	//
	//   - the tunnel's own address arriving in the carve-out, because LocalNetworks skipped
	//     by a name macOS does not have
	//   - route(8) refusing 255.255.255.255/32, which the carve-out always contains
	//   - halvesFor and `route -interface` given the label rather than the device
	//
	// A fixture that pre-processes its input the way the caller does not is a fixture that
	// tests something nobody runs.
	refuseIfAnotherTunnelIsUp(t, iface)
	excluded := carveoutAsTheReconcilerBuildsIt(t, iface)
	if err := router.Claim(iface, []netip.AddrPort{endpoint}, excluded); err != nil {
		t.Fatalf("claiming with the label and a real carve-out: %v", err)
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

	// The v6 halves too, since the interface carries a v6 address.
	for _, half := range egressHalves6 {
		if present, err := routeExists(half); err != nil {
			t.Fatal(err)
		} else if !present {
			t.Errorf("%s is not in the table after claiming an interface with a v6 address", half)
		}
	}

	// And the interface is still converged. wgplan withdraws anything on the interface it
	// did not plan, and the halves are on the interface — so before #202 this reconciled
	// forever, withdrawing them while the router reinstalled them, twice a second.
	observed, err := l.Observe(iface)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := wgplan.For(wgplan.Interface{
		Name:       iface,
		PrivateKey: genDarwinKey(t),
		MTU:        1380,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.90.77.1/32"),
			netip.MustParsePrefix("fd7c:6d65:7368:77::1/128"),
		},
	}, observed)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range plan.Ops {
		if op.Kind == wgplan.RemoveRoute {
			t.Errorf("with a full tunnel claimed, the interface plan would withdraw %s — "+
				"which the egress router installed and will reinstall, forever", op.Prefix)
		}
	}

	if err := router.Release(); err != nil {
		t.Fatalf("releasing: %v", err)
	}
	gone := append([]netip.Prefix{}, egressHalves...)
	gone = append(gone, egressHalves6...)
	gone = append(gone, pinned)
	for _, half := range gone {
		if present, err := routeExists(half); err != nil {
			t.Fatal(err)
		} else if present {
			t.Errorf("%s is still in the table after releasing", half)
		}
	}
}

// refuseIfAnotherTunnelIsUp skips when the host already has a meshp tunnel that is not this
// test's.
//
// Not tidiness, and not a workaround: it is #207, which this test found. The carve-out knows
// the addresses of the tunnel being claimed for and treats any other meshp tunnel as an
// ordinary local network, so it pins that tunnel's address to the LAN gateway and the kernel
// refuses. A developer with meshp running would see this test fail for a reason that is not
// the code under test, and would reasonably conclude the test was flaky.
//
// It skips rather than working around it, because working around it — telling LocalNetworks
// about the other tunnel here — would make the test pass while a device with two memberships
// still could not claim. CI has no second membership, so this runs there.
func refuseIfAnotherTunnelIsUp(t *testing.T, mine string) {
	t.Helper()
	entries, err := os.ReadDir(wireguardRunDir)
	if err != nil {
		return // no directory, no other tunnels
	}
	client, err := wgctrl.New()
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()

	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".name")
		if name == entry.Name() || name == mine {
			continue
		}
		// Asked of WireGuard rather than of the name file or the interface list, because
		// neither answers the question. A name file outlives the process that wrote it, and
		// the utun it names outlives it too — macOS hands the number back out, so a stale
		// mapping can point at a live interface belonging to something else entirely. A
		// device that answers wgctrl is a tunnel that is actually being served.
		if _, err := client.Device(name); err != nil {
			continue
		}
		t.Skipf("this host already has the meshp tunnel %q up, which the carve-out would "+
			"pin to the LAN gateway (#207); stop meshpd and run this again", name)
	}
}

// carveoutAsTheReconcilerBuildsIt is the prefix list a real claim is given.
//
// Built through egress.Compute rather than assembled by hand, so that what CI claims with is
// what a device claims with — including alwaysExcluded, which carries the limited broadcast
// that route(8) refuses, and LocalNetworks, which is where the tunnel's own address used to
// arrive from.
func carveoutAsTheReconcilerBuildsIt(t *testing.T, iface string) []netip.Prefix {
	t.Helper()

	device, err := realInterface(iface)
	if err != nil {
		t.Fatalf("resolving %s: %v", iface, err)
	}
	addrs, err := interfaceAddressesOf(device)
	if err != nil {
		t.Fatalf("reading %s's addresses: %v", device, err)
	}

	carve, err := egress.Compute(context.Background(), egress.Inputs{
		// Resolved from a literal, so the test needs no DNS and no control plane.
		ControlURL:    "https://198.51.100.1",
		LocalPrefixes: egress.LocalNetworks(addrs),
	}, nil)
	if err != nil {
		t.Fatalf("computing the carve-out: %v", err)
	}
	return carve.Prefixes
}

// interfaceAddressesOf is the tunnel's own addresses, which identify it to LocalNetworks.
func interfaceAddressesOf(device string) ([]netip.Prefix, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}
	return interfaceAddresses(iface)
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

// Whether a route already goes where a claim is asking for it to.
//
// This is the decision that says whether a correction happens at all, and getting it wrong
// in the "yes it does" direction is the bug this whole mechanism exists to fix: a stale
// carve-out that every pass believes is fine.
func TestWhetherARouteAlreadyGoesWhereAsked(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  routeEnd
		via  []string
		want bool
	}{
		{"the interface it was asked for", routeEnd{present: true, iface: "utun5"},
			[]string{"-interface", "utun5"}, true},
		{"a different interface", routeEnd{present: true, iface: "en0"},
			[]string{"-interface", "utun5"}, false},
		{"the gateway it was asked for",
			routeEnd{present: true, gateway: netip.MustParseAddr("192.168.1.1")},
			[]string{"-gateway", "192.168.1.1"}, true},
		{"the gateway of a network this laptop has left",
			routeEnd{present: true, gateway: netip.MustParseAddr("192.168.1.1")},
			[]string{"-gateway", "10.0.0.1"}, false},

		{"no route at all", routeEnd{}, []string{"-interface", "utun5"}, false},
		// Not a state routeTarget can produce, and asserted anyway: goesTo answers for a
		// struct rather than for the routing table, and "absent" has to beat whatever else
		// the struct is carrying or a caller could be told a route it has not got is fine.
		{"absent, and carrying a target anyway",
			routeEnd{iface: "utun5", gateway: netip.MustParseAddr("192.168.1.1")},
			[]string{"-interface", "utun5"}, false},
		{"an interface route asked for by gateway",
			routeEnd{present: true, iface: "utun5"}, []string{"-gateway", "192.168.1.1"}, false},
		{"a gateway route asked for by interface",
			routeEnd{present: true, gateway: netip.MustParseAddr("192.168.1.1")},
			[]string{"-interface", "utun5"}, false},
		{"an interface that has gone away, so it has no name",
			routeEnd{present: true}, []string{"-interface", "utun5"}, false},
		{"something that is not a way of naming a route",
			routeEnd{present: true, iface: "utun5"}, []string{"-blackhole"}, false},
	} {
		if got := tc.end.goesTo(tc.via); got != tc.want {
			t.Errorf("%s: goesTo = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The carve-out contains one prefix macOS will not route, and Claim must not abort on it.
//
// route(8) rejects 255.255.255.255/32 with "bad address", and Claim gives up on the first
// prefix it cannot install — so a device in a network with an egress group never claimed the
// default route at all, and with fail-closed enforced had no internet.
//
// Asked of directRoutes, which is the list Claim installs, rather than of the predicate.
// The first version of this fix added the predicate and never called it: the behaviour was
// unchanged on the machine that found the bug while this test passed, because it was asking
// the wrong question. ADR-0018 is about mechanisms nothing reaches, and a test that calls the
// mechanism directly cannot notice that nothing else does.
func TestClaimDoesNotTryToRouteTheLimitedBroadcast(t *testing.T) {
	carveOut := []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("192.168.0.0/24"),
		// A single host an operator asked to keep direct. Here because without a /32 that
		// must be kept, "skip the broadcast" and "skip every host route" are the same
		// answer, and a rule that dropped every /32 would pass.
		netip.MustParsePrefix("10.7.7.7/32"),
		netip.MustParsePrefix("fe80::/10"),
	}
	endpoints := []netip.AddrPort{netip.MustParseAddrPort("168.144.85.34:3478")}

	got := directRoutes(endpoints, carveOut)

	for _, p := range got {
		if p == netip.MustParsePrefix("255.255.255.255/32") {
			t.Error("Claim would try to route 255.255.255.255/32; route(8) refuses it and " +
				"the whole claim fails, leaving the device refusing egress with nothing " +
				"carrying it")
		}
	}

	// Everything else that keeps the machine's own network working while a full tunnel is
	// claimed still gets a route. Skipping any of these would be a hole in the thing the
	// carve-out exists to protect.
	for _, want := range []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("192.168.0.0/24"),
		netip.MustParsePrefix("10.7.7.7/32"),
		netip.MustParsePrefix("168.144.85.34/32"),
	} {
		if !slices.Contains(got, want) {
			t.Errorf("%s must be kept off the tunnel and Claim would not route it", want)
		}
	}

	// IPv6 is left alone here, which is a separate deliberate limitation of this platform's
	// claim rather than something this change touches.
	for _, p := range got {
		if p.Addr().Is6() {
			t.Errorf("an IPv6 prefix %s reached the v4 gateway loop", p)
		}
	}
}

// meshp's name for a tunnel is not the kernel's, and everything here talks to the kernel.
//
// The third instance of one root cause (#200): meshp0 is a real interface on Linux and a
// label on macOS, where the kernel makes a utunN. LocalNetworks was fixed by identifying the
// tunnel by address; halvesFor and the route commands genuinely need the device's name, so
// Claim resolves it.
func TestTheKernelsNameIsUsedNotMeshpsLabel(t *testing.T) {
	// A name the kernel really has resolves to itself, which is both the Linux case and what
	// lets this be checked without a tunnel.
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no interfaces to check against")
	}
	real := ifaces[0].Name
	got, err := realInterface(real)
	if err != nil {
		t.Fatalf("realInterface(%q): %v", real, err)
	}
	if got != real {
		t.Errorf("realInterface(%q) = %q, want it unchanged", real, got)
	}

	// A label with no interface and no name file is an error rather than a name passed
	// through — passing it through is what produced "no such network interface" from three
	// different callers.
	if got, err := realInterface("meshp-nonexistent-" + t.Name()); err == nil {
		t.Errorf("a label with no interface behind it resolved to %q instead of failing", got)
	}
}

// The name file is what survives a restart, and is how a label is translated.
func TestALabelResolvesThroughItsNameFile(t *testing.T) {
	if _, err := os.Stat(wireguardRunDir); err != nil {
		t.Skip("no", wireguardRunDir, "on this host")
	}
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no interfaces to point a name file at")
	}
	target := ifaces[0].Name

	label := "meshptest-" + strings.ReplaceAll(t.Name(), "/", "-")
	path := filepath.Join(wireguardRunDir, label+".name")
	if err := os.WriteFile(path, []byte(target+"\n"), 0o600); err != nil {
		t.Skip("cannot write a name file here:", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	got, err := realInterface(label)
	if err != nil {
		t.Fatalf("realInterface(%q): %v", label, err)
	}
	if got != target {
		t.Errorf("realInterface(%q) = %q, want %q from the name file", label, got, target)
	}
}

// The route reader consults the record, which is the half a unit test of the rule cannot see.
//
// #202 is only fixed if interfaceRoutes actually asks. An earlier fix in this file added a
// predicate and never called it, the tests passed because they asked the predicate, and the
// behaviour on the machine was unchanged — so this exercises the reader against a record on
// disk rather than the rule in isolation.
func TestTheRouteReaderExcludesWhatTheEgressRouterRecorded(t *testing.T) {
	index, routes := anInterfaceWithRoutes(t)
	victim := routes[0]

	dir := t.TempDir()
	previous := egressRecordPath
	egressRecordPath = filepath.Join(dir, "egress-routes")
	t.Cleanup(func() { egressRecordPath = previous })

	recordClaim([]netip.Prefix{victim})

	after, err := interfaceRoutes(index)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(after, victim) {
		t.Errorf("%s is recorded as the egress router's and interfaceRoutes still reports it; "+
			"the planner will withdraw it every pass", victim)
	}

	// And only that one. Excluding more would hide peer routes from the planner.
	for _, keep := range routes[1:] {
		if !slices.Contains(after, keep) {
			t.Errorf("%s is the interface plan's and was excluded", keep)
		}
	}
}

// anInterfaceWithRoutes finds an interface this host has that carries more than one route,
// so the test above can tell "excluded the recorded one" from "excluded everything".
func anInterfaceWithRoutes(t *testing.T) (int, []netip.Prefix) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot read this host's interfaces:", err)
	}
	for _, iface := range ifaces {
		routes, err := interfaceRoutes(iface.Index)
		if err == nil && len(routes) > 1 {
			return iface.Index, routes
		}
	}
	t.Skip("no interface on this host carries more than one route")
	return 0, nil
}
