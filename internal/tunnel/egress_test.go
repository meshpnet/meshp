package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/egress"
	"github.com/meshpnet/meshp/internal/peerset"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func egressState(version uint64) *peerset.Set {
	return stateWithRoutes(version,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("exit", bobKey, "0.0.0.0/0", "::/0")},
		peer(bobKey, "100.90.0.2/32"))
}

func withEgress(t *testing.T) (*Reconciler, *fakeFilter, *fakeEgress, *[]string) {
	t.Helper()
	order := &[]string{}
	filter := &fakeFilter{order: order}
	router := &fakeEgress{order: order}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"
	r := New(newFakeLink(), m, nil, filter, nil)
	r.egress = router
	// The same object as the filter, which is what a Linux host has. The split exists for
	// the platform where they differ, and these tests are about the ordering between the
	// lock and the route rather than about which object provides which.
	r.lock = filter
	return r, filter, router, order
}

// The ordering the whole feature rests on: the lock is installed before the route is
// claimed. The gap between them, in the other order, is a device sending the user's traffic
// in clear over whatever network it is on at the moment it believes it is protected.
func TestTheLockGoesOnBeforeTheRouteIsClaimed(t *testing.T) {
	r, _, _, order := withEgress(t)

	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}
	// One sequence, not two, because what is under test is which came first.
	if got := strings.Join(*order, ", "); got != "lock meshp0, claim meshp0" {
		t.Errorf("order was %q, want the lock installed before the route was claimed", got)
	}
}

// And the reverse on the way out. A lock still in place with the route gone refuses
// everything and the machine has no network.
func TestTheRouteIsReleasedBeforeTheLockComesOff(t *testing.T) {
	r, _, _, order := withEgress(t)
	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}

	// The group goes away.
	plain := stateWithRoutes(2, nil, peer(bobKey, "100.90.0.2/32"))
	if _, err := r.Apply(context.Background(), plain); err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(*order, ", "); got != "lock meshp0, claim meshp0, release, unlock" {
		t.Errorf("order was %q, want the route released before the lock came off", got)
	}
}

// A claim that cannot be made safely is not made at all. Without a control plane address
// the device would lock itself away from the one channel that could tell it to stop.
func TestAClaimIsRefusedWithoutAWayBackToTheControlPlane(t *testing.T) {
	filter := &fakeFilter{}
	router := &fakeEgress{}
	r := New(newFakeLink(), membership(), nil, filter, nil) // no ControlURL
	r.egress = router

	unapplied, err := r.Apply(context.Background(), egressState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "egress") {
		t.Errorf("unapplied = %v, want egress reported", unapplied)
	}
	if len(router.events) != 0 {
		t.Errorf("a default route was claimed anyway: %v", router.events)
	}
	if len(filter.locks) != 0 {
		t.Errorf("a lock was installed with no way back: %v", filter.locks)
	}
}

// A host that cannot do one half must not do the other. Half of this feature is not a
// degraded version of it.
func TestAHostThatCannotRouteDoesNotLockItself(t *testing.T) {
	filter := &fakeFilter{}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"
	r := New(newFakeLink(), m, nil, filter, nil) // no egress implementation

	unapplied, err := r.Apply(context.Background(), egressState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "egress") {
		t.Errorf("unapplied = %v, want egress reported", unapplied)
	}
	if len(filter.locks) != 0 {
		t.Errorf("a host that cannot claim a route locked itself anyway: %v", filter.locks)
	}
}

// The safe half of a half-done claim. If the route will not go on, the lock stays: this
// device sends nothing rather than sending it the wrong way, and the next pass tries again.
func TestAFailedClaimLeavesTheLockOn(t *testing.T) {
	r, filter, router, _ := withEgress(t)
	router.claimErr = errors.New("netlink said no")

	unapplied, err := r.Apply(context.Background(), egressState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "egress") {
		t.Errorf("unapplied = %v, want egress reported", unapplied)
	}
	if len(filter.locks) == 0 || filter.locks[len(filter.locks)-1] != "meshp0" {
		t.Errorf("the lock was not left in place after a failed claim: %v", filter.locks)
	}
}

// The carve-out reaches the lock. A lock that permitted nothing would refuse the control
// plane and the relay along with everything else.
func TestTheCarveoutReachesTheLock(t *testing.T) {
	r, filter, _, _ := withEgress(t)

	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}
	if len(filter.endpoints) == 0 || len(filter.endpoints[0]) == 0 {
		t.Fatal("the lock was given no endpoints, so the control plane is unreachable")
	}
	var sawControl bool
	for _, ep := range filter.endpoints[0] {
		if ep.String() == "198.51.100.10:8443" {
			sawControl = true
		}
	}
	if !sawControl {
		t.Errorf("the control plane is not in the lock's endpoints: %v", filter.endpoints[0])
	}
	if len(filter.excluded[0]) == 0 {
		t.Error("the lock was given no excluded prefixes, so link-local traffic is refused")
	}
}

// Absent means closed. A control plane that has never heard of this field must not be
// asking every device to leak, so omission has to fall the safe way.
func TestFailClosedDefaultsToClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tunnel *meshpv1.TunnelConfig
		want   bool
	}{
		{"no tunnel config at all", nil, true},
		{"a config that says nothing", &meshpv1.TunnelConfig{Mtu: 1420}, true},
		{"an explicit yes", &meshpv1.TunnelConfig{
			FailClosedPolicy: meshpv1.TunnelConfig_FAIL_CLOSED_ENFORCED}, true},
		{"an explicit no", &meshpv1.TunnelConfig{
			FailClosedPolicy: meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED}, false},
		{"the retired bool, which is never read", &meshpv1.TunnelConfig{FailClosed: true}, true},
	} {
		if got := failClosedFor(tc.tunnel); got != tc.want {
			t.Errorf("%s: failClosedFor = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The lock is what makes a full tunnel honest, so a network that asks for it and a host
// that cannot enforce it must not quietly become a route with no protection.
func TestAHostThatCannotFailClosedRefusesTheClaim(t *testing.T) {
	router := &fakeEgress{}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"
	r := New(newFakeLink(), m, nil, nil, nil) // no filter
	r.egress = router

	unapplied, err := r.Apply(context.Background(), egressState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "egress") {
		t.Errorf("unapplied = %v, want egress reported", unapplied)
	}
	if len(router.events) != 0 {
		t.Errorf("a route was claimed with no way to fail closed: %v", router.events)
	}
}

// And with the policy explicitly opted out, the same host may claim: what it cannot do is
// no longer being asked of it.
func TestAnExplicitOptOutClaimsWithoutALock(t *testing.T) {
	router := &fakeEgress{}
	filter := &fakeFilter{}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"
	r := New(newFakeLink(), m, nil, filter, nil)
	r.egress = router

	// Built through a real delta rather than reached into, so the opt-out travels the way
	// it would from a control plane that meant it.
	state := peerset.New()
	state.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: 1,
		UpsertPeers: []*meshpv1.Peer{peer(bobKey, "100.90.0.2/32")},
		Tunnel: &meshpv1.TunnelConfig{
			Mtu:              1420,
			FailClosedPolicy: meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED,
		},
		RouteGroups: []*meshpv1.RouteGroupAssignment{
			assignmentTo("exit", bobKey, "0.0.0.0/0", "::/0"),
		},
	})

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if len(router.events) == 0 {
		t.Fatal("no route was claimed under an explicit opt-out")
	}
	if len(filter.locks) != 0 {
		t.Errorf("a lock was installed for a network that opted out: %v", filter.locks)
	}
}

// The flag has to reach the lock, or the rule is rendered correctly and never asked for.
// This is the edge ADR-0018 asks for: a value that travels from desired state, through the
// reconciler, to the thing that acts on it.
func TestPreventLeaksReachesTheLock(t *testing.T) {
	router := &fakeEgress{}
	filter := &fakeFilter{}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"
	r := New(newFakeLink(), m, nil, filter, nil)
	r.egress = router
	r.lock = filter

	state := peerset.New()
	state.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: 1,
		UpsertPeers: []*meshpv1.Peer{peer(bobKey, "100.90.0.2/32")},
		Tunnel:      &meshpv1.TunnelConfig{Mtu: 1420},
		Dns:         &meshpv1.DnsConfig{PreventLeaks: true},
		RouteGroups: []*meshpv1.RouteGroupAssignment{
			assignmentTo("exit", bobKey, "0.0.0.0/0", "::/0"),
		},
	})

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if len(filter.dnsLocked) == 0 {
		t.Fatal("no lock was installed")
	}
	if !filter.dnsLocked[0] {
		t.Error("the network asked for leak prevention and the lock was not told")
	}
}

// And a network that has not asked does not get it.
func TestLeakPreventionIsNotAssumed(t *testing.T) {
	r, filter, _, _ := withEgress(t)

	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}
	if len(filter.dnsLocked) == 0 {
		t.Fatal("no lock was installed")
	}
	if filter.dnsLocked[0] {
		t.Error("DNS was refused for a network that never asked for it")
	}
}

// A host that can refuse traffic and cannot enforce a policy is a host that fails closed.
//
// The whole reason ApplyLock left Filter. macOS is about to be exactly this: it will have a
// pf ruleset that can drop what does not go through the tunnel, and no implementation of
// ACLs, forwarding or prefix mapping. Before the split it had to have both or neither, and
// "neither" meant a laptop could not be given a full tunnel at all.
//
// What this asserts is that the two capabilities are now independent in the direction that
// matters: the lock goes on, and nothing pretends a policy was enforced.
func TestAHostWithALockAndNoFilterStillFailsClosed(t *testing.T) {
	lock := &fakeFilter{}
	router := &fakeEgress{}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"

	// No filter at all — the shape of a platform with no ACL implementation.
	r := New(newFakeLink(), m, nil, nil, nil)
	r.egress = router
	r.lock = lock

	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}

	if len(lock.dnsLocked) == 0 {
		t.Fatal("a host with a lock and no filter did not install one, so it cannot fail closed")
	}
	if len(router.events) == 0 {
		t.Error("the route was never claimed, so the lock is refusing everything for nothing")
	}
}

// And the converse: a host that can enforce a policy and cannot refuse traffic does not
// claim the route when the network asks devices to fail closed.
//
// This held before the split too, through `r.filter == nil`. It is asserted here because the
// split moved which field decides it, and getting that wrong would mean a device claiming a
// default route while quietly declining to enforce the property it was claimed for — which
// is the dishonesty ADR-0011 is written against.
func TestAHostWithAFilterAndNoLockWillNotClaim(t *testing.T) {
	filter := &fakeFilter{}
	router := &fakeEgress{}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"

	r := New(newFakeLink(), m, nil, filter, nil)
	r.egress = router
	// No lock.

	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}

	if len(router.events) != 0 {
		t.Errorf("a host that cannot fail closed claimed the default route anyway: %v", router.events)
	}
	if len(filter.dnsLocked) != 0 {
		t.Error("something installed a lock through the filter, which is no longer its job")
	}
}

// A second tunnel on the host is not a local network, and the carve-out has to say so.
//
// #207: a device in two networks has an interface per membership (ADR-0004). The carve-out was
// told the addresses of the one being claimed for, so the other looked like an ordinary local
// network — and keeping a local network off the tunnel means routing it through the LAN
// gateway, which the kernel refuses for an address on a point-to-point link. The claim aborted
// on it every pass, and with fail-closed enforced the device refused egress with nothing
// carrying it.
//
// Asserted on what Claim is handed, and not on the helper that computes it. The helper being
// right is not the property that was missing — it did not exist — and a test that calls it
// directly passes with the call site reverted, which is how three of today's fixes were nearly
// shipped without their wiring.
func TestASecondTunnelOnTheHostIsNotCarvedOut(t *testing.T) {
	// A real address on this host, called a tunnel's. LocalNetworks reads the machine's own
	// interfaces — it is not injectable and should not be, since what it reports is a fact
	// about the host — so the way to describe "another tunnel" to it is to name something
	// that is really there.
	addr, network := anAddressOnThisHost(t)

	r, _, router, _ := withEgress(t)
	r.link.(*fakeLink).tunnelAddresses = []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}

	failed := r.applyEgress(context.Background(), "meshp0", nil, true, false, false, nil, nil)
	if failed != nil {
		t.Fatalf("the claim did not happen: %v", failed)
	}
	if slices.Contains(router.claimedPrefixes, network) {
		t.Errorf("%s belongs to an interface named as a tunnel and was carved out anyway; "+
			"keeping it off the tunnel means routing it through the LAN gateway, which the "+
			"kernel refuses for a point-to-point address — the claim fails and the device is "+
			"left refusing egress. got %v", network, router.claimedPrefixes)
	}
}

// anAddressOnThisHost returns a routable address the machine really has, and the network the
// carve-out would derive from it.
func anAddressOnThisHost(t *testing.T) (netip.Addr, netip.Prefix) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot read this host's interfaces:", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			// Not link-local: fe80::/64 is on nearly every interface, so excluding one
			// leaves the same network arriving from another and this would measure nothing.
			if !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if p := netip.PrefixFrom(addr, ones); p.IsValid() {
				return addr, p.Masked()
			}
		}
	}
	t.Skip("no interface on this host carries an address this can use")
	return netip.Addr{}, netip.Prefix{}
}

// A platform that answers without mentioning this membership's own tunnel must not lose it.
//
// Defensive, and the defence is the one that matters: carving out the tunnel being claimed for
// is #200, where the claim asked the kernel to route a device's own mesh address through the
// LAN gateway and the whole claim failed. Widening the list to every tunnel must not open a
// path back to that.
func TestTheMembershipsOwnTunnelSurvivesAnIncompleteList(t *testing.T) {
	mine := netip.MustParsePrefix("100.80.0.3/32")
	other := netip.MustParsePrefix("100.90.0.7/32")

	link := newFakeLink()
	link.tunnelAddresses = []netip.Prefix{other} // answered, and does not mention mine

	r := &Reconciler{link: link, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	got := r.tunnelAddresses([]netip.Prefix{mine})

	if !slices.Contains(got, mine) {
		t.Errorf("the platform listed %v and this membership's own tunnel %s was dropped; "+
			"the claim would carve out its own address, which is #200", got, mine)
	}
}

// A platform that cannot answer costs what it always cost, not the whole claim.
func TestAHostThatCannotListItsTunnelsStillKnowsItsOwn(t *testing.T) {
	mine := netip.MustParsePrefix("100.80.0.3/32")

	link := newFakeLink()
	link.tunnelAddressesErr = errors.New("no")

	r := &Reconciler{link: link, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	got := r.tunnelAddresses([]netip.Prefix{mine})

	if !slices.Contains(got, mine) {
		t.Errorf("with the platform unable to list tunnels, this membership's own address "+
			"was lost too: %v — which is the failure #200 was about", got)
	}
}

// A claim survives DNS going away, which is a state a claim itself produces.
//
// #204: the carve-out needs the control plane's address and refuses to be built without it —
// a device that locked itself away from its control plane would be off the network for a
// reason nobody watching could see. Right on its own, and with a full tunnel claimed it made
// a cycle a device could not leave: the claim carries DNS, so disturbing the claim takes DNS
// with it; the next pass cannot resolve, so it does not claim; the device still wants a claim,
// so nothing is released; round again. Observed on a laptop with no network at all until
// somebody typed `meshp down`.
//
// Asserted through applyEgress, because a resolver that remembers correctly and is never
// reached is worth nothing — a mistake made twice in this area already.
func TestAClaimSurvivesDNSGoingAway(t *testing.T) {
	answering := true
	upstream := func(context.Context, string) ([]netip.Addr, error) {
		if !answering {
			return nil, errors.New("no DNS while the tunnel is broken")
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.10")}, nil
	}

	r, _, router, _ := withEgress(t)
	// A name, not an address. withEgress uses an IP literal, which needs no resolver at all —
	// so this would pass without any of the behaviour under test.
	r.membership.ControlURL = "https://control.example.test:8443"
	r.resolve = egress.Remembering(upstream, filepath.Join(t.TempDir(), "resolved"))

	if failed := r.applyEgress(context.Background(), "meshp0", nil, true, false, false, nil, nil); failed != nil {
		t.Fatalf("the first claim, with DNS working, did not happen: %v", failed)
	}
	first := len(router.events)

	// The claim is in place and now DNS is gone — a change of network, a resolver that has
	// stopped answering. The device has to be able to claim again.
	answering = false
	if failed := r.applyEgress(context.Background(), "meshp0", nil, true, false, false, nil, nil); failed != nil {
		t.Fatalf("with DNS gone the device could not claim again: %v — and it cannot release "+
			"either, because it still wants a claim, so it stays with no network", failed)
	}
	if len(router.events) <= first {
		t.Error("the second claim did not reach the router")
	}
}

// A name never resolved is still a refusal. Inventing an address would pin a route to
// something nobody chose, which is worse than not claiming.
func TestAControlPlaneThatWasNeverResolvedIsStillRefused(t *testing.T) {
	r, _, _, _ := withEgress(t)
	r.membership.ControlURL = "https://control.example.test:8443"
	r.resolve = egress.Remembering(
		func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("no DNS, ever")
		},
		filepath.Join(t.TempDir(), "resolved"),
	)

	if failed := r.applyEgress(context.Background(), "meshp0", nil, true, false, false, nil, nil); failed == nil {
		t.Error("a control plane that has never resolved produced a claim; the carve-out " +
			"would not know which address to keep off the tunnel")
	}
}
