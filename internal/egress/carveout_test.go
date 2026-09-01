package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// fixed answers whatever a test says, so what is under test is the decision rather than DNS.
func fixed(answers map[string][]string) Resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		raw, ok := answers[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		out := make([]netip.Addr, 0, len(raw))
		for _, s := range raw {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

func compute(t *testing.T, in Inputs, r Resolver) Carveout {
	t.Helper()
	out, err := Compute(context.Background(), in, r)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	return out
}

func hasPrefix(c Carveout, s string) bool {
	want := netip.MustParsePrefix(s)
	for _, p := range c.Prefixes {
		if p == want {
			return true
		}
	}
	return false
}

func hasEndpoint(c Carveout, s string) bool {
	want := netip.MustParseAddrPort(s)
	for _, ep := range c.Endpoints {
		if ep == want {
			return true
		}
	}
	return false
}

// The channel that can undo all of this. A device that claims a default route without
// knowing where its control plane is has removed the only thing that could tell it to stop.
func TestTheControlPlaneIsAlwaysCarvedOut(t *testing.T) {
	got := compute(t, Inputs{ControlURL: "https://control.example:8443"},
		fixed(map[string][]string{"control.example": {"198.51.100.10"}}))

	if !hasEndpoint(got, "198.51.100.10:8443") {
		t.Errorf("the control plane is not in the carve-out: %+v", got.Endpoints)
	}
}

// Refusing is visible; claiming anyway is not. A device that cannot work out where its
// control plane is must not lock itself away from it.
func TestAnUnreachableControlPlaneRefusesTheWholeCarveout(t *testing.T) {
	_, err := Compute(context.Background(),
		Inputs{ControlURL: "https://control.example"}, fixed(nil))

	if !errors.Is(err, ErrNoControlPlane) {
		t.Fatalf("err = %v, want ErrNoControlPlane", err)
	}
}

// A relay that will not resolve costs that relay. The device is then visibly unconverged
// rather than invisibly cut off, which is the trade this makes on purpose.
func TestAnUnresolvableRelayDoesNotCostTheCarveout(t *testing.T) {
	got := compute(t, Inputs{
		ControlURL:     "https://198.51.100.10:443",
		RelayEndpoints: []string{"gone.example:3478", "203.0.113.9:3478"},
	}, fixed(nil))

	if !hasEndpoint(got, "203.0.113.9:3478") {
		t.Errorf("the resolvable relay was lost with the unresolvable one: %+v", got.Endpoints)
	}
	if !hasEndpoint(got, "198.51.100.10:443") {
		t.Error("the control plane was lost")
	}
}

// An address needs no resolver, and that matters more here than it looks: a deployment
// named by address stays reachable on a device whose DNS the lock is about to refuse.
func TestAnAddressNeedsNoResolver(t *testing.T) {
	got := compute(t, Inputs{ControlURL: "https://198.51.100.10:8443"}, fixed(nil))

	if !hasEndpoint(got, "198.51.100.10:8443") {
		t.Errorf("a control plane named by address was not carved out: %+v", got.Endpoints)
	}
}

// The scheme's default port, because that is what a session actually dialled.
func TestTheSchemeSuppliesTheDefaultPort(t *testing.T) {
	got := compute(t, Inputs{ControlURL: "https://198.51.100.10"}, fixed(nil))

	if !hasEndpoint(got, "198.51.100.10:443") {
		t.Errorf("https did not default to 443: %+v", got.Endpoints)
	}
}

// The one prefix that must never be carved out. Excluding a default route permits
// everything and hands nothing to the tunnel: a device that reports itself fully tunnelled
// and is not, which is the dishonesty ADR-0011 exists to prevent — arriving through one
// mistyped line of configuration.
func TestADefaultRouteIsNeverCarvedOut(t *testing.T) {
	got := compute(t, Inputs{
		ControlURL:    "https://198.51.100.10:443",
		ExtraPrefixes: []string{"0.0.0.0/0", "::/0", "192.168.1.0/24"},
	}, fixed(nil))

	for _, p := range got.Prefixes {
		if p.Bits() == 0 {
			t.Errorf("a default route was carved out: %s", p)
		}
	}
	if !hasPrefix(got, "192.168.1.0/24") {
		t.Error("the usable exclusion was lost along with the default routes")
	}
}

// Each of these keeps the machine working and none of them leaves the local link, so
// capturing them protects nothing and breaks the network underneath.
func TestTheLinkLocalWorldIsAlwaysCarvedOut(t *testing.T) {
	got := compute(t, Inputs{ControlURL: "https://198.51.100.10:443"}, fixed(nil))

	for _, want := range []struct{ prefix, why string }{
		{"169.254.0.0/16", "IPv4 link-local, which is what a machine has before DHCP answers"},
		{"224.0.0.0/4", "IPv4 multicast, which mDNS and discovery need"},
		{"fe80::/10", "IPv6 link-local, which neighbour discovery depends on"},
		{"ff00::/8", "IPv6 multicast, which router advertisements arrive on"},
	} {
		if !hasPrefix(got, want.prefix) {
			t.Errorf("%s is not carved out\n  needed for: %s", want.prefix, want.why)
		}
	}
}

// The gateway the outer WireGuard packets leave through lives on one of these. Capturing
// the local network is how a device tunnels itself off its own link.
func TestTheLocalNetworkIsCarvedOut(t *testing.T) {
	got := compute(t, Inputs{
		ControlURL:    "https://198.51.100.10:443",
		LocalPrefixes: []netip.Prefix{netip.MustParsePrefix("192.168.7.42/24")},
	}, fixed(nil))

	// Masked, because a route and a firewall rule want the network rather than the address
	// the interface happens to hold on it.
	if !hasPrefix(got, "192.168.7.0/24") {
		t.Errorf("the local network is not carved out: %+v", got.Prefixes)
	}
}

// One typo should cost that exclusion, not the device's route.
func TestAnUnusableExtraPrefixIsSkipped(t *testing.T) {
	got := compute(t, Inputs{
		ControlURL:    "https://198.51.100.10:443",
		ExtraPrefixes: []string{"not-a-prefix", "10.8.0.0/16"},
	}, fixed(nil))

	if !hasPrefix(got, "10.8.0.0/16") {
		t.Errorf("a usable exclusion was lost with an unusable one: %+v", got.Prefixes)
	}
}

// The same inputs must produce the same carve-out, or every reconcile pass reloads a lock
// and rewrites a routing table that did not change.
func TestTheCarveoutIsStable(t *testing.T) {
	in := Inputs{
		ControlURL:     "https://198.51.100.10:443",
		RelayEndpoints: []string{"203.0.113.9:3478", "203.0.113.8:3478", "203.0.113.9:3478"},
		LocalPrefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.7.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.168.7.0/24"),
		},
	}
	first := compute(t, in, fixed(nil))
	second := compute(t, in, fixed(nil))

	if len(first.Prefixes) != len(second.Prefixes) || len(first.Endpoints) != len(second.Endpoints) {
		t.Fatalf("the same inputs produced different sizes: %+v vs %+v", first, second)
	}
	for i := range first.Prefixes {
		if first.Prefixes[i] != second.Prefixes[i] {
			t.Errorf("prefix %d differs: %s vs %s", i, first.Prefixes[i], second.Prefixes[i])
		}
	}
	for i := range first.Endpoints {
		if first.Endpoints[i] != second.Endpoints[i] {
			t.Errorf("endpoint %d differs: %s vs %s", i, first.Endpoints[i], second.Endpoints[i])
		}
	}

	// And a repeat is dropped rather than carried twice.
	seen := map[netip.Prefix]int{}
	for _, p := range first.Prefixes {
		seen[p]++
		if seen[p] > 1 {
			t.Errorf("%s appears more than once", p)
		}
	}
}

// The tunnel's own interface must not be carved out: its prefix is the mesh the device is
// joining, and excluding it would leave every peer unreachable through the interface that
// serves them.
//
// This used to be a test that could not test the thing. LocalNetworks took an interface name,
// so proving the tunnel was skipped needed an interface actually called meshp0 — which the
// test said out loud was "the data-plane container's job rather than this test's", and which
// meant the property went unchecked on the platform where it was broken. macOS calls the
// interface utunN and never matched the name at all (#200).
//
// Identifying the tunnel by an address it carries makes it checkable anywhere: take an
// address this machine really has, call it the tunnel's, and require that interface's
// networks to disappear from the answer.
func TestAnInterfaceCarryingTheTunnelsAddressIsNotTreatedAsLocal(t *testing.T) {
	all := LocalNetworks(nil)
	if len(all) == 0 {
		t.Skip("this machine reports no local networks to exclude one from")
	}

	// Any address that is genuinely on this host, standing in for the tunnel's.
	pretendTunnel, networks := anInterfacesAddress(t)
	got := LocalNetworks([]netip.Prefix{netip.PrefixFrom(pretendTunnel, pretendTunnel.BitLen())})

	for _, p := range networks {
		if slices.Contains(got, p) {
			t.Errorf("%s belongs to the interface carrying %s, which was named as the "+
				"tunnel's own, and it is still reported as a local network",
				p, pretendTunnel)
		}
	}
	if len(got) >= len(all) {
		t.Errorf("naming a real address as the tunnel's excluded nothing: %d before, %d after",
			len(all), len(got))
	}
}

// Loopback and default routes are never local networks, whatever is passed.
func TestLoopbackAndDefaultsAreNeverLocalNetworks(t *testing.T) {
	for _, p := range LocalNetworks(nil) {
		if p.Addr().IsLoopback() {
			t.Errorf("loopback %s was reported as a local network", p)
		}
		if p.Bits() == 0 {
			t.Errorf("a default route was reported as a local network: %s", p)
		}
	}
}

// The tunnel is matched by address and not by containment, and the difference is not
// academic: a device's addresses come from the network's own range (ADR-0005), so a
// deployment whose LAN overlapped that range would have its real network mistaken for the
// tunnel and silently dropped from the carve-out — which is a hole in a fail-closed lock.
func TestTheTunnelIsMatchedByAddressAndNotByContainment(t *testing.T) {
	own := []netip.Prefix{netip.MustParsePrefix("100.80.0.3/32")}

	if !holds(own, netip.MustParseAddr("100.80.0.3")) {
		t.Error("the tunnel's own address was not recognised")
	}
	if holds(own, netip.MustParseAddr("100.80.0.9")) {
		t.Error("another address in the same range was taken for the tunnel's")
	}

	wide := []netip.Prefix{netip.MustParsePrefix("100.80.0.0/24")}
	if holds(wide, netip.MustParseAddr("100.80.0.9")) {
		t.Error("an address merely inside the tunnel's prefix was taken for the tunnel's; " +
			"a LAN overlapping the mesh range would be dropped from the carve-out")
	}
}

// An interface carrying the tunnel contributes nothing, not just the address that matched.
//
// Deterministic, because the property only shows on a tunnel with more than one address —
// which every device has, a v4 and a v6, but which the host running the tests may not arrange
// for any single interface. A mutation that excluded only the matching prefix passed the
// machine-dependent test above.
func TestATunnelWithSeveralAddressesContributesNoneOfThem(t *testing.T) {
	// Only the addresses the control plane assigned are the tunnel's, as far as this knows.
	tunnel := []netip.Prefix{netip.MustParsePrefix("100.80.0.3/32")}

	// What the interface actually carries is more than that: the other assigned address, and
	// the link-local one the kernel adds to every interface by itself. Recognising the
	// interface by one address has to disqualify all of them — the fixture matters, because
	// a list where every entry matched could not tell "skip the interface" from "skip each
	// matching address".
	carried := []netip.Prefix{
		netip.MustParsePrefix("100.80.0.3/32"),
		netip.MustParsePrefix("fd7c:6d65:7368:80::3/128"),
		netip.MustParsePrefix("fe80::1c9d:8f2:1b3c:4d5e/64"),
	}

	if got := contributes(carried, tunnel); len(got) != 0 {
		t.Errorf("the tunnel's own interface contributed %v; carving any of it out sends "+
			"part of the mesh out of the wrong door", got)
	}
}

// And an interface that is not the tunnel contributes everything it carries.
func TestAnOrdinaryInterfaceContributesEveryNetworkItCarries(t *testing.T) {
	tunnel := []netip.Prefix{netip.MustParsePrefix("100.80.0.3/32")}
	carried := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.102/24"),
		netip.MustParsePrefix("2001:db8::5/64"),
	}

	got := contributes(carried, tunnel)
	want := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/24"),
		netip.MustParsePrefix("2001:db8::/64"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("contributes = %v, want %v", got, want)
	}
}

// anInterfacesAddress returns one address this host really has, and every network the
// interface carrying it contributes.
func anInterfacesAddress(t *testing.T) (netip.Addr, []netip.Prefix) {
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
		var (
			first     netip.Addr
			prefixes  []netip.Prefix
			haveFirst bool
		)
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
			// Not a link-local one. fe80::/64 is on nearly every interface, so excluding
			// the one carrying it leaves the same prefix arriving from another and the
			// test measures nothing. A tunnel's address is never link-local anyway — it
			// comes out of the network's own range (ADR-0005).
			if !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() {
				continue
			}
			if !haveFirst {
				first, haveFirst = addr, true
			}
			ones, _ := ipnet.Mask.Size()
			if p := netip.PrefixFrom(addr, ones); p.IsValid() {
				prefixes = append(prefixes, p.Masked())
			}
		}
		if haveFirst && len(prefixes) > 0 {
			return first, prefixes
		}
	}
	t.Skip("no interface on this host carries an address this can use")
	return netip.Addr{}, nil
}

func TestAMissingControlURLIsRefused(t *testing.T) {
	_, err := Compute(context.Background(), Inputs{}, fixed(nil))
	if !errors.Is(err, ErrNoControlPlane) {
		t.Fatalf("err = %v, want ErrNoControlPlane", err)
	}
	if !strings.Contains(err.Error(), "control plane") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}
