package tunnel

import (
	"context"
	"net/netip"
	"testing"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// The case ADR-0004 sells and ADR-0019 says must not be resolved silently: a technician
// supporting two customers who both took their router's default.
func TestTwoNetworksClaimingOneCustomerPrefixBothRefuse(t *testing.T) {
	claims := NewClaims()
	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("branch", bobKey, "192.168.1.0/24")},
		peer(bobKey, "100.90.0.2/32"))

	first := New(newFakeLink(), membership(), nil, nil, nil).WithClaims(claims)
	if _, err := first.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	// A second membership, on its own interface, carrying the same customer prefix.
	second := membership()
	second.InterfaceName = "meshp1"
	other := New(newFakeLink(), second, nil, nil, nil).WithClaims(claims)

	unapplied, err := other.Apply(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "route-groups") {
		t.Errorf("the second network carried a contested prefix silently: %v", unapplied)
	}

	// And the first refuses too, on its next pass. Neither wins, because which one a packet
	// reached would otherwise depend on the order the routing table was written.
	unapplied, err = first.Apply(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "route-groups") {
		t.Errorf("the first network kept carrying a contested prefix: %v", unapplied)
	}
}

// One network on a device is the ordinary case and must be untouched.
func TestOneNetworkCarriesItsPrefixes(t *testing.T) {
	claims := NewClaims()
	r := New(newFakeLink(), membership(), nil, nil, nil).WithClaims(claims)
	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("branch", bobKey, "192.168.1.0/24")},
		peer(bobKey, "100.90.0.2/32"))

	unapplied, err := r.Apply(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if slicesContain(unapplied, "route-groups") {
		t.Errorf("a network with nobody to contest it refused its own prefix: %v", unapplied)
	}
}

// Longest match resolves these deterministically on every machine, so they are not
// ambiguous and must not be refused.
func TestOverlappingButUnequalPrefixesAreNotContested(t *testing.T) {
	claims := NewClaims()
	claims.Declare("meshp0", []netip.Prefix{p("192.168.1.0/24")})

	for _, other := range []string{"192.168.1.0/25", "192.168.0.0/16", "0.0.0.0/0"} {
		if got := claims.Contested("meshp1", p(other)); len(got) != 0 {
			t.Errorf("%s was called contested against 192.168.1.0/24: %v", other, got)
		}
	}
	if got := claims.Contested("meshp1", p("192.168.1.0/24")); len(got) != 1 {
		t.Errorf("an identical prefix was not contested: %v", got)
	}
}

// A full tunnel alongside a customer LAN is well defined, so an egress group must not
// contest anything — otherwise turning on egress would take a technician's customers away.
func TestAnEgressGroupContestsNothing(t *testing.T) {
	claims := NewClaims()
	claims.Declare("meshp0", []netip.Prefix{p("0.0.0.0/0"), p("::/0")})

	if got := contestedPrefixes(claims, "meshp1", []netip.Prefix{p("192.168.1.0/24")}); len(got) != 0 {
		t.Errorf("a customer prefix was contested by a default route: %v", got)
	}
	if got := contestedPrefixes(claims, "meshp1", []netip.Prefix{p("0.0.0.0/0")}); len(got) != 0 {
		t.Errorf("a default route contested another default route: %v", got)
	}
}

// A membership that has left every route group must stop contesting, or the network it used
// to share a prefix with stays refused for a claim nobody holds.
func TestLeavingEveryGroupReleasesTheClaim(t *testing.T) {
	claims := NewClaims()
	first := New(newFakeLink(), membership(), nil, nil, nil).WithClaims(claims)
	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("branch", bobKey, "192.168.1.0/24")},
		peer(bobKey, "100.90.0.2/32"))
	if _, err := first.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if got := claims.Contested("meshp1", p("192.168.1.0/24")); len(got) != 1 {
		t.Fatalf("the first membership never claimed it: %v", got)
	}

	// The control plane takes it out of every group.
	if _, err := first.Apply(context.Background(),
		stateWithRoutes(2, nil, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if got := claims.Contested("meshp1", p("192.168.1.0/24")); len(got) != 0 {
		t.Errorf("a membership that left every group still contests: %v", got)
	}
}

// A nil registry is the single-network case and every existing caller.
func TestANilRegistryContestsNothing(t *testing.T) {
	var claims *Claims
	claims.Declare("meshp0", []netip.Prefix{p("192.168.1.0/24")})
	claims.Forget("meshp0")
	if got := claims.Contested("meshp1", p("192.168.1.0/24")); got != nil {
		t.Errorf("a nil registry reported a collision: %v", got)
	}
}
