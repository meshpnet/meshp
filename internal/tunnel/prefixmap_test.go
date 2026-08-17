package tunnel

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/meshpnet/meshp/internal/wgplan"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// mappedTo adds an allocated range to an assignment.
func mappedTo(a *meshpv1.RouteGroupAssignment, real, to string) *meshpv1.RouteGroupAssignment {
	a.MappedPrefixes = append(a.MappedPrefixes,
		&meshpv1.RouteGroupAssignment_MappedPrefix{Prefix: real, Mapped: to})
	return a
}

// The whole of ADR-0020, at the device: two memberships carrying 192.168.1.0/24 both work,
// because the routing table holds two distinct ranges instead of one prefix twice.
//
// Without the mapping this is the case PR #70 refuses outright, and refusing is still what
// happens if anything here is missing -- which is what makes the assertion meaningful rather
// than a restatement of the setup.
func TestTwoMembershipsOnOnePrefixAreBothCarried(t *testing.T) {
	claims := NewClaims()
	first := desiredWithMapping(t, "meshp0", claims, "100.71.5.0/24")
	second := desiredWithMapping(t, "meshp1", claims, "100.71.6.0/24")

	for _, c := range []struct {
		iface  string
		iface2 wgplan.Interface
		mapped string
	}{{"meshp0", first, "100.71.5.0/24"}, {"meshp1", second, "100.71.6.0/24"}} {
		// The allowed IP stays the customer's own prefix: that is the destination in the
		// packet once the rewrite has happened, and WireGuard drops anything outside it.
		if got := allowedIPsOf(c.iface2, bobKey); !slices.Contains(got, "192.168.1.0/24") {
			t.Errorf("%s allows %v, missing the prefix that actually crosses the tunnel", c.iface, got)
		}
		// And the mapping is what the interface will translate by.
		want := netip.MustParsePrefix(c.mapped)
		if got := c.iface2.Mapped[netip.MustParsePrefix("192.168.1.0/24")]; got != want {
			t.Errorf("%s maps to %v, want %v", c.iface, got, want)
		}
	}
}

// desiredWithMapping builds one membership's interface for a colliding prefix.
func desiredWithMapping(t *testing.T, iface string, claims *Claims, mapped string) wgplan.Interface {
	t.Helper()
	m := membership()
	m.InterfaceName = iface
	assignment := mappedTo(assignmentTo("branch", bobKey, "192.168.1.0/24"), "192.168.1.0/24", mapped)

	got, unhonoured, err := Desired(m, stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignment},
		peer(bobKey, "100.90.0.2/32")), nil, nil, claims, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unhonoured) != 0 {
		t.Fatalf("%s refused %v; a mapped prefix is not contested", iface, unhonoured)
	}
	return got
}

// The honest failure ADR-0020 insists on: a host that cannot translate keeps refusing rather
// than carrying one of two identical prefixes.
//
// This is the assertion that stops the feature being worse than what it replaced. A device
// that installed a route to a mapped range with nothing to rewrite it would blackhole the
// customer it was meant to reach, and would look configured while doing it.
func TestAHostThatCannotTranslateStillRefuses(t *testing.T) {
	claims := NewClaims()
	assignment := mappedTo(assignmentTo("branch", bobKey, "192.168.1.0/24"), "192.168.1.0/24", "100.71.5.0/24")

	// The first membership claims the real prefix, because it cannot translate either.
	one := membership()
	one.InterfaceName = "meshp0"
	if _, _, err := Desired(one, stateWithRoutes(1, []*meshpv1.RouteGroupAssignment{assignment},
		peer(bobKey, "100.90.0.2/32")), nil, nil, claims, false, nil); err != nil {
		t.Fatal(err)
	}

	two := membership()
	two.InterfaceName = "meshp1"
	iface, unhonoured, err := Desired(two, stateWithRoutes(1, []*meshpv1.RouteGroupAssignment{assignment},
		peer(bobKey, "100.90.0.2/32")), nil, nil, claims, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unhonoured) == 0 {
		t.Error("a host that cannot translate carried a prefix another membership also claims")
	}
	if len(iface.Mapped) != 0 {
		t.Errorf("Mapped = %v on a host with nothing to perform the translation", iface.Mapped)
	}
}

// A mapping whose halves are different sizes is refused rather than approximated: the host
// part is carried across unchanged, so a mismatched pair reaches the wrong machine inside the
// right customer.
func TestAMappingThatCannotWorkIsIgnored(t *testing.T) {
	assignment := mappedTo(assignmentTo("branch", bobKey, "192.168.1.0/24"), "192.168.1.0/24", "100.71.5.0/25")

	iface, _, err := Desired(membership(), stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignment},
		peer(bobKey, "100.90.0.2/32")), nil, nil, NewClaims(), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(iface.Mapped) != 0 {
		t.Errorf("Mapped = %v; a mapping of mismatched sizes cannot carry the host part", iface.Mapped)
	}
}

// The rules reach the host, and stop when the device stops colliding.
func TestTheMappingIsInstalledAndRemoved(t *testing.T) {
	link := newFakeLink()
	filter := &fakeFilter{}
	r := New(link, membership(), nil, filter, nil).WithClaims(NewClaims())

	assignment := mappedTo(assignmentTo("branch", bobKey, "192.168.1.0/24"), "192.168.1.0/24", "100.71.5.0/24")
	if _, err := r.Apply(context.Background(), stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignment}, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.mappings) != 1 || len(filter.mappings[0]) != 1 {
		t.Fatalf("mappings installed = %v", filter.mappings)
	}

	// Unchanged: not reinstalled, because rebuilding the table runs on the reconcile timer.
	if _, err := r.Apply(context.Background(), stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{assignment}, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.mappings) != 1 {
		t.Errorf("an unchanged mapping was installed %d times", len(filter.mappings))
	}

	// And the collision going away takes the rules with it (Invariant 20).
	plain := assignmentTo("branch", bobKey, "192.168.1.0/24")
	if _, err := r.Apply(context.Background(), stateWithRoutes(2,
		[]*meshpv1.RouteGroupAssignment{plain}, peer(bobKey, "100.90.0.2/32"))); err != nil {
		t.Fatal(err)
	}
	if len(filter.mappings) != 2 {
		t.Fatalf("the mapping was not removed: %v", filter.mappings)
	}
	if len(filter.mappings[1]) != 0 {
		t.Errorf("removal installed %v rather than nothing", filter.mappings[1])
	}
}

// A mapped range is itself a routing-table entry, and can be contested like any other.
//
// This is the case that pins down what Claims must talk about. Declaring and contesting are
// two halves of one rule, and a mutation to either alone leaves them agreeing with each other
// while both look at the wrong thing -- the test above cannot tell. Here one membership's
// allocated range is a prefix another membership genuinely carries, so the two halves have to
// be looking at the routing table or the device installs the same entry twice.
//
// It is not hypothetical: the allocator avoids the organisation's own address pools and other
// mapped ranges, but nothing stops a customer's LAN being inside the mapped block. It is
// carrier-grade NAT space and unusual for a LAN, which makes this rare and not impossible.
func TestAMappedRangeCanItselfBeContested(t *testing.T) {
	const overlap = "100.71.5.0/24"

	// The mapped membership first: it claims the range it will route by.
	t.Run("the plain membership loses when the mapped one claimed first", func(t *testing.T) {
		claims := NewClaims()
		desiredWithMapping(t, "meshp0", claims, overlap)

		plain := membership()
		plain.InterfaceName = "meshp1"
		_, unhonoured, err := Desired(plain, stateWithRoutes(1,
			[]*meshpv1.RouteGroupAssignment{assignmentTo("theirs", bobKey, overlap)},
			peer(bobKey, "100.90.0.2/32")), nil, nil, claims, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(unhonoured) == 0 {
			t.Errorf("a prefix already held as somebody's mapped range was carried anyway")
		}
	})

	// And the other way round: the range was taken, so the mapping cannot use it.
	t.Run("the mapped membership loses when the plain one claimed first", func(t *testing.T) {
		claims := NewClaims()
		plain := membership()
		plain.InterfaceName = "meshp1"
		if _, _, err := Desired(plain, stateWithRoutes(1,
			[]*meshpv1.RouteGroupAssignment{assignmentTo("theirs", bobKey, overlap)},
			peer(bobKey, "100.90.0.2/32")), nil, nil, claims, true, nil); err != nil {
			t.Fatal(err)
		}

		m := membership()
		m.InterfaceName = "meshp0"
		assignment := mappedTo(assignmentTo("branch", bobKey, "192.168.1.0/24"), "192.168.1.0/24", overlap)
		_, unhonoured, err := Desired(m, stateWithRoutes(1,
			[]*meshpv1.RouteGroupAssignment{assignment},
			peer(bobKey, "100.90.0.2/32")), nil, nil, claims, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(unhonoured) == 0 {
			t.Errorf("a mapped range another membership already routes was used anyway")
		}
	})
}
