package prefixmap

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, p(s))
	}
	return out
}

func alloc(t *testing.T, block, prefix string, reserved ...string) netip.Prefix {
	t.Helper()
	got, err := Allocate(p(block), p(prefix), prefixes(reserved...))
	if err != nil {
		t.Fatalf("Allocate(%s, %s): %v", block, prefix, err)
	}
	return got
}

// The size has to match, because the host part is carried across unchanged: 100.71.5.5 is
// 192.168.1.5 at the other end, and a range of another size could not express that.
func TestAMappedRangeIsTheSameSizeAsWhatItCarries(t *testing.T) {
	for _, size := range []string{"/16", "/20", "/24", "/25", "/30"} {
		got := alloc(t, "100.71.0.0/16", "192.168.0.0"+size)
		if got.Bits() != p("192.168.0.0"+size).Bits() {
			t.Errorf("%s was mapped to %v, a different size", size, got)
		}
		if got.Masked() != got {
			t.Errorf("%v is not aligned to its own size", got)
		}
	}
}

// Lowest free, so a deployment that has allocated three ranges has three small numbers rather
// than three scattered ones. These end up in support tickets.
func TestAllocationStartsAtTheBottomOfTheBlock(t *testing.T) {
	if got := alloc(t, "100.71.0.0/16", "192.168.1.0/24"); got != p("100.71.0.0/24") {
		t.Errorf("first allocation = %v, want 100.71.0.0/24", got)
	}
	if got := alloc(t, "100.71.0.0/16", "192.168.1.0/24", "100.71.0.0/24"); got != p("100.71.1.0/24") {
		t.Errorf("second allocation = %v, want 100.71.1.0/24", got)
	}
}

// The same inputs give the same answer, every time. A mapped address that moved between
// releases would be one an operator had already written down somewhere.
func TestAllocationIsDeterministic(t *testing.T) {
	reserved := []string{"100.71.0.0/24", "100.71.2.0/24"}
	first := alloc(t, "100.71.0.0/16", "192.168.1.0/24", reserved...)
	for range 10 {
		if got := alloc(t, "100.71.0.0/16", "192.168.1.0/24", reserved...); got != first {
			t.Fatalf("the same question answered %v then %v", first, got)
		}
	}
}

// The point of Reserved: a mapped range must not land on the mesh addresses of a network the
// device is already in, or the collision comes back one level up with nothing left to resolve
// it (ADR-0020).
func TestAMappedRangeAvoidsWhatIsSpokenFor(t *testing.T) {
	got := alloc(t, "100.71.0.0/16", "192.168.1.0/24", "100.71.0.0/20")
	if p("100.71.0.0/20").Overlaps(got) {
		t.Errorf("%v was allocated inside a reserved /20", got)
	}
	if got != p("100.71.16.0/24") {
		t.Errorf("got %v, want the first range past the reservation", got)
	}
}

// Overlap in both directions. A reserved range smaller than the candidate is easy to miss:
// the candidate does not sit inside it, but they still collide.
func TestASmallReservationInsideACandidateStillBlocksIt(t *testing.T) {
	got := alloc(t, "100.71.0.0/16", "192.168.1.0/24", "100.71.0.128/28")
	if p("100.71.0.128/28").Overlaps(got) {
		t.Errorf("%v was allocated around a reservation inside it", got)
	}
	if got != p("100.71.1.0/24") {
		t.Errorf("got %v, want the next range after the one holding the reservation", got)
	}
}

// A default route contains every address, so there is nothing distinct to reach it by. Two
// full tunnels on one device stay refused, which is honest rather than a mapping that cannot
// work.
//
// The message is asserted, not just the error kind, and that is the whole reason the guard
// exists. A /0 is smaller than any real block, so removing the check still refuses it — via
// "larger than the block", which is true and would send an operator to enlarge a block that
// could never be large enough. A mutation removing the guard survives an errors.Is check
// alone, which is how this test came to check the wording.
func TestADefaultRouteCannotBeMapped(t *testing.T) {
	_, err := Allocate(p("100.71.0.0/16"), p("0.0.0.0/0"), nil)
	if !errors.Is(err, ErrUnmappable) {
		t.Fatalf("err = %v, want ErrUnmappable", err)
	}
	if !strings.Contains(err.Error(), "default route") {
		t.Errorf("err = %q; it should say what is actually wrong, not send somebody to resize a block", err)
	}
}

// A customer network larger than the block is a different failure from a full block: freeing
// something up would not help, and an operator needs to be told to enlarge the block instead.
func TestAPrefixLargerThanTheBlockIsUnmappableNotExhausted(t *testing.T) {
	_, err := Allocate(p("100.71.0.0/16"), p("10.0.0.0/8"), nil)
	if !errors.Is(err, ErrUnmappable) {
		t.Errorf("err = %v, want ErrUnmappable", err)
	}
	if errors.Is(err, ErrExhausted) {
		t.Error("a prefix too large to ever fit was reported as the block being full")
	}
}

// And a genuinely full block says so, rather than returning something that overlaps.
func TestAFullBlockIsReportedAsExhausted(t *testing.T) {
	_, err := Allocate(p("100.71.0.0/24"), p("192.168.1.0/24"), prefixes("100.71.0.0/24"))
	if !errors.Is(err, ErrExhausted) {
		t.Errorf("err = %v, want ErrExhausted", err)
	}
}

// A block exactly one range wide still works, which is the boundary either side of the case
// above.
func TestABlockThatHoldsExactlyOneRangeWorks(t *testing.T) {
	if got := alloc(t, "100.71.0.0/24", "192.168.1.0/24"); got != p("100.71.0.0/24") {
		t.Errorf("got %v", got)
	}
}

// Families are not interchangeable. Handing back an IPv4 range for an IPv6 prefix would
// produce a rule that matches nothing.
func TestFamiliesAreNotMixed(t *testing.T) {
	if _, err := Allocate(p("100.71.0.0/16"), p("fd00:1::/64"), nil); !errors.Is(err, ErrUnmappable) {
		t.Errorf("an IPv6 prefix was given a range from an IPv4 block: %v", err)
	}
	if _, err := Allocate(p("fd00:71::/48"), p("192.168.1.0/24"), nil); !errors.Is(err, ErrUnmappable) {
		t.Errorf("an IPv4 prefix was given a range from an IPv6 block: %v", err)
	}
}

// IPv6 works, because a device in two networks can collide there too -- ULA prefixes are
// meant to be random but are routinely copied from an example.
func TestAnIPv6PrefixGetsAnIPv6Range(t *testing.T) {
	got := alloc(t, "fd00:71::/48", "fd12:3456:789a::/64")
	if !got.Addr().Is6() || got.Bits() != 64 {
		t.Errorf("got %v, want a /64 out of the IPv6 block", got)
	}
	if !p("fd00:71::/48").Overlaps(got) {
		t.Errorf("%v is not inside the block", got)
	}
}

// --- Colliding -------------------------------------------------------------------------

// The condition the whole feature exists for.
func TestTheSamePrefixInTwoNetworksCollides(t *testing.T) {
	got := Colliding(map[string][]netip.Prefix{
		"customer-a": prefixes("192.168.1.0/24", "10.20.0.0/16"),
		"customer-b": prefixes("192.168.1.0/24"),
	})
	if !slices.Equal(got, prefixes("192.168.1.0/24")) {
		t.Errorf("collisions = %v, want just 192.168.1.0/24", got)
	}
}

// One network carrying a prefix is the ordinary case and must not be mapped. Mapping it would
// give a technician an address to type that is not the one the customer uses, for no reason.
func TestAPrefixInOneNetworkDoesNotCollide(t *testing.T) {
	got := Colliding(map[string][]netip.Prefix{
		"customer-a": prefixes("192.168.1.0/24", "10.20.0.0/16"),
		"customer-b": prefixes("172.16.0.0/24"),
	})
	if len(got) != 0 {
		t.Errorf("collisions = %v on a device where nothing repeats", got)
	}
}

// Overlap is not collision. ADR-0019 settled that longest match decides it and the result is
// what the operator meant: a /24 inside somebody else's /16 is reached by the /24.
func TestOverlappingButDistinctPrefixesDoNotCollide(t *testing.T) {
	got := Colliding(map[string][]netip.Prefix{
		"customer-a": prefixes("10.0.0.0/8"),
		"customer-b": prefixes("10.20.30.0/24"),
	})
	if len(got) != 0 {
		t.Errorf("collisions = %v; overlap is decided by longest match, not by mapping", got)
	}
}

// Two full tunnels are not a mappable collision. Marking them as one would report a fault
// nobody can act on, since a default route has nothing to be mapped into.
func TestTwoDefaultRoutesAreNotReportedAsAMappableCollision(t *testing.T) {
	got := Colliding(map[string][]netip.Prefix{
		"customer-a": prefixes("0.0.0.0/0"),
		"customer-b": prefixes("0.0.0.0/0"),
	})
	if len(got) != 0 {
		t.Errorf("collisions = %v, want none: a default route cannot be mapped", got)
	}
}

// The same prefix twice in one network is a duplicate, not a collision -- one routing table
// entry serves both route groups.
func TestARepeatWithinOneNetworkIsNotACollision(t *testing.T) {
	got := Colliding(map[string][]netip.Prefix{
		"customer-a": prefixes("192.168.1.0/24", "192.168.1.0/24"),
	})
	if len(got) != 0 {
		t.Errorf("collisions = %v within a single network", got)
	}
}

// A stable order, so the same device does not look like it changed between passes.
func TestCollisionsComeBackInAStableOrder(t *testing.T) {
	in := map[string][]netip.Prefix{
		"a": prefixes("192.168.1.0/24", "10.0.0.0/24", "172.16.5.0/24"),
		"b": prefixes("192.168.1.0/24", "10.0.0.0/24", "172.16.5.0/24"),
	}
	want := Colliding(in)
	if len(want) != 3 {
		t.Fatalf("collisions = %v, want three", want)
	}
	for range 20 {
		if got := Colliding(in); !slices.Equal(got, want) {
			t.Fatalf("order changed: %v then %v", want, got)
		}
	}
}

// A device in no networks, or networks carrying nothing, has no collisions and no panic.
func TestNothingCarriedIsNoCollision(t *testing.T) {
	if got := Colliding(nil); len(got) != 0 {
		t.Errorf("collisions = %v from nothing", got)
	}
	if got := Colliding(map[string][]netip.Prefix{"a": nil, "b": {}}); len(got) != 0 {
		t.Errorf("collisions = %v from empty networks", got)
	}
}
