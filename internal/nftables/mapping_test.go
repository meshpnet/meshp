package nftables

import (
	"net/netip"
	"strings"
	"testing"
)

func mapping(mapped, real string) Mapping {
	return Mapping{Mapped: netip.MustParsePrefix(mapped), Real: netip.MustParsePrefix(real)}
}

func renderMap(t *testing.T, iface string, mappings ...Mapping) string {
	t.Helper()
	out, err := RenderMap(iface, mappings)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The mask is the arithmetic, and getting it wrong sends a technician to the wrong host
// inside the right customer — which is worse than sending them nowhere, because it works.
func TestTheHostPartIsCarriedAcross(t *testing.T) {
	for _, tc := range []struct{ mapped, real, wildcard string }{
		{"100.71.5.0/24", "192.168.1.0/24", "0.0.0.255"},
		{"100.71.0.0/16", "10.4.0.0/16", "0.0.255.255"},
		{"100.71.7.128/25", "192.168.2.128/25", "0.0.0.127"},
		{"100.71.8.0/30", "172.16.9.0/30", "0.0.0.3"},
	} {
		got := renderMap(t, "meshp0", mapping(tc.mapped, tc.real))
		if !strings.Contains(got, "& "+tc.wildcard+" |") {
			t.Errorf("%s -> %s used no %s mask:\n%s", tc.mapped, tc.real, tc.wildcard, got)
		}
	}
}

// Both directions, or the reply never gets home. The customer answers the source it saw, so
// something has to turn 192.168.1.5 back into the address the technician's socket knows.
func TestBothDirectionsAreRewritten(t *testing.T) {
	got := renderMap(t, "meshp0", mapping("100.71.5.0/24", "192.168.1.0/24"))

	if !strings.Contains(got, `oifname "meshp0" ip daddr 100.71.5.0/24 ip daddr set`) {
		t.Errorf("nothing rewrites the destination on the way out:\n%s", got)
	}
	if !strings.Contains(got, `iifname "meshp0" ip saddr 192.168.1.0/24 ip saddr set`) {
		t.Errorf("nothing rewrites the source on the way back:\n%s", got)
	}
}

// The source is never touched. ADR-0007 enforces ACLs at the destination against the identity
// of the device reaching it, and rewriting the source would hand every customer's server one
// address for the entire MSP.
func TestTheSourceIsNeverRewrittenOnTheWayOut(t *testing.T) {
	got := renderMap(t, "meshp0", mapping("100.71.5.0/24", "192.168.1.0/24"))

	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "oifname") && strings.Contains(line, "saddr set") {
			t.Errorf("an outbound rule rewrites the source: %s", line)
		}
	}
}

// No connection tracking, which is the choice the design actually rests on.
//
// A conntrack DNAT would re-route after rewriting, against a table holding two identical
// prefixes, and would keep per-connection state that an expiry or a daemon restart drops
// underneath an established connection. Raw arithmetic has neither problem.
func TestTranslationDoesNotTrackConnections(t *testing.T) {
	got := renderMap(t, "meshp0", mapping("100.71.5.0/24", "192.168.1.0/24"))

	for _, banned := range []string{"dnat", "snat", "masquerade", "ct "} {
		if strings.Contains(got, banned) {
			t.Errorf("the ruleset uses %q, which puts per-connection state on the path:\n%s", banned, got)
		}
	}
}

// The hook, asserted for what it is: a convention with one real property behind it.
//
// This is deliberately a weaker claim than it looks. For locally-generated traffic the route
// is already chosen before either hook runs, so a raw rewrite in output behaves identically —
// a mutation moving it there passes every real-packet test in this package. Postrouting earns
// its place only because forwarded packets traverse it and never reach output.
func TestTheOutboundRewriteIsInPostrouting(t *testing.T) {
	got := renderMap(t, "meshp0", mapping("100.71.5.0/24", "192.168.1.0/24"))

	if !strings.Contains(got, "hook postrouting") {
		t.Errorf("the outbound rewrite is not in postrouting:\n%s", got)
	}
}

// Nothing to map means nothing installed, which is Invariant 20: a device that stopped
// colliding stops translating rather than keeping a rewrite nobody asked for.
func TestNoMappingsRemovesTheTable(t *testing.T) {
	got := renderMap(t, "meshp0")

	if !strings.Contains(got, "delete table inet "+MapTableName) {
		t.Errorf("an empty mapping set does not remove the table:\n%s", got)
	}
	if strings.Contains(got, "add rule") {
		t.Errorf("an empty mapping set still installed rules:\n%s", got)
	}
}

// Refused rather than approximated. Every one of these would produce a ruleset that
// translates something, and translating the wrong thing is how a technician reaches a machine
// they did not mean to touch.
func TestAMappingThatCannotBeExpressedIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Mapping
	}{
		{"different sizes", mapping("100.71.5.0/24", "192.168.1.0/25")},
		{"different families", mapping("100.71.5.0/24", "fd00::/24")},
		{"host bits set in the mapped half", mapping("100.71.5.7/24", "192.168.1.0/24")},
		{"host bits set in the real half", mapping("100.71.5.0/24", "192.168.1.9/24")},
		{"a half that is missing", Mapping{Mapped: netip.MustParsePrefix("100.71.5.0/24")}},
	} {
		if _, err := RenderMap("meshp0", []Mapping{tc.m}); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

// Two rules for the same mapped range would fire in file order, so the second never runs and
// whoever wrote it believes something untrue.
func TestTheSameMappedRangeTwiceIsRefused(t *testing.T) {
	_, err := RenderMap("meshp0", []Mapping{
		mapping("100.71.5.0/24", "192.168.1.0/24"),
		mapping("100.71.5.0/24", "10.0.0.0/24"),
	})
	if err == nil {
		t.Error("the same mapped range was accepted twice")
	}
}

// A stable order, so an unchanged set of mappings renders an unchanged script. Otherwise the
// reconciler reinstalls the ruleset every pass and it reads as churn.
func TestTheSameMappingsRenderTheSameScript(t *testing.T) {
	forward := renderMap(t, "meshp0",
		mapping("100.71.5.0/24", "192.168.1.0/24"),
		mapping("100.71.6.0/24", "192.168.1.0/24"),
		mapping("100.71.4.0/24", "10.0.0.0/24"))
	backward := renderMap(t, "meshp0",
		mapping("100.71.4.0/24", "10.0.0.0/24"),
		mapping("100.71.6.0/24", "192.168.1.0/24"),
		mapping("100.71.5.0/24", "192.168.1.0/24"))

	if forward != backward {
		t.Errorf("the order they arrived in changed the script:\n%s\n---\n%s", forward, backward)
	}
}

// Two customers really can share one real prefix — that is the case this exists for, and it
// must not be mistaken for the duplicate the check above refuses.
func TestTwoMappingsMayShareARealPrefix(t *testing.T) {
	got := renderMap(t, "meshp0",
		mapping("100.71.5.0/24", "192.168.1.0/24"),
		mapping("100.71.6.0/24", "192.168.1.0/24"))

	if !strings.Contains(got, "daddr 100.71.5.0/24") || !strings.Contains(got, "daddr 100.71.6.0/24") {
		t.Errorf("two customers on one prefix did not both get a mapping:\n%s", got)
	}
}

// An interface name is interpolated into a script that runs as root.
func TestAnUnusableInterfaceNameIsRefused(t *testing.T) {
	for _, name := range []string{"", "meshp0; drop table inet filter", "a b", strings.Repeat("x", 16)} {
		if _, err := RenderMap(name, []Mapping{mapping("100.71.5.0/24", "192.168.1.0/24")}); err == nil {
			t.Errorf("%q was accepted as an interface name", name)
		}
	}
}

// Two memberships do not erase each other, which is the defect an end-to-end run found.
//
// Every membership reconciles on its own timer and renders its own ruleset whole. When they
// shared one table the second to reconcile deleted the first's rules -- so a technician in
// two customers reached exactly one of them, and which one depended on timing. On the only
// devices that have these rules at all, that is the feature failing completely.
//
// The unit tests before this one all rendered a single interface, so none of them could see
// it. This is the smallest test that can.
func TestTwoInterfacesDoNotShareATable(t *testing.T) {
	first := renderMap(t, "meshp0", mapping("100.71.5.0/24", "192.168.1.0/24"))
	second := renderMap(t, "meshp1", mapping("100.71.6.0/24", "192.168.1.0/24"))

	if MapTable("meshp0") == MapTable("meshp1") {
		t.Fatal("both interfaces render into one table, so whichever reconciles last wins")
	}
	// Neither script may touch the other's table, by any statement: an `add` would be
	// harmless but a `delete` is the whole bug.
	if strings.Contains(first, MapTable("meshp1")) {
		t.Errorf("meshp0's ruleset names meshp1's table:\n%s", first)
	}
	if strings.Contains(second, MapTable("meshp0")) {
		t.Errorf("meshp1's ruleset names meshp0's table:\n%s", second)
	}
}

// And removal is still scoped to the interface, so one membership leaving does not take the
// other's translation with it.
func TestRemovingOneInterfaceLeavesTheOther(t *testing.T) {
	empty := renderMap(t, "meshp0")

	if !strings.Contains(empty, "delete table inet "+MapTable("meshp0")) {
		t.Errorf("removing meshp0's mappings does not delete its table:\n%s", empty)
	}
	if strings.Contains(empty, MapTable("meshp1")) {
		t.Errorf("removing meshp0's mappings touches meshp1's table:\n%s", empty)
	}
}
