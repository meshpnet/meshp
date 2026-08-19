package session

import (
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/store"
)

// alsoJoin puts a device that is already enrolled into a second network.
//
// Directly, because enrolment mints a new device each time and the whole condition here is
// one device holding two memberships (ADR-0004). The row is the minimum a membership needs
// to be live: the technician is not routing anything in this network, only reachable through
// it, so no key or address is required to see the collision.
func (f *fixture) alsoJoin(d device, network uuid.UUID, iface, label string) {
	f.t.Helper()
	if _, err := f.store.Pool().Exec(f.ctx,
		`INSERT INTO device_network_memberships (device_id,network_id,interface_name,dns_label,state)
		 VALUES ($1,$2,$3,$4,'active')`, d.deviceID, network, iface, label); err != nil {
		f.t.Fatal(err)
	}
}

// carryIn gives another network a subnet group holding a prefix, with somebody to carry it.
func (f *fixture) carryIn(network uuid.UUID, slug, prefix string) {
	f.t.Helper()
	var group uuid.UUID
	if err := f.store.Pool().QueryRow(f.ctx,
		`INSERT INTO route_groups (network_id,slug,name,kind) VALUES ($1,$2,$2,'subnet') RETURNING id`,
		network, slug).Scan(&group); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.store.Pool().Exec(f.ctx,
		`INSERT INTO route_group_prefixes (route_group_id,prefix) VALUES ($1,$2)`, group, prefix); err != nil {
		f.t.Fatal(err)
	}
}

// The claim ADR-0004 has made since the beginning, now arriving on the wire.
//
// A technician in two customers' networks, both using 192.168.1.0/24, is told a distinct
// range to reach each by. Without this the assignment carries the real prefix twice and the
// agent refuses both, which is where PR #70 left it.
func TestACollidingPrefixArrivesWithSomewhereToReachIt(t *testing.T) {
	f := newFixture(t)
	tech := f.enrolDevice("technician")
	carrier := f.enrolDevice("branch-router")

	// The fixture's own network carries it, and is advertised so an assignment exists.
	f.subnetGroup("branch-lan", "192.168.1.0/24")
	f.advertise("branch-lan", carrier, 1)

	// A second customer, on the same addresses, with this technician in it.
	other := f.otherNetwork("customer-b")
	f.carryIn(other, "their-lan", "192.168.1.0/24")
	f.alsoJoin(tech, other, "meshp1", "technician-b")

	assignments := f.assignments(tech)
	if len(assignments) != 1 {
		t.Fatalf("assignments = %d, want the one group this network carries", len(assignments))
	}

	mapped := assignments[0].GetMappedPrefixes()
	if len(mapped) != 1 {
		t.Fatalf("mapped_prefixes = %v; a colliding prefix reached the device with nowhere to reach it",
			mapped)
	}
	if got := mapped[0].GetPrefix(); got != "192.168.1.0/24" {
		t.Errorf("mapped the wrong prefix: %q", got)
	}
	to, err := netip.ParsePrefix(mapped[0].GetMapped())
	if err != nil {
		t.Fatalf("the mapped range is not a prefix: %q", mapped[0].GetMapped())
	}
	if !store.DefaultMappedBlock.Overlaps(to) {
		t.Errorf("%v is outside the mapped block", to)
	}
	if to.Bits() != 24 {
		t.Errorf("%v is not the size of the prefix it carries", to)
	}
}

// The ordinary device is charged nothing for this. A prefix nobody contests is reached at the
// address the customer actually uses, because a mapped address is a thing a person has to
// learn and one handed out for nothing is a cost with no benefit.
func TestAnUncontestedPrefixArrivesUnmapped(t *testing.T) {
	f := newFixture(t)
	tech := f.enrolDevice("technician")
	carrier := f.enrolDevice("branch-router")

	f.subnetGroup("branch-lan", "192.168.1.0/24")
	f.advertise("branch-lan", carrier, 1)

	// A second network, but carrying something else, so nothing is contested.
	other := f.otherNetwork("customer-b")
	f.carryIn(other, "their-lan", "10.20.0.0/16")
	f.alsoJoin(tech, other, "meshp1", "technician-b")

	assignments := f.assignments(tech)
	if len(assignments) != 1 {
		t.Fatalf("assignments = %d", len(assignments))
	}
	if mapped := assignments[0].GetMappedPrefixes(); len(mapped) != 0 {
		t.Errorf("mapped_prefixes = %v on a device where nothing collides", mapped)
	}
}

// A device in one network only is the common case and must be untouched, including by the
// query that looks for collisions.
func TestADeviceInOneNetworkIsNeverMapped(t *testing.T) {
	f := newFixture(t)
	tech := f.enrolDevice("technician")
	carrier := f.enrolDevice("branch-router")

	f.subnetGroup("branch-lan", "192.168.1.0/24")
	f.advertise("branch-lan", carrier, 1)

	assignments := f.assignments(tech)
	if len(assignments) != 1 {
		t.Fatalf("assignments = %d", len(assignments))
	}
	if mapped := assignments[0].GetMappedPrefixes(); len(mapped) != 0 {
		t.Errorf("mapped_prefixes = %v for a device with a single membership", mapped)
	}
}

// Each membership is told its own range and not the other's.
//
// The device holds both, so both are in the mapping table; putting the wrong one in a
// network's assignment would install a range on an interface it does not belong to, and the
// technician would reach the other customer through it.
func TestEachNetworkIsToldOnlyItsOwnRange(t *testing.T) {
	f := newFixture(t)
	tech := f.enrolDevice("technician")
	carrier := f.enrolDevice("branch-router")

	f.subnetGroup("branch-lan", "192.168.1.0/24")
	f.advertise("branch-lan", carrier, 1)

	other := f.otherNetwork("customer-b")
	f.carryIn(other, "their-lan", "192.168.1.0/24")
	f.alsoJoin(tech, other, "meshp1", "technician-b")

	mapped := f.assignments(tech)[0].GetMappedPrefixes()
	if len(mapped) != 1 {
		t.Fatalf("mapped_prefixes = %v, want exactly this network's", mapped)
	}

	// What the other network was given, read from the store, must be a different range --
	// and must not be the one this membership was just told.
	all, err := f.store.EnsureMappings(f.ctx, tech.deviceID, store.DefaultMappedBlock)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("the device has %d mappings, want one per network", len(all))
	}
	var theirs string
	for _, m := range all {
		if m.NetworkID == other {
			theirs = m.Mapped.String()
		}
	}
	if theirs == "" {
		t.Fatal("the second network was never given a range")
	}
	if mapped[0].GetMapped() == theirs {
		t.Errorf("this network was told %s, which belongs to the other one", theirs)
	}
}

// mappedByNetwork keeps each membership's own range, deterministically.
//
// A unit test beside the integration one above, because that test cannot pin this down: both
// networks map the same prefix, the map is keyed by prefix, and which value survives without
// the filter depends on the order rows come back in. A mutation removing the filter passed it
// on a coin flip. Here the other network's mapping is passed last on purpose, so dropping the
// filter always overwrites and always fails.
//
// What it protects is not small: the wrong range on a membership installs one customer's
// mapped prefix on another customer's interface, and the technician reaches the wrong
// machine -- the exact failure the whole feature exists to prevent.
func TestMappedRangesAreNarrowedToOneNetwork(t *testing.T) {
	ours := uuid.New()
	theirs := uuid.New()
	prefix := netip.MustParsePrefix("192.168.1.0/24")

	got := mappedByNetwork([]store.PrefixMapping{
		{NetworkID: ours, Prefix: prefix, Mapped: netip.MustParsePrefix("100.71.0.0/24")},
		// Last on purpose: this is the one that overwrites if nothing filters.
		{NetworkID: theirs, Prefix: prefix, Mapped: netip.MustParsePrefix("100.71.1.0/24")},
	}, ours)

	if len(got) != 1 {
		t.Fatalf("got %v, want only this network's mapping", got)
	}
	if got[prefix] != netip.MustParsePrefix("100.71.0.0/24") {
		t.Errorf("%v was reached at %v, which belongs to the other network", prefix, got[prefix])
	}
}

// And a device with no mappings at all gets nothing rather than an empty map to range over.
func TestNoMappingsIsNoMap(t *testing.T) {
	if got := mappedByNetwork(nil, uuid.New()); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
