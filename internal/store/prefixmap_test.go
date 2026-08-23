package store

import (
	"context"
	"net/netip"
	"testing"

	"github.com/google/uuid"
)

// mapWorld seeds one organisation, two customer networks, and a device in both. The shape
// ADR-0004 promises and ADR-0020 makes work: one technician, two customers.
type mapWorld struct {
	s      *Store
	ctx    context.Context
	org    uuid.UUID
	netA   uuid.UUID
	netB   uuid.UUID
	device uuid.UUID
}

func seedMapWorld(t *testing.T) *mapWorld {
	t.Helper()
	s := freshStore(t)
	ctx := testContext(t)
	w := &mapWorld{s: s, ctx: ctx}

	row := s.pool.QueryRow(ctx, `INSERT INTO organizations (slug,name) VALUES ('msp','MSP') RETURNING id`)
	if err := row.Scan(&w.org); err != nil {
		t.Fatalf("seeding the organisation: %v", err)
	}
	w.netA = w.network(t, "customer-a")
	w.netB = w.network(t, "customer-b")
	w.device = w.newDevice(t, "tech-laptop")
	return w
}

func (w *mapWorld) network(t *testing.T, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := w.s.pool.QueryRow(w.ctx,
		`INSERT INTO networks (organization_id,slug,name) VALUES ($1,$2,$2) RETURNING id`,
		w.org, slug).Scan(&id)
	if err != nil {
		t.Fatalf("seeding network %s: %v", slug, err)
	}
	return id
}

func (w *mapWorld) newDevice(t *testing.T, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := w.s.pool.QueryRow(w.ctx,
		`INSERT INTO devices (organization_id,name,identity_public_key) VALUES ($1,$2,$3) RETURNING id`,
		w.org, name, []byte(name+"-key-0123456789012345")).Scan(&id)
	if err != nil {
		t.Fatalf("seeding device %s: %v", name, err)
	}
	return id
}

// join puts the device in a network and gives that network a route group carrying prefix.
func (w *mapWorld) join(t *testing.T, device, network uuid.UUID, iface, label, prefix string) {
	t.Helper()
	_, err := w.s.pool.Exec(w.ctx,
		`INSERT INTO device_network_memberships (device_id,network_id,interface_name,dns_label,state)
		 VALUES ($1,$2,$3,$4,'active')`, device, network, iface, label)
	if err != nil {
		t.Fatalf("joining: %v", err)
	}
	if prefix == "" {
		return
	}
	w.carry(t, network, "lan-"+label, prefix)
}

// carry gives a network a subnet route group holding one prefix.
func (w *mapWorld) carry(t *testing.T, network uuid.UUID, slug, prefix string) {
	t.Helper()
	var group uuid.UUID
	err := w.s.pool.QueryRow(w.ctx,
		`INSERT INTO route_groups (network_id,slug,name,kind) VALUES ($1,$2,$2,'subnet') RETURNING id`,
		network, slug).Scan(&group)
	if err != nil {
		t.Fatalf("seeding route group: %v", err)
	}
	if _, err := w.s.pool.Exec(w.ctx,
		`INSERT INTO route_group_prefixes (route_group_id,prefix) VALUES ($1,$2)`, group, prefix); err != nil {
		t.Fatalf("seeding prefix: %v", err)
	}
}

func (w *mapWorld) ensure(t *testing.T) []PrefixMapping {
	t.Helper()
	got, err := w.s.EnsureMappings(w.ctx, w.device, DefaultMappedBlock)
	if err != nil {
		t.Fatalf("EnsureMappings: %v", err)
	}
	return got
}

// The case the whole feature exists for: two customers, the same prefix, one technician.
func TestTwoNetworksOnOnePrefixEachGetARange(t *testing.T) {
	w := seedMapWorld(t)
	w.join(t, w.device, w.netA, "meshp0", "a", "192.168.1.0/24")
	w.join(t, w.device, w.netB, "meshp1", "b", "192.168.1.0/24")

	got := w.ensure(t)
	if len(got) != 2 {
		t.Fatalf("mappings = %+v, want one for each network", got)
	}
	if got[0].Mapped == got[1].Mapped {
		t.Fatalf("both networks were given %v, which is the collision again", got[0].Mapped)
	}
	for _, m := range got {
		if !DefaultMappedBlock.Overlaps(m.Mapped) {
			t.Errorf("%v is outside the mapped block", m.Mapped)
		}
		if m.Mapped.Bits() != 24 {
			t.Errorf("%v is not the size of the prefix it carries", m.Mapped)
		}
	}
}

// A device whose networks carry different prefixes is the ordinary case, and must cost
// nothing: no rows, no addresses spent, no mapped address for a technician to learn.
func TestNoCollisionAllocatesNothing(t *testing.T) {
	w := seedMapWorld(t)
	w.join(t, w.device, w.netA, "meshp0", "a", "192.168.1.0/24")
	w.join(t, w.device, w.netB, "meshp1", "b", "10.20.0.0/16")

	if got := w.ensure(t); len(got) != 0 {
		t.Errorf("mappings = %+v on a device with nothing contested", got)
	}
	var rows int
	if err := w.s.pool.QueryRow(w.ctx, `SELECT count(*) FROM prefix_mappings`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("%d rows were written for a device with no collision", rows)
	}
}

// Asking twice gives the same answer and writes nothing the second time. This runs on the
// state-building path, so an allocation per state build would spend the block in a day.
func TestAskingTwiceIsStableAndWritesOnce(t *testing.T) {
	w := seedMapWorld(t)
	w.join(t, w.device, w.netA, "meshp0", "a", "192.168.1.0/24")
	w.join(t, w.device, w.netB, "meshp1", "b", "192.168.1.0/24")

	first := w.ensure(t)
	for range 3 {
		again := w.ensure(t)
		if len(again) != len(first) {
			t.Fatalf("got %d mappings then %d", len(first), len(again))
		}
		for i := range again {
			if again[i] != first[i] {
				t.Fatalf("the answer changed: %+v then %+v", first, again)
			}
		}
	}
	var rows int
	if err := w.s.pool.QueryRow(w.ctx, `SELECT count(*) FROM prefix_mappings`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("%d rows after four calls, want 2", rows)
	}
}

// The property that makes a mapped address worth printing: a second technician in the same
// two customers is told the same numbers, so the range means one thing across a deployment.
func TestASecondDeviceSeesTheSameRanges(t *testing.T) {
	w := seedMapWorld(t)
	w.join(t, w.device, w.netA, "meshp0", "a", "192.168.1.0/24")
	w.join(t, w.device, w.netB, "meshp1", "b", "192.168.1.0/24")
	first := w.ensure(t)

	other := w.newDevice(t, "second-laptop")
	w.join(t, other, w.netA, "meshp0", "a2", "")
	w.join(t, other, w.netB, "meshp1", "b2", "")

	got, err := w.s.EnsureMappings(w.ctx, other, DefaultMappedBlock)
	if err != nil {
		t.Fatalf("EnsureMappings for the second device: %v", err)
	}
	if len(got) != len(first) {
		t.Fatalf("second device got %+v, first got %+v", got, first)
	}
	for i := range got {
		if got[i] != first[i] {
			t.Errorf("the same customer is %v on one laptop and %v on another", first[i].Mapped, got[i].Mapped)
		}
	}
}

// A mapped range must not land on a network's own mesh addresses, or the collision is back
// one level up with nothing left to resolve it (ADR-0020).
func TestAMappedRangeAvoidsTheOrganisationsAddressPools(t *testing.T) {
	w := seedMapWorld(t)
	// A pool overlapping the bottom of the block, so the naive lowest-free answer is wrong.
	if _, err := w.s.pool.Exec(w.ctx,
		`INSERT INTO address_pools (network_id,prefix,family,purpose) VALUES ($1,$2,4,'device')`,
		w.netA, "100.71.0.0/20"); err != nil {
		t.Fatal(err)
	}
	w.join(t, w.device, w.netA, "meshp0", "a", "192.168.1.0/24")
	w.join(t, w.device, w.netB, "meshp1", "b", "192.168.1.0/24")

	pool := netip.MustParsePrefix("100.71.0.0/20")
	for _, m := range w.ensure(t) {
		if pool.Overlaps(m.Mapped) {
			t.Errorf("%v was allocated on top of a network's own addresses", m.Mapped)
		}
	}
}

// Two full tunnels are not a mappable collision: a default route contains every address, so
// there is no distinct range to reach it by. Reporting one would be a fault nobody can fix.
func TestTwoEgressGroupsAreNotMapped(t *testing.T) {
	w := seedMapWorld(t)
	w.join(t, w.device, w.netA, "meshp0", "a", "")
	w.join(t, w.device, w.netB, "meshp1", "b", "")
	for _, n := range []uuid.UUID{w.netA, w.netB} {
		if _, err := w.s.pool.Exec(w.ctx,
			`INSERT INTO route_groups (network_id,slug,name,kind) VALUES ($1,'full','Full','egress')`, n); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.ensure(t); len(got) != 0 {
		t.Errorf("mappings = %+v; a default route has nothing to be mapped into", got)
	}
}

// A membership that is not active does not contribute a collision. Spending a range because
// a revoked device once held two networks is an address nobody gets back.
func TestAnInactiveMembershipDoesNotCollide(t *testing.T) {
	w := seedMapWorld(t)
	w.join(t, w.device, w.netA, "meshp0", "a", "192.168.1.0/24")
	w.join(t, w.device, w.netB, "meshp1", "b", "192.168.1.0/24")
	if _, err := w.s.pool.Exec(w.ctx,
		`UPDATE device_network_memberships SET state = 'revoked' WHERE network_id = $1`, w.netB); err != nil {
		t.Fatal(err)
	}

	if got := w.ensure(t); len(got) != 0 {
		t.Errorf("mappings = %+v; only one network is live", got)
	}
}

// A mapped range must not land on a network somebody can genuinely reach.
//
// The block is in CGNAT space, which is fine until a customer uses CGNAT space too — a
// customer already running something built on 100.64.0.0/10 has LANs exactly there. A
// mapped range allocated on top of one shadows a reachable network, and the device cannot
// tell the two apart: both are prefixes it was told to route, and the mapping wins.
//
// RFC 1918 is deliberately not reserved, which the second half of this test holds in place:
// reserving every carried prefix would rule out the whole private space for no gain.
func TestAMappedRangeAvoidsACarriedPrefixInsideTheBlock(t *testing.T) {
	w := seedMapWorld(t)
	w.join(t, w.device, w.netA, "meshp0", "tech", "100.90.0.10/32")
	w.join(t, w.device, w.netB, "meshp1", "tech", "100.90.1.10/32")

	// The collision that needs mapping, in ordinary private space.
	w.carry(t, w.netA, "lan-a", "192.168.1.0/24")
	w.carry(t, w.netB, "lan-b", "192.168.1.0/24")

	// And a third network in the same organisation whose LAN is inside the mapped block.
	// Nothing about it collides; it is simply somewhere a mapped range must not go.
	netC := w.network(t, "customer-c")
	w.carry(t, netC, "lan-c", "100.71.0.0/24")

	for _, mapping := range w.ensure(t) {
		if mapping.Mapped.Overlaps(netip.MustParsePrefix("100.71.0.0/24")) {
			t.Errorf("allocated %s, which lands on a customer LAN that is genuinely reachable",
				mapping.Mapped)
		}
	}
}

// The RFC 1918 half of the same rule: a carried prefix that cannot overlap the block is not
// reserved, so the allocator is not slowly starved by every customer LAN in the deployment.
func TestPrivatePrefixesDoNotNarrowTheBlock(t *testing.T) {
	w := seedMapWorld(t)
	w.join(t, w.device, w.netA, "meshp0", "tech", "100.90.0.10/32")
	w.join(t, w.device, w.netB, "meshp1", "tech", "100.90.1.10/32")
	w.carry(t, w.netA, "lan-a", "192.168.1.0/24")
	w.carry(t, w.netB, "lan-b", "192.168.1.0/24")

	// A third customer carrying a very large private range. If this were reserved, it would
	// take out nothing here — but the query that reserves it would be the wrong shape, and
	// the assertion below is what says the filter is by overlap rather than wholesale.
	netC := w.network(t, "customer-c")
	w.carry(t, netC, "lan-c", "10.0.0.0/8")

	got := w.ensure(t)
	if len(got) == 0 {
		t.Fatal("nothing was allocated for a real collision")
	}
	for _, mapping := range got {
		if !DefaultMappedBlock.Overlaps(mapping.Mapped) {
			t.Errorf("allocated %s, which is outside the block", mapping.Mapped)
		}
	}
}
