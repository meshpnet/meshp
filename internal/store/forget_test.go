package store

import (
	"testing"

	"github.com/google/uuid"
)

// forgetActor is a valid actor: WriteAudit refuses a zero one, so every call here needs a
// kind the schema allows and a label somebody could read.
func forgetActor() Actor { return Actor{Kind: "user", Label: "someone@example.com"} }

// forgetFixture seeds a device with one membership, a current key, and the peer_upsert row
// a real enrolment leaves in the change log. That last row is the point: it is what made a
// hard delete impossible before migration 0017, so a fixture without it would pass against
// the schema this feature had to change.
func forgetFixture(t *testing.T, s *Store) (orgID, networkID, deviceID, membershipID uuid.UUID) {
	t.Helper()
	ctx := testContext(t)

	orgID, networkID = insertOrgAndNetwork(t, s)

	err := s.pool.QueryRow(ctx,
		`INSERT INTO devices (organization_id, name, identity_public_key)
		 VALUES ($1, 'laptop', '\x0102') RETURNING id`, orgID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("inserting device: %v", err)
	}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO device_network_memberships (device_id, network_id, interface_name, dns_label)
		 VALUES ($1, $2, 'meshp0', 'laptop') RETURNING id`, deviceID, networkID).Scan(&membershipID)
	if err != nil {
		t.Fatalf("inserting membership: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO wireguard_keys (membership_id, public_key, state)
		 VALUES ($1, 'laptop-key', 'current')`, membershipID); err != nil {
		t.Fatalf("inserting key: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO state_changes (network_id, version, kind, membership_id)
		 VALUES ($1, 1, 'peer_upsert', $2)`, networkID, membershipID); err != nil {
		t.Fatalf("inserting the enrolment's change row: %v", err)
	}
	return orgID, networkID, deviceID, membershipID
}

func countRows(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(testContext(t), query, args...).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	return n
}

func TestForgetDeviceRemovesTheDeviceAndItsMemberships(t *testing.T) {
	s := freshStore(t)
	orgID, _, deviceID, membershipID := forgetFixture(t, s)

	forgotten, err := s.ForgetDevice(testContext(t), ForgetRequest{
		OrganizationID: orgID,
		DeviceID:       deviceID,
		Actor:          forgetActor(),
	})
	if err != nil {
		t.Fatalf("forgetting: %v", err)
	}

	if forgotten.Name != "laptop" {
		t.Errorf("name = %q, want laptop", forgotten.Name)
	}
	if got := len(forgotten.Keys); got != 1 || forgotten.Keys[0] != "laptop-key" {
		t.Errorf("keys = %v, want [laptop-key]", forgotten.Keys)
	}

	if n := countRows(t, s, `SELECT count(*) FROM devices WHERE id = $1`, deviceID); n != 0 {
		t.Errorf("device rows = %d, want 0", n)
	}
	if n := countRows(t, s,
		`SELECT count(*) FROM device_network_memberships WHERE id = $1`, membershipID); n != 0 {
		t.Errorf("membership rows = %d, want 0", n)
	}
	if n := countRows(t, s,
		`SELECT count(*) FROM wireguard_keys WHERE membership_id = $1`, membershipID); n != 0 {
		t.Errorf("key rows = %d, want 0", n)
	}
}

// The removal has to outlive the thing it removes. Before 0017 this delete could not happen
// at all; the risk afterwards is the opposite one — cascading away the very row that tells
// everybody else to drop the key.
func TestForgetDeviceLeavesThePeerRemovalBehind(t *testing.T) {
	s := freshStore(t)
	orgID, networkID, deviceID, membershipID := forgetFixture(t, s)

	if _, err := s.ForgetDevice(testContext(t), ForgetRequest{
		OrganizationID: orgID, DeviceID: deviceID, Actor: forgetActor(),
	}); err != nil {
		t.Fatalf("forgetting: %v", err)
	}

	if n := countRows(t, s,
		`SELECT count(*) FROM state_changes
		 WHERE network_id = $1 AND kind = 'peer_remove' AND peer_public_key = 'laptop-key'`,
		networkID); n != 1 {
		t.Errorf("peer_remove rows naming the key = %d, want 1", n)
	}

	// And the enrolment's own row is gone, because a peer_upsert pointing at a membership
	// that no longer exists tells an agent to go and read nothing.
	if n := countRows(t, s,
		`SELECT count(*) FROM state_changes WHERE kind = 'peer_upsert' AND membership_id = $1`,
		membershipID); n != 0 {
		t.Errorf("stale peer_upsert rows = %d, want 0", n)
	}
}

// Removing an advertiser changes where every other device sends traffic. A delete that took
// a gateway away silently is the failure #206 fixed for route groups.
func TestForgetDeviceRecomputesRoutesWhenItCarriedAPrefix(t *testing.T) {
	s := freshStore(t)
	ctx := testContext(t)
	orgID, networkID, deviceID, membershipID := forgetFixture(t, s)

	var groupID uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO route_groups (network_id, slug, name, kind)
		 VALUES ($1, 'branch', 'Branch', 'subnet') RETURNING id`, networkID).Scan(&groupID)
	if err != nil {
		t.Fatalf("inserting route group: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO route_advertisers (route_group_id, membership_id) VALUES ($1, $2)`,
		groupID, membershipID); err != nil {
		t.Fatalf("inserting advertiser: %v", err)
	}

	if _, err := s.ForgetDevice(ctx, ForgetRequest{
		OrganizationID: orgID, DeviceID: deviceID, Actor: forgetActor(),
	}); err != nil {
		t.Fatalf("forgetting: %v", err)
	}

	// The kind directly rather than a net count: the cascade deletes the fixture's own
	// peer_upsert at the same time, so counting rows before and against after understates
	// what was added and would pass whether or not the routes were recomputed.
	if n := countRows(t, s,
		`SELECT count(*) FROM state_changes WHERE network_id = $1 AND kind = 'routes'`,
		networkID); n < 1 {
		t.Errorf("routes change rows = %d, want at least 1", n)
	}
	if n := countRows(t, s,
		`SELECT count(*) FROM state_changes
		 WHERE network_id = $1 AND kind = 'peer_remove' AND peer_public_key = 'laptop-key'`,
		networkID); n != 1 {
		t.Errorf("peer_remove rows = %d, want 1", n)
	}
	if n := countRows(t, s,
		`SELECT count(*) FROM route_advertisers WHERE membership_id = $1`, membershipID); n != 0 {
		t.Errorf("advertiser rows = %d, want 0", n)
	}
}

// The counterpart: a device that carried nothing must not make every other device in the
// network recompute its routes. Without this, the cheap path and the expensive one are
// indistinguishable and the `advertises` check could be deleted with every test still green.
func TestForgetDeviceDoesNotRecomputeRoutesWhenItCarriedNothing(t *testing.T) {
	s := freshStore(t)
	orgID, networkID, deviceID, _ := forgetFixture(t, s)

	before := countRows(t, s,
		`SELECT count(*) FROM state_changes WHERE network_id = $1`, networkID)

	if _, err := s.ForgetDevice(testContext(t), ForgetRequest{
		OrganizationID: orgID, DeviceID: deviceID, Actor: forgetActor(),
	}); err != nil {
		t.Fatalf("forgetting: %v", err)
	}

	if n := countRows(t, s,
		`SELECT count(*) FROM state_changes WHERE network_id = $1 AND kind = 'peer_remove'`,
		networkID); n != 1 {
		t.Errorf("peer_remove rows = %d, want 1", n)
	}
	// The assertion that gives the `advertises` check a reason to exist: delete that
	// branch and this network gets a routes recomputation it did not need.
	if n := countRows(t, s,
		`SELECT count(*) FROM state_changes WHERE network_id = $1 AND kind = 'routes'`,
		networkID); n != 0 {
		t.Errorf("routes change rows = %d, want 0 — it carried nothing", n)
	}
	_ = before
}

// Every affected network's trail records it, because the only reader is per network.
func TestForgetDeviceIsAuditedInTheNetworkItAffected(t *testing.T) {
	s := freshStore(t)
	orgID, networkID, deviceID, _ := forgetFixture(t, s)

	if _, err := s.ForgetDevice(testContext(t), ForgetRequest{
		OrganizationID: orgID, DeviceID: deviceID, Actor: forgetActor(),
	}); err != nil {
		t.Fatalf("forgetting: %v", err)
	}

	if n := countRows(t, s,
		`SELECT count(*) FROM audit_events
		 WHERE network_id = $1 AND action = 'device.forgotten'`, networkID); n != 1 {
		t.Errorf("audit rows in the network's trail = %d, want 1", n)
	}
}

// A device id from another tenant must not be erasable by whoever can guess one.
func TestForgetDeviceRefusesADeviceInAnotherOrganisation(t *testing.T) {
	s := freshStore(t)
	_, _, deviceID, _ := forgetFixture(t, s)

	var otherOrg uuid.UUID
	if err := s.pool.QueryRow(testContext(t),
		`INSERT INTO organizations (slug, name) VALUES ('other', 'Other') RETURNING id`,
	).Scan(&otherOrg); err != nil {
		t.Fatalf("inserting the other organization: %v", err)
	}

	_, err := s.ForgetDevice(testContext(t), ForgetRequest{
		OrganizationID: otherOrg, DeviceID: deviceID, Actor: forgetActor(),
	})
	if err == nil {
		t.Fatal("forgetting another organisation's device succeeded")
	}

	if n := countRows(t, s, `SELECT count(*) FROM devices WHERE id = $1`, deviceID); n != 1 {
		t.Errorf("device rows = %d, want 1 — it should still be there", n)
	}

	// And nothing was told anything. The refusal happens after the memberships have been
	// read and their peer removals bumped, so this is the assertion that the transaction
	// really did take those back rather than leaving another tenant's network carrying
	// removals for a device that was never touched.
	if n := countRows(t, s,
		`SELECT count(*) FROM state_changes WHERE kind = 'peer_remove'`); n != 0 {
		t.Errorf("peer_remove rows = %d, want 0 — the refusal must leave no trace", n)
	}
}
