package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// orgOf reads the organisation the harness's network belongs to, which is what the forget
// route is scoped by.
func (h *harness) orgOf(networkID uuid.UUID) uuid.UUID {
	h.t.Helper()
	network, err := h.store.Queries().GetNetwork(h.ctx, networkID)
	if err != nil {
		h.t.Fatalf("reading the network: %v", err)
	}
	return network.OrganizationID
}

func (h *harness) forget(orgID, deviceID uuid.UUID) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodDelete,
		h.server.URL+"/api/v1/organizations/"+orgID.String()+"/devices/"+deviceID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) countDevices(deviceID uuid.UUID) int {
	h.t.Helper()
	var n int
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT count(*) FROM devices WHERE id = $1`, deviceID).Scan(&n); err != nil {
		h.t.Fatalf("counting devices: %v", err)
	}
	return n
}

// The whole point: after this the device is not listed, not revoked-and-listed. Revocation
// deliberately keeps the row so an administrator can see a device is out, which is the right
// answer to a different question and no answer at all to "take my laptop off this system".
func TestForgettingADeviceRemovesItEntirely(t *testing.T) {
	h := newHarness(t)
	alice := h.enrol("alice")
	bob := h.enrol("bob")
	orgID := h.orgOf(h.netID)

	resp := h.forget(orgID, bob.DeviceID)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if n := h.countDevices(bob.DeviceID); n != 0 {
		t.Errorf("bob's device rows = %d, want 0", n)
	}
	// Alice is untouched, which is the assertion that stops this passing for a handler that
	// deletes everything it can reach.
	if n := h.countDevices(alice.DeviceID); n != 1 {
		t.Errorf("alice's device rows = %d, want 1", n)
	}

	var listed int
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT count(*) FROM device_network_memberships WHERE id = $1`,
		bob.MembershipID).Scan(&listed); err != nil {
		t.Fatal(err)
	}
	if listed != 0 {
		t.Errorf("bob's membership rows = %d, want 0", listed)
	}
}

// Everyone else is told to drop the key. Same enforcement as revocation: the erased device
// is not reached and does not need to be.
func TestForgettingADeviceTellsTheOtherPeers(t *testing.T) {
	h := newHarness(t)
	h.enrol("alice")
	bob := h.enrol("bob")
	orgID := h.orgOf(h.netID)

	resp := h.forget(orgID, bob.DeviceID)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var removals int
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT count(*) FROM state_changes WHERE network_id = $1 AND kind = 'peer_remove'`,
		h.netID).Scan(&removals); err != nil {
		t.Fatal(err)
	}
	if removals != 1 {
		t.Errorf("peer_remove rows = %d, want 1", removals)
	}
}

func TestForgettingADeviceThatIsNotThereIs404(t *testing.T) {
	h := newHarness(t)
	orgID := h.orgOf(h.netID)

	resp := h.forget(orgID, uuid.New())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// An id that exists but belongs to another organisation answers the same way, so the route
// cannot be used to find out which device ids are real.
func TestForgettingADeviceInAnotherOrganisationIs404(t *testing.T) {
	h := newHarness(t)
	bob := h.enrol("bob")

	var otherOrg uuid.UUID
	if err := h.store.Pool().QueryRow(h.ctx,
		`INSERT INTO organizations (slug, name) VALUES ('other', 'Other') RETURNING id`,
	).Scan(&otherOrg); err != nil {
		t.Fatalf("inserting the other organization: %v", err)
	}

	resp := h.forget(otherOrg, bob.DeviceID)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if n := h.countDevices(bob.DeviceID); n != 1 {
		t.Errorf("bob's device rows = %d, want 1 — it is not that organisation's to erase", n)
	}
}
