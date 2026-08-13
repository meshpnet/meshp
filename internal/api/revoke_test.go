package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// enrol puts a device in the harness's network and returns what the control plane assigned.
func (h *harness) enrol(name string) enrollclient.JoinResult {
	h.t.Helper()
	token := h.mintToken(1, time.Hour)
	id, wg := newDevice(h.t)
	res, err := enrollclient.New(h.server.URL, nil).Join(h.ctx, enrollclient.JoinRequest{
		Token: token, Identity: id, WireGuard: wg,
		Name: name, Hostname: name, OS: "linux", AgentVersion: "test",
	})
	if err != nil {
		h.t.Fatalf("enrolling %s: %v", name, err)
	}
	return res
}

func (h *harness) revoke(networkID, membershipID uuid.UUID, body any) *http.Response {
	h.t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(http.MethodDelete,
		h.server.URL+"/api/v1/networks/"+networkID.String()+"/devices/"+membershipID.String(),
		bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// The point of the whole feature: a revoked device stops being a peer, so everyone else
// is told to drop its key. That removal is the enforcement — nothing depends on reaching
// the revoked device at all.
func TestRevokingADeviceRemovesItAsAPeer(t *testing.T) {
	h := newHarness(t)
	alice := h.enrol("alice")
	bob := h.enrol("bob")

	resp := h.revoke(h.netID, bob.MembershipID, map[string]any{"reason": "sold"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke returned %d", resp.StatusCode)
	}

	var out struct {
		Status             string `json:"status"`
		WireGuardPublicKey string `json:"wireguard_public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "revoked" || out.WireGuardPublicKey == "" {
		t.Fatalf("response = %+v", out)
	}

	// Alice must no longer be told about Bob.
	peers, err := h.store.Queries().ListPeersForMembership(h.ctx, dbgen.ListPeersForMembershipParams{NetworkID: h.netID, ID: alice.MembershipID})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		if p.MembershipID == bob.MembershipID {
			t.Fatal("a revoked device is still offered as a peer")
		}
	}

	// And the removal is in the delta log by key, because by the time an agent asks, the
	// row that held the key may be gone.
	var kind, key string
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT kind, peer_public_key FROM state_changes
		 WHERE network_id = $1 AND kind = 'peer_remove' ORDER BY version DESC LIMIT 1`,
		h.netID).Scan(&kind, &key); err != nil {
		t.Fatalf("no removal was recorded: %v", err)
	}
	if key != out.WireGuardPublicKey {
		t.Errorf("recorded removal of %q, want %q", key, out.WireGuardPublicKey)
	}
}

// Revoking twice is not an error the second time so much as a different answer: there was
// nothing to revoke. Reporting success would tell an administrator they had just removed a
// device that somebody else removed an hour ago.
func TestRevokingTwiceReportsNothingToDo(t *testing.T) {
	h := newHarness(t)
	bob := h.enrol("bob")

	first := h.revoke(h.netID, bob.MembershipID, nil)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first revoke returned %d", first.StatusCode)
	}

	second := h.revoke(h.netID, bob.MembershipID, nil)
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusNotFound {
		t.Errorf("second revoke returned %d, want 404", second.StatusCode)
	}
}

// Scoped by network as well as by id, so an administrator holding one network cannot reach
// into another — and cannot use the endpoint to discover whether an id exists elsewhere.
func TestRevokingFromTheWrongNetworkIsRefused(t *testing.T) {
	h := newHarness(t)
	bob := h.enrol("bob")

	resp := h.revoke(uuid.New(), bob.MembershipID, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("returned %d, want 404", resp.StatusCode)
	}

	// And it really did not happen.
	rows, err := h.store.Queries().ListMembershipsForNetwork(h.ctx, h.netID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.MembershipID == bob.MembershipID && r.State != "active" {
			t.Fatalf("the membership is %s; a foreign network id revoked it", r.State)
		}
	}
}

// Cutting a device out of a network is the most consequential thing here, so it is
// accounted for whether or not anyone was watching.
func TestARevocationIsAudited(t *testing.T) {
	h := newHarness(t)
	bob := h.enrol("bob")

	resp := h.revoke(h.netID, bob.MembershipID, map[string]any{"reason": "laptop stolen"})
	_ = resp.Body.Close()

	var action, metadata string
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT action, metadata::text FROM audit_events
		 WHERE network_id = $1 AND action = 'device.revoked' ORDER BY created_at DESC LIMIT 1`,
		h.netID).Scan(&action, &metadata); err != nil {
		t.Fatalf("no audit event: %v", err)
	}
	if !bytes.Contains([]byte(metadata), []byte("laptop stolen")) {
		t.Errorf("the reason was not recorded: %s", metadata)
	}
}

// An unauthenticated caller must not be able to empty a network.
func TestRevokingNeedsAdmin(t *testing.T) {
	h := newHarness(t)
	bob := h.enrol("bob")

	req, _ := http.NewRequest(http.MethodDelete,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/devices/"+bob.MembershipID.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an unauthenticated revoke returned %d", resp.StatusCode)
	}
}

// Revoked memberships stay listed. A device that silently vanished from the list is
// indistinguishable from one that was never there, and an administrator checking that a
// device is really out needs to see that it is out.
func TestARevokedDeviceIsStillListed(t *testing.T) {
	h := newHarness(t)
	bob := h.enrol("bob")
	resp := h.revoke(h.netID, bob.MembershipID, nil)
	_ = resp.Body.Close()

	rows, err := h.store.Queries().ListMembershipsForNetwork(h.ctx, h.netID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.MembershipID == bob.MembershipID {
			found = true
			if r.State != "revoked" || r.RevokedAt == nil {
				t.Errorf("listed as state=%q revoked_at=%v", r.State, r.RevokedAt)
			}
		}
	}
	if !found {
		t.Error("the revoked device disappeared from the list entirely")
	}
}

// The store reports a missing membership as its own condition rather than a generic error,
// because the caller answers 404 for it and 500 for everything else.
func TestRevokingAnUnknownMembership(t *testing.T) {
	h := newHarness(t)
	_, err := h.store.RevokeMembership(h.ctx, store.RevokeRequest{
		NetworkID:    h.netID,
		MembershipID: uuid.New(),
	})
	if err == nil {
		t.Fatal("revoking a membership that does not exist reported success")
	}
	if !isNotAMember(err) {
		t.Errorf("error = %v, want store.ErrNotAMember", err)
	}
}

func isNotAMember(err error) bool { return errors.Is(err, store.ErrNotAMember) }
