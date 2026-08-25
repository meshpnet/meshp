package api

import (
	"net/http"
	"testing"
)

// A device connected to one replica shows as connected on the other.
//
// The whole of the presence half of #145. Before this, a control plane reported the devices
// attached to *itself* and called every other one disconnected — so on a two-replica
// deployment roughly half the devices in the overview were wrong, and an MSP asking "is this
// customer's device online" got a different answer depending on which replica answered.
//
// Simulated rather than orchestrated: standing a second httptest server up would give a
// second hub but the same process, and what is being tested is precisely what happens when
// the hub does *not* know about a session that the database does. So the database is put
// into the state another replica would leave it in, and this replica — whose hub is empty —
// is asked.
func TestADeviceHeldByAnotherReplicaReadsAsConnected(t *testing.T) {
	h := newHarness(t)
	res := h.enrol("held-elsewhere")

	// Before: no session anywhere, so it reads as disconnected. Establishes that the
	// assertion below is about the change rather than about a default.
	if connected := overviewConnected(t, h, res.MembershipID.String()); connected {
		t.Fatal("a device with no session anywhere reads as connected")
	}

	// What the replica next door writes when a device opens a control channel with it.
	// This process's hub knows nothing about it.
	if _, err := h.store.Pool().Exec(h.ctx,
		`UPDATE membership_state
		 SET connected_since = now(), control_session_id = 'a-session-on-another-replica'
		 WHERE membership_id = $1`, res.MembershipID); err != nil {
		t.Fatal(err)
	}

	if connected := overviewConnected(t, h, res.MembershipID.String()); !connected {
		t.Error("a device connected to another replica reads as disconnected")
	}
}

// And it says the detail is somebody else's, rather than implying the device has gone quiet.
//
// A device attached to the replica next door for an hour and one that has never said
// anything both have no tunnel data here. Rendering them the same way is how an operator is
// sent to investigate a device that is working.
func TestTheOverviewSaysWhenTheDetailIsAnotherReplicas(t *testing.T) {
	h := newHarness(t)
	res := h.enrol("held-elsewhere")

	if _, err := h.store.Pool().Exec(h.ctx,
		`UPDATE membership_state
		 SET connected_since = now(), control_session_id = 'a-session-on-another-replica'
		 WHERE membership_id = $1`, res.MembershipID); err != nil {
		t.Fatal(err)
	}

	device := overviewDevice(t, h, res.MembershipID.String())
	if device["reported_by"] != "another_replica" {
		t.Errorf("reported_by = %v, want another_replica", device["reported_by"])
	}
	if _, hasTunnel := device["tunnel"]; hasTunnel {
		t.Error("this replica reported tunnel detail for a session it is not holding")
	}
	// And no fault, which is the failure that would have reached somebody's dashboard.
	if faults, _ := device["faults"].([]any); len(faults) != 0 {
		t.Errorf("faults = %v, want none for a device that is connected and working", faults)
	}
}

// overviewDevice reads one device out of the overview.
func overviewDevice(t *testing.T, h *harness, membershipID string) map[string]any {
	t.Helper()
	status, _, body := doJSON(t, http.MethodGet,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/overview", nil, nil, true)
	if status != http.StatusOK {
		t.Fatalf("overview = %d: %v", status, body)
	}
	devices, _ := body["devices"].([]any)
	for _, raw := range devices {
		device, _ := raw.(map[string]any)
		if device["membership_id"] == membershipID {
			return device
		}
	}
	t.Fatalf("membership %s is not in the overview", membershipID)
	return nil
}

func overviewConnected(t *testing.T, h *harness, membershipID string) bool {
	t.Helper()
	return overviewDevice(t, h, membershipID)["connected"] == true
}
