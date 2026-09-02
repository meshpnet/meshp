package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// testPolicy asks what a device would enforce, given a document or the one in force.
func (h *harness) testPolicy(body string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/acl/test", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// rulesOf pulls one direction out of a compiled filter.
func rulesOf(t *testing.T, body map[string]any, direction string) []any {
	t.Helper()
	filter, ok := body["filter"].(map[string]any)
	if !ok {
		t.Fatalf("no filter in the answer: %v", body)
	}
	rules, _ := filter[direction].([]any)
	return rules
}

// The question the route exists for: a policy is written in selectors and what reaches a
// device is prefixes, and nobody could see the second before publishing the first.
func TestADryRunCompilesAProposedPolicyWithoutPublishingIt(t *testing.T) {
	h := newHarness(t)
	alice := h.enrol("alice")
	h.enrol("bob")

	proposed := `{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocol":"any"}]}`
	status, body := h.testPolicy(`{"device":"alice","document":` + proposed + `}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", status, body)
	}
	if body["device"] != "alice" {
		t.Errorf("device = %v, want alice", body["device"])
	}
	if body["membership_id"] != alice.MembershipID.String() {
		t.Errorf("membership_id = %v, want alice's", body["membership_id"])
	}
	if len(rulesOf(t, body, "inbound")) == 0 {
		t.Error("a permit-everything policy compiled to no inbound rules")
	}

	// And nothing was published: the network still has no policy.
	resp := h.getPolicy()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the dry-run published something: GET /acl = %d, want 404", resp.StatusCode)
	}
}

// Omitting the document asks what a device is enforcing right now.
func TestADryRunWithNoDocumentUsesTheOneInForce(t *testing.T) {
	h := newHarness(t)
	h.enrol("alice")

	resp := h.putPolicy(`{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocol":"any"}]}`)
	_ = resp.Body.Close()

	status, body := h.testPolicy(`{"device":"alice"}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", status, body)
	}
	if len(rulesOf(t, body, "inbound")) == 0 {
		t.Error("the live policy compiled to nothing")
	}
}

func TestADryRunWithNoDocumentAndNoPolicySaysSo(t *testing.T) {
	h := newHarness(t)
	h.enrol("alice")

	status, body := h.testPolicy(`{"device":"alice"}`)
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404: %v", status, body)
	}
	if body["error"] != "no_policy" {
		t.Errorf("error = %v, want no_policy", body["error"])
	}
}

// The reason reaches the author, the same way publishing does. Guessing at why a policy was
// refused is the thing this endpoint exists to stop.
func TestADryRunOnAnInvalidDocumentGivesTheReason(t *testing.T) {
	h := newHarness(t)
	h.enrol("alice")

	status, body := h.testPolicy(`{"device":"alice","document":{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocol":"icmp","ports":["22"]}]}}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %v", status, body)
	}
	if msg, _ := body["message"].(string); msg == "" {
		t.Errorf("no reason given: %v", body)
	}
}

func TestADryRunNeedsADeviceToCompileFor(t *testing.T) {
	h := newHarness(t)
	status, body := h.testPolicy(`{}`)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: %v", status, body)
	}
}

func TestADryRunForADeviceThatIsNotThereIs404(t *testing.T) {
	h := newHarness(t)
	h.enrol("alice")

	status, _ := h.testPolicy(`{"device":"nobody","document":{"version":1,"rules":[]}}`)
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", status)
	}
}

// Compiling for whichever of two devices called "laptop" sorted first would answer a
// question nobody asked.
func TestADryRunRefusesAnAmbiguousName(t *testing.T) {
	h := newHarness(t)
	h.enrol("laptop")
	h.enrol("laptop")

	status, _ := h.testPolicy(`{"device":"laptop","document":{"version":1,"rules":[]}}`)
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an ambiguous name", status)
	}
}

// A device is addressable by its ids as well, which is what a script holds.
func TestADryRunTakesEitherIdAsWellAsAName(t *testing.T) {
	h := newHarness(t)
	alice := h.enrol("alice")

	for _, id := range []string{alice.MembershipID.String(), alice.DeviceID.String()} {
		status, body := h.testPolicy(`{"device":"` + id + `","document":{"version":1,"rules":[]}}`)
		if status != http.StatusOK {
			t.Errorf("device=%s: status = %d, want 200: %v", id, status, body)
		}
	}
}

// The compiled filter says what it denies by default, because an empty rule list means two
// opposite things depending on it.
func TestADryRunSaysWhetherItDeniesByDefault(t *testing.T) {
	h := newHarness(t)
	h.enrol("alice")

	_, body := h.testPolicy(`{"device":"alice","document":{"version":1,"rules":[]}}`)
	if _, ok := body["default_deny"]; !ok {
		t.Errorf("the answer does not say whether it denies by default: %v", body)
	}
}
