package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// groupFailover is a group's policy as the API reports it.
type groupFailover struct {
	status           int
	Enabled          bool   `json:"enabled"`
	FailThreshold    uint32 `json:"fail_threshold"`
	RecoverThreshold uint32 `json:"recover_threshold"`
	MinHoldSeconds   uint32 `json:"min_hold_seconds"`
}

// setFailover puts a policy and reports what came back.
func (h *harness) setFailover(slug, body string) groupFailover {
	h.t.Helper()
	req := mustRequest(h.t, http.MethodPut,
		h.server.URL+h.netPath("/route-groups/"+slug+"/failover"), body)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	out := groupFailover{status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		return out
	}
	var wrapper struct {
		LocalFailover groupFailover `json:"local_failover"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		h.t.Fatal(err)
	}
	wrapper.LocalFailover.status = resp.StatusCode
	return wrapper.LocalFailover
}

// readFailover reads one group's policy back out of the list.
func (h *harness) readFailover(slug string) groupFailover {
	h.t.Helper()
	req := mustRequest(h.t, http.MethodGet, h.server.URL+h.netPath("/route-groups"), "")
	req.Header.Set("Authorization", "Bearer "+testAdminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out struct {
		RouteGroups []struct {
			Slug          string        `json:"slug"`
			LocalFailover groupFailover `json:"local_failover"`
		} `json:"route_groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.t.Fatal(err)
	}
	for _, g := range out.RouteGroups {
		if g.Slug == slug {
			g.LocalFailover.status = resp.StatusCode
			return g.LocalFailover
		}
	}
	h.t.Fatalf("no group %q in the listing", slug)
	return groupFailover{}
}

func (h *harness) branchGroup(t *testing.T, body string) {
	t.Helper()
	resp := h.post(h.netPath("/route-groups"), body)
	status := resp.StatusCode
	_ = resp.Body.Close()
	if status != http.StatusCreated {
		t.Fatalf("creating the group returned %d", status)
	}
}

// A group created without a policy may move itself, and says so when read back.
func TestANewGroupMayMoveItself(t *testing.T) {
	h := newHarness(t)
	h.branchGroup(t, `{"slug":"branch","kind":"subnet","prefixes":["192.168.10.0/24"]}`)

	got := h.readFailover("branch")
	if !got.Enabled {
		t.Error("a group nobody configured reports that its devices may not move themselves")
	}
	// Unset rather than the agent's defaults. An operator reading this needs to know what is
	// written down; showing 3 where nothing is stored makes an unset field look chosen.
	if got.FailThreshold != 0 || got.RecoverThreshold != 0 || got.MinHoldSeconds != 0 {
		t.Errorf("an unconfigured group reports thresholds: %+v", got)
	}
}

func TestSettingAPolicyOnCreation(t *testing.T) {
	h := newHarness(t)
	h.branchGroup(t, `{"slug":"branch","kind":"subnet","prefixes":["192.168.10.0/24"],
		"local_failover":{"enabled":true,"fail_threshold":2,"recover_threshold":20,"min_hold_seconds":300}}`)

	got := h.readFailover("branch")
	if !got.Enabled || got.FailThreshold != 2 || got.RecoverThreshold != 20 || got.MinHoldSeconds != 300 {
		t.Errorf("read back %+v", got)
	}
}

func TestChangingAPolicyLater(t *testing.T) {
	h := newHarness(t)
	h.branchGroup(t, `{"slug":"branch","kind":"subnet","prefixes":["192.168.10.0/24"]}`)

	got := h.setFailover("branch", `{"enabled":false,"fail_threshold":2,"recover_threshold":20}`)
	if got.status != http.StatusOK {
		t.Fatalf("returned %d", got.status)
	}
	if got.Enabled {
		t.Error("the opt-out did not take")
	}
	if again := h.readFailover("branch"); again.Enabled || again.FailThreshold != 2 {
		t.Errorf("read back %+v", again)
	}
}

// A PUT replaces the whole policy. The numbers only mean anything together, so a field left
// out goes back to its default rather than keeping whatever was there — otherwise an operator
// ends up with a fail threshold from today beside a recover threshold from last month.
func TestAPolicyIsReplacedWhole(t *testing.T) {
	h := newHarness(t)
	h.branchGroup(t, `{"slug":"branch","kind":"subnet","prefixes":["192.168.10.0/24"]}`)

	h.setFailover("branch", `{"enabled":true,"fail_threshold":2,"recover_threshold":20,"min_hold_seconds":300}`)
	h.setFailover("branch", `{"enabled":true,"fail_threshold":5}`)

	got := h.readFailover("branch")
	if got.FailThreshold != 5 {
		t.Errorf("fail_threshold = %d, want 5", got.FailThreshold)
	}
	if got.RecoverThreshold != 0 || got.MinHoldSeconds != 0 {
		t.Errorf("fields left out of the replacement survived it: %+v", got)
	}
}

// Omitting `enabled` means the default rather than false. False is the setting that stops a
// device leaving a dead advertiser, and a body that never mentioned it must not turn it on.
func TestOmittingEnabledDoesNotDisableFailover(t *testing.T) {
	h := newHarness(t)
	h.branchGroup(t, `{"slug":"branch","kind":"subnet","prefixes":["192.168.10.0/24"]}`)

	if got := h.setFailover("branch", `{"fail_threshold":2}`); !got.Enabled {
		t.Error("a policy that did not mention enabled turned local failover off")
	}
	if got := h.readFailover("branch"); !got.Enabled {
		t.Error("and it stuck")
	}
}

// A policy that would make a device oscillate is refused, and refused before it is stored.
func TestABackwardsPolicyIsRefusedByTheAPI(t *testing.T) {
	h := newHarness(t)
	h.branchGroup(t, `{"slug":"branch","kind":"subnet","prefixes":["192.168.10.0/24"]}`)

	for _, body := range []string{
		`{"enabled":true,"fail_threshold":5,"recover_threshold":2}`,
		`{"enabled":true,"fail_threshold":9999}`,
		`{"enabled":true,"min_hold_seconds":100000000}`,
		`{"enabled":true,"fail_treshold":2}`, // a typo, refused rather than ignored
	} {
		if got := h.setFailover("branch", body); got.status == http.StatusOK {
			t.Errorf("%s was accepted", body)
		}
	}
	if got := h.readFailover("branch"); got.FailThreshold != 0 {
		t.Errorf("a refused policy was stored anyway: %+v", got)
	}
}

// A group that is not in this network is a 404, so a typo in a slug does not look like a
// fleet that has been reconfigured.
func TestSettingAPolicyOnAnUnknownGroupIsNotFound(t *testing.T) {
	h := newHarness(t)

	if got := h.setFailover("nope", `{"enabled":true}`); got.status != http.StatusNotFound {
		t.Errorf("returned %d, want 404", got.status)
	}
}

// How patient a device is about moving decides how long a customer's traffic is broken, so
// it is not something an unauthenticated caller may change.
func TestFailoverNeedsTheAdminToken(t *testing.T) {
	h := newHarness(t)
	h.branchGroup(t, `{"slug":"branch","kind":"subnet","prefixes":["192.168.10.0/24"]}`)

	req, err := http.NewRequest(http.MethodPut,
		h.server.URL+h.netPath("/route-groups/branch/failover"),
		bytes.NewReader([]byte(`{"enabled":false}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	status := resp.StatusCode
	_ = resp.Body.Close()
	if status != http.StatusUnauthorized {
		t.Errorf("an unauthenticated caller got %d", status)
	}
}
