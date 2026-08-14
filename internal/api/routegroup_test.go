package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func (h *harness) post(path, body string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) del(path string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, h.server.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) netPath(suffix string) string {
	return "/api/v1/networks/" + h.netID.String() + suffix
}

// The MSP case: a branch office's LAN carried by a device that sits in it.
func TestCreatingASubnetGroup(t *testing.T) {
	h := newHarness(t)

	resp := h.post(h.netPath("/route-groups"),
		`{"slug":"branch-lan","name":"Branch LAN","kind":"subnet","prefixes":["192.168.10.0/24"]}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("returned %d", resp.StatusCode)
	}

	var out struct {
		Slug     string   `json:"slug"`
		Kind     string   `json:"kind"`
		Prefixes []string `json:"prefixes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Slug != "branch-lan" || out.Kind != "subnet" {
		t.Fatalf("group = %+v", out)
	}
	if len(out.Prefixes) != 1 || out.Prefixes[0] != "192.168.10.0/24" {
		t.Errorf("prefixes = %v", out.Prefixes)
	}
}

// "Send everything through this device" and "send this subnet through this device" are
// different decisions with different blast radii. A group that quietly did both would be
// the more dangerous one wearing the safer one's name.
func TestKindAndPrefixesMustAgree(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct{ name, body string }{
		{"an egress group with prefixes of its own",
			`{"slug":"exit","kind":"egress","prefixes":["192.168.1.0/24"]}`},
		{"a subnet group with no prefixes",
			`{"slug":"nothing","kind":"subnet"}`},
		{"a subnet group carrying the default route",
			`{"slug":"sneaky","kind":"subnet","prefixes":["0.0.0.0/0"]}`},
		{"a kind that is not one of the three",
			`{"slug":"weird","kind":"magic","prefixes":["192.168.1.0/24"]}`},
		{"a slug that is not usable in a URL",
			`{"slug":"Branch LAN","kind":"subnet","prefixes":["192.168.1.0/24"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.post(h.netPath("/route-groups"), tc.body)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode < 400 {
				t.Fatalf("accepted %s (HTTP %d)", tc.name, resp.StatusCode)
			}
		})
	}
}

// An egress group carries the default route and takes no prefixes of its own.
func TestCreatingAnEgressGroup(t *testing.T) {
	h := newHarness(t)
	resp := h.post(h.netPath("/route-groups"),
		`{"slug":"exit","kind":"egress","stable_egress_ip":"203.0.113.7"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("returned %d", resp.StatusCode)
	}
	var out struct {
		StableEgressIP string `json:"stable_egress_ip"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.StableEgressIP != "203.0.113.7" {
		t.Errorf("the stable egress address was lost: %q", out.StableEgressIP)
	}
}

// An advertiser is a role a device plays. Re-advertising with a different priority is an
// edit, not a conflict: an operator adjusting a failover order should not remove first.
func TestAdvertisingAndReadjusting(t *testing.T) {
	h := newHarness(t)
	device := h.enrol("branch-router")
	_ = h.post(h.netPath("/route-groups"),
		`{"slug":"branch-lan","kind":"subnet","prefixes":["192.168.10.0/24"]}`).Body.Close()

	for _, priority := range []int{1, 5} {
		body := `{"membership_id":"` + device.MembershipID.String() + `","priority":` +
			string(rune('0'+priority)) + `}`
		resp := h.post(h.netPath("/route-groups/branch-lan/advertisers"), body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("advertising at priority %d returned %d", priority, resp.StatusCode)
		}
	}

	var priority int32
	var count int
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT count(*), max(priority) FROM route_advertisers`).Scan(&count, &priority); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("%d advertiser rows, want 1 — re-advertising duplicated instead of editing", count)
	}
	if priority != 5 {
		t.Errorf("priority = %d, want the readjusted 5", priority)
	}
}

// Advertising for a group that does not exist must not silently succeed.
func TestAdvertisingForAnUnknownGroup(t *testing.T) {
	h := newHarness(t)
	device := h.enrol("router")
	resp := h.post(h.netPath("/route-groups/nope/advertisers"),
		`{"membership_id":"`+device.MembershipID.String()+`"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("returned %d, want 404", resp.StatusCode)
	}
}

// Every route change is desired state for the whole network, so it has to move the version
// or no agent finds out until something unrelated does.
func TestRouteChangesMoveTheStateVersion(t *testing.T) {
	h := newHarness(t)
	device := h.enrol("router")

	version := func() int64 {
		h.t.Helper()
		var v int64
		if err := h.store.Pool().QueryRow(h.ctx,
			`SELECT state_version FROM networks WHERE id = $1`, h.netID).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	steps := []struct {
		name   string
		do     func() *http.Response
		status int
	}{
		{"creating a group", func() *http.Response {
			return h.post(h.netPath("/route-groups"),
				`{"slug":"branch-lan","kind":"subnet","prefixes":["192.168.10.0/24"]}`)
		}, http.StatusCreated},
		{"advertising", func() *http.Response {
			return h.post(h.netPath("/route-groups/branch-lan/advertisers"),
				`{"membership_id":"`+device.MembershipID.String()+`"}`)
		}, http.StatusOK},
		{"withdrawing", func() *http.Response {
			return h.del(h.netPath("/route-groups/branch-lan/advertisers/" + device.MembershipID.String()))
		}, http.StatusOK},
		{"deleting the group", func() *http.Response {
			return h.del(h.netPath("/route-groups/branch-lan"))
		}, http.StatusOK},
	}

	for _, step := range steps {
		before := version()
		resp := step.do()
		got := resp.StatusCode
		_ = resp.Body.Close()
		if got != step.status {
			t.Fatalf("%s returned %d, want %d", step.name, got, step.status)
		}
		if after := version(); after <= before {
			t.Errorf("%s did not move the state version: %d -> %d", step.name, before, after)
		}
	}

	// And the change names no peer, because it is about every device at once.
	var kind string
	var membershipID, peerKey *string
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT kind, membership_id::text, peer_public_key FROM state_changes
		 WHERE network_id = $1 ORDER BY version DESC LIMIT 1`, h.netID).
		Scan(&kind, &membershipID, &peerKey); err != nil {
		t.Fatal(err)
	}
	if kind != "routes" {
		t.Errorf("recorded a %q change, want routes", kind)
	}
	if membershipID != nil || peerKey != nil {
		t.Errorf("a route change named a peer: %v %v", membershipID, peerKey)
	}
}

// Standing up a network required psql until now, which is fine for us and disqualifying
// for anybody else.
func TestCreatingANetwork(t *testing.T) {
	h := newHarness(t)

	var orgID string
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT id::text FROM organizations LIMIT 1`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}

	resp := h.post("/api/v1/networks",
		`{"organization_id":"`+orgID+`","slug":"branch","name":"Branch",
		  "address_pools":["100.91.0.0/24","fd7c:1::/120"]}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("returned %d", resp.StatusCode)
	}
	var out struct {
		NetworkID string `json:"network_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	var pools int
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT count(*) FROM address_pools WHERE network_id = $1`, out.NetworkID).Scan(&pools); err != nil {
		t.Fatal(err)
	}
	if pools != 2 {
		t.Errorf("%d address pools, want 2", pools)
	}
}

// A network with no pool enrols nobody, and the failure would surface as an enrolment that
// cannot allocate an address rather than as the missing configuration it is.
func TestANetworkNeedsAnAddressPool(t *testing.T) {
	h := newHarness(t)
	var orgID string
	_ = h.store.Pool().QueryRow(h.ctx, `SELECT id::text FROM organizations LIMIT 1`).Scan(&orgID)

	resp := h.post("/api/v1/networks", `{"organization_id":"`+orgID+`","slug":"empty"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("returned %d, want 400", resp.StatusCode)
	}
}

// Creating networks and steering traffic are both things only an administrator may do.
func TestRouteEndpointsNeedAdmin(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/api/v1/networks", h.netPath("/route-groups")} {
		req, _ := http.NewRequest(http.MethodPost, h.server.URL+path, bytes.NewReader([]byte(`{}`)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s answered an unauthenticated caller with %d", path, resp.StatusCode)
		}
	}
}

func (h *harness) get(path string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.server.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// An operator has to be able to see what is steering traffic before changing it.
func TestListingRouteGroupsAndDevices(t *testing.T) {
	h := newHarness(t)
	device := h.enrol("branch-router")
	_ = h.post(h.netPath("/route-groups"),
		`{"slug":"branch-lan","kind":"subnet","prefixes":["192.168.10.0/24"]}`).Body.Close()
	_ = h.post(h.netPath("/route-groups"), `{"slug":"exit","kind":"egress"}`).Body.Close()

	resp := h.get(h.netPath("/route-groups"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("returned %d", resp.StatusCode)
	}
	var groups struct {
		RouteGroups []struct {
			Slug     string   `json:"slug"`
			Kind     string   `json:"kind"`
			Prefixes []string `json:"prefixes"`
		} `json:"route_groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		t.Fatal(err)
	}
	if len(groups.RouteGroups) != 2 {
		t.Fatalf("%d groups listed, want 2", len(groups.RouteGroups))
	}
	// Sorted by slug, so two reads of the same network render the same way.
	if groups.RouteGroups[0].Slug != "branch-lan" || groups.RouteGroups[1].Slug != "exit" {
		t.Errorf("groups came back in an unstable order: %+v", groups.RouteGroups)
	}
	if len(groups.RouteGroups[0].Prefixes) != 1 {
		t.Error("the subnet group lost its prefix")
	}

	// And the device listing, which is how an operator finds the membership to advertise.
	devices := h.get(h.netPath("/devices"))
	defer func() { _ = devices.Body.Close() }()
	if devices.StatusCode != http.StatusOK {
		t.Fatalf("listing devices returned %d", devices.StatusCode)
	}
	var listed struct {
		Devices []struct {
			MembershipID string `json:"membership_id"`
			State        string `json:"state"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(devices.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range listed.Devices {
		if d.MembershipID == device.MembershipID.String() {
			found = true
			if d.State != "active" {
				t.Errorf("the device is listed as %q", d.State)
			}
		}
	}
	if !found {
		t.Error("the enrolled device is not in the listing")
	}
}
