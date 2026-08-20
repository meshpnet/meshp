package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/sessionclient"
)

// overview is the shape of the endpoint's response, as a consumer would read it.
//
// Decoded into a struct rather than a map so that a field being renamed breaks this test.
// The commercial layer builds its roll-up on this response (ADR-0009), so its shape is a
// contract with somebody who cannot be asked to change.
type overview struct {
	AsOf    time.Time `json:"as_of"`
	Network struct {
		ID           string `json:"id"`
		Slug         string `json:"slug"`
		StateVersion int64  `json:"state_version"`
	} `json:"network"`
	Devices []struct {
		MembershipID        string   `json:"membership_id"`
		DeviceName          string   `json:"device_name"`
		Connected           bool     `json:"connected"`
		AppliedVersion      int64    `json:"applied_version"`
		UnappliedComponents []string `json:"unapplied_components"`
		LastError           string   `json:"last_error"`
	} `json:"devices"`
	DevicesTruncated bool `json:"devices_truncated"`
	RouteGroups      []struct {
		Slug        string   `json:"slug"`
		Prefixes    []string `json:"prefixes"`
		Advertisers []struct {
			DeviceName string `json:"device_name"`
			Health     string `json:"health"`
			Connected  bool   `json:"connected"`
		} `json:"advertisers"`
	} `json:"route_groups"`
	PollAfterSeconds int `json:"poll_after_seconds"`
}

func (h *harness) overview(query string) overview {
	h.t.Helper()
	resp := h.get(h.netPath("/overview" + query))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("the overview returned %d", resp.StatusCode)
	}
	var out overview
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.t.Fatalf("decoding the overview: %v", err)
	}
	return out
}

// A device with a live control session reads as connected, and one without does not.
//
// Through a real agent rather than by reaching into the hub, because the edge this is
// really testing is the one ADR-0018 is about: the handler takes presence from the session
// server's hub, and nothing else in the package would notice if that assignment vanished.
func TestOverviewReportsWhoIsConnected(t *testing.T) {
	h := newHarness(t)

	// Enrolled here rather than through h.enrol, because driving a real agent needs the
	// identity key and the helper does not hand it back.
	identity, wg := newDevice(t)
	joined, err := enrollclient.New(h.server.URL, nil).Join(h.ctx, enrollclient.JoinRequest{
		Token: h.mintToken(1, time.Hour), Identity: identity, WireGuard: wg,
		Name: "connected-laptop", OS: "linux", AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("the laptop could not join: %v", err)
	}
	connectedID := joined.MembershipID.String()
	offlineID := h.enrol("offline-nas").MembershipID.String()

	agentCtx, stopAgent := context.WithCancel(h.ctx)
	defer stopAgent()
	client := sessionclient.New(sessionclient.Options{
		ControlURL:   h.server.URL,
		Identity:     identity,
		MembershipID: joined.MembershipID,
		AgentVersion: "test",
	})
	rec := newRecorder()
	go func() { _ = client.Run(agentCtx, rec) }()

	// One peer: the other device. Waiting on this rather than on a timer means the session
	// is established before the overview is asked, without guessing how long that takes.
	rec.waitForPeers(t, 1, 10*time.Second)

	got := h.overview("")
	if len(got.Devices) != 2 {
		t.Fatalf("the overview carries %d devices, want 2", len(got.Devices))
	}
	byID := map[string]bool{}
	for _, d := range got.Devices {
		byID[d.MembershipID] = d.Connected
	}
	if !byID[connectedID] {
		t.Error("the device with a live session reads as disconnected")
	}
	if byID[offlineID] {
		t.Error("a device that never opened a session reads as connected")
	}

	if got.Network.Slug != "hq" {
		t.Errorf("network slug = %q, want hq", got.Network.Slug)
	}
	if got.AsOf.IsZero() {
		t.Error("as_of is missing, so a stale page cannot be seen to be stale")
	}
	if got.PollAfterSeconds <= 0 {
		t.Errorf("poll_after_seconds = %d, want a positive interval", got.PollAfterSeconds)
	}
}

// What a device could not apply reaches the page. It has been written on every
// acknowledgement since the first migration and read by nothing.
func TestOverviewSurfacesWhatADeviceCouldNotApply(t *testing.T) {
	h := newHarness(t)
	membershipID := h.enrol("cannot-filter").MembershipID

	if _, err := h.store.Pool().Exec(h.ctx,
		`INSERT INTO membership_state (membership_id, network_id, applied_version, unapplied_components, last_error)
		 VALUES ($1, $2, 7, ARRAY['policy','forwarding'], 'nftables is not available here')
		 ON CONFLICT (membership_id) DO UPDATE
		 SET applied_version = 7,
		     unapplied_components = ARRAY['policy','forwarding'],
		     last_error = 'nftables is not available here'`,
		membershipID, h.netID); err != nil {
		t.Fatal(err)
	}

	got := h.overview("")
	if len(got.Devices) != 1 {
		t.Fatalf("the overview carries %d devices, want 1", len(got.Devices))
	}
	device := got.Devices[0]
	if len(device.UnappliedComponents) != 2 {
		t.Fatalf("unapplied_components = %v, want two entries", device.UnappliedComponents)
	}
	if device.AppliedVersion != 7 {
		t.Errorf("applied_version = %d, want 7", device.AppliedVersion)
	}
	if device.LastError == "" {
		t.Error("last_error is missing, so the reason is only in the device's own log")
	}
}

// A device that has never acknowledged anything still appears, with an empty list rather
// than a missing field.
func TestOverviewCarriesADeviceWithNoStateRow(t *testing.T) {
	h := newHarness(t)
	h.enrol("never-connected")

	got := h.overview("")
	if len(got.Devices) != 1 {
		t.Fatalf("the overview carries %d devices, want 1", len(got.Devices))
	}
	if got.Devices[0].UnappliedComponents == nil {
		t.Error("unapplied_components is null; a consumer must not have to tell absent from empty")
	}
	if got.Devices[0].AppliedVersion != 0 {
		t.Errorf("applied_version = %d, want 0", got.Devices[0].AppliedVersion)
	}
}

// An advertiser nobody has reported on is unknown, not healthy. Rendering it as healthy
// would make a route group that has never worked look fine.
func TestOverviewCarriesRouteGroupsAndUnreportedHealth(t *testing.T) {
	h := newHarness(t)
	membershipID := h.enrol("branch-gateway").MembershipID.String()

	resp := h.post(h.netPath("/route-groups"),
		`{"slug":"branch-lan","name":"Branch LAN","kind":"subnet","prefixes":["192.168.10.0/24"]}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the group returned %d", resp.StatusCode)
	}
	resp = h.post(h.netPath("/route-groups/branch-lan/advertisers"),
		`{"membership_id":"`+membershipID+`","priority":10}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("advertising returned %d", resp.StatusCode)
	}

	got := h.overview("")
	if len(got.RouteGroups) != 1 {
		t.Fatalf("the overview carries %d route groups, want 1", len(got.RouteGroups))
	}
	group := got.RouteGroups[0]
	if group.Slug != "branch-lan" {
		t.Errorf("slug = %q, want branch-lan", group.Slug)
	}
	if len(group.Prefixes) != 1 || group.Prefixes[0] != "192.168.10.0/24" {
		t.Errorf("prefixes = %v, want [192.168.10.0/24]", group.Prefixes)
	}
	if len(group.Advertisers) != 1 {
		t.Fatalf("the group has %d advertisers, want 1", len(group.Advertisers))
	}
	if got, want := group.Advertisers[0].Health, "unknown"; got != want {
		t.Errorf("health = %q, want %q — nobody has reported on this advertiser", got, want)
	}
	if group.Advertisers[0].DeviceName != "branch-gateway" {
		t.Errorf("advertiser device_name = %q, want branch-gateway", group.Advertisers[0].DeviceName)
	}
}

// A response that could not carry every device says so rather than returning a short list.
func TestOverviewMarksATruncatedDeviceList(t *testing.T) {
	h := newHarness(t)
	h.enrol("one")
	h.enrol("two")
	h.enrol("three")

	full := h.overview("")
	if full.DevicesTruncated {
		t.Error("a complete list is marked truncated")
	}
	if len(full.Devices) != 3 {
		t.Fatalf("the overview carries %d devices, want 3", len(full.Devices))
	}

	cut := h.overview("?devices=2")
	if !cut.DevicesTruncated {
		t.Error("a list that was cut is not marked truncated, which reads as a complete network")
	}
	if len(cut.Devices) != 2 {
		t.Errorf("the overview carries %d devices, want the 2 that were asked for", len(cut.Devices))
	}
}

// Listing networks exists so the page is reachable without pasting a UUID.
func TestListingNetworks(t *testing.T) {
	h := newHarness(t)
	h.enrol("a-device")

	resp := h.get("/api/v1/networks")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing networks returned %d", resp.StatusCode)
	}
	var out struct {
		Networks []struct {
			ID                string `json:"id"`
			Slug              string `json:"slug"`
			OrganizationSlug  string `json:"organization_slug"`
			ActiveDeviceCount int64  `json:"active_device_count"`
		} `json:"networks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Networks) != 1 {
		t.Fatalf("listed %d networks, want 1", len(out.Networks))
	}
	if out.Networks[0].Slug != "hq" || out.Networks[0].OrganizationSlug != "acme" {
		t.Errorf("listed %s/%s, want acme/hq",
			out.Networks[0].OrganizationSlug, out.Networks[0].Slug)
	}
	if out.Networks[0].ActiveDeviceCount != 1 {
		t.Errorf("active_device_count = %d, want 1", out.Networks[0].ActiveDeviceCount)
	}
}

// The read endpoints are behind the same token as everything else. A view that could be
// read without one would publish a network's whole topology to anybody who found the port.
func TestOverviewNeedsTheAdminToken(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{h.netPath("/overview"), "/api/v1/networks"} {
		req, _ := http.NewRequest(http.MethodGet, h.server.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a token returned %d, want 401", path, resp.StatusCode)
		}
	}
}

// A network that does not exist is a 404 rather than an empty overview, which would read
// as a real network with nothing in it.
func TestOverviewOfAnUnknownNetwork(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/api/v1/networks/6f4d3c2b-1a09-4f8e-9d7c-6b5a4f3e2d1c/overview")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("returned %d, want 404", resp.StatusCode)
	}
}
