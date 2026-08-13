package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/meshpnet/meshp/internal/acl"
)

func (h *harness) putPolicy(body string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPut,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/acl", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) getPolicy() *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/acl", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

const samplePolicy = `{"version":1,"rules":[
  {"src":["tag:laptop"],"dst":["tag:server"],"protocol":"tcp","ports":["22"]}
]}`

// No policy and an empty policy mean opposite things: one permits everything, the other
// permits nothing. An administrator shown {"rules":[]} for a network that has never had a
// policy would believe their network was closed.
func TestANetworkWithNoPolicySaysSo(t *testing.T) {
	h := newHarness(t)
	resp := h.getPolicy()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("returned %d, want 404", resp.StatusCode)
	}
	var out struct{ Error string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error != "no_policy" {
		t.Errorf("error code = %q", out.Error)
	}
}

func TestPublishingAndReadingBackAPolicy(t *testing.T) {
	h := newHarness(t)

	resp := h.putPolicy(samplePolicy)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := json.Marshal(resp.Status)
		t.Fatalf("publish returned %d (%s)", resp.StatusCode, body)
	}
	var published struct {
		Status  string `json:"status"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&published); err != nil {
		t.Fatal(err)
	}
	if published.Status != "published" || published.Version != 1 {
		t.Fatalf("published = %+v", published)
	}

	read := h.getPolicy()
	defer func() { _ = read.Body.Close() }()
	if read.StatusCode != http.StatusOK {
		t.Fatalf("read back returned %d", read.StatusCode)
	}
	var got struct {
		Version  int          `json:"version"`
		Document acl.Document `json:"document"`
	}
	if err := json.NewDecoder(read.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Document.Rules) != 1 {
		t.Fatalf("read back %d rules, want 1", len(got.Document.Rules))
	}
	if got.Document.Rules[0].Ports[0] != "22" {
		t.Errorf("the rule came back changed: %+v", got.Document.Rules[0])
	}
}

// Exactly one policy is in force at a time; the database's unique index says so, and
// publishing has to work with it rather than around it.
func TestPublishingAgainSupersedesTheOldPolicy(t *testing.T) {
	h := newHarness(t)

	first := h.putPolicy(samplePolicy)
	_ = first.Body.Close()
	second := h.putPolicy(`{"version":1,"rules":[{"src":["*"],"dst":["*"]}]}`)
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("republish returned %d", second.StatusCode)
	}

	var out struct {
		Version int `json:"version"`
	}
	_ = json.NewDecoder(second.Body).Decode(&out)
	if out.Version != 2 {
		t.Errorf("second publication is version %d, want 2", out.Version)
	}

	var active int
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT count(*) FROM acl_policies WHERE network_id = $1 AND is_active`, h.netID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("%d policies are active, want exactly 1", active)
	}
}

// The author gets the reason verbatim. This is the one place a detailed error is the whole
// value: the caller holds this network's admin token, and "rule 0: names ports with
// protocol icmp" is the difference between fixing a policy and guessing at it.
func TestAnInvalidPolicyIsRefusedWithItsReason(t *testing.T) {
	h := newHarness(t)
	resp := h.putPolicy(`{"version":1,"rules":[
	  {"src":["*"],"dst":["*"],"protocol":"icmp","ports":["22"]}
	]}`)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("returned %d, want 400", resp.StatusCode)
	}
	var out struct{ Error, Message string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error != "invalid_policy" {
		t.Errorf("error code = %q", out.Error)
	}
	if !bytes.Contains([]byte(out.Message), []byte("ports")) {
		t.Errorf("message does not say what was wrong: %q", out.Message)
	}

	// And nothing was stored.
	read := h.getPolicy()
	defer func() { _ = read.Body.Close() }()
	if read.StatusCode != http.StatusNotFound {
		t.Error("a refused policy was stored anyway")
	}
}

// Publishing a policy is how a network is closed. Anyone who could do it unauthenticated
// could also open it.
func TestPublishingNeedsAdmin(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPut,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/acl", bytes.NewReader([]byte(samplePolicy)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an unauthenticated publish returned %d", resp.StatusCode)
	}
}

// A policy is meant to be diffed and rolled back, which needs the documents and not only
// the version numbers.
func TestEveryPublishedVersionIsKept(t *testing.T) {
	h := newHarness(t)
	_ = h.putPolicy(samplePolicy).Body.Close()
	_ = h.putPolicy(`{"version":1,"rules":[{"src":["*"],"dst":["*"]}]}`).Body.Close()

	req, _ := http.NewRequest(http.MethodGet,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/acl/versions", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out struct {
		Policies []struct {
			Version  int             `json:"version"`
			Active   bool            `json:"active"`
			Document json.RawMessage `json:"document"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) != 2 {
		t.Fatalf("%d versions kept, want 2", len(out.Policies))
	}
	if out.Policies[0].Version != 2 || !out.Policies[0].Active {
		t.Errorf("newest first and active: got %+v", out.Policies[0])
	}
	if out.Policies[1].Active {
		t.Error("a superseded policy is still marked active")
	}
	if len(out.Policies[1].Document) == 0 {
		t.Error("a stored document came back empty; it cannot be diffed or rolled back")
	}
}

// Publishing has to log a state change, or the policy reaches nobody until something
// unrelated bumps the version.
func TestPublishingRecordsAStateChange(t *testing.T) {
	h := newHarness(t)

	var before int64
	_ = h.store.Pool().QueryRow(h.ctx,
		`SELECT state_version FROM networks WHERE id = $1`, h.netID).Scan(&before)

	_ = h.putPolicy(samplePolicy).Body.Close()

	var after int64
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT state_version FROM networks WHERE id = $1`, h.netID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("state version did not move: %d -> %d", before, after)
	}

	var kind string
	var membershipID, peerKey *string
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT kind, membership_id::text, peer_public_key FROM state_changes
		 WHERE network_id = $1 ORDER BY version DESC LIMIT 1`, h.netID).
		Scan(&kind, &membershipID, &peerKey); err != nil {
		t.Fatal(err)
	}
	if kind != "policy" {
		t.Errorf("recorded a %q change, want policy", kind)
	}
	// It names no peer, because it is about all of them at once.
	if membershipID != nil || peerKey != nil {
		t.Errorf("a policy change named a peer: membership=%v key=%v", membershipID, peerKey)
	}
}
