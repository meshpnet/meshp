package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func createRecord(t *testing.T, h *harness, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/dns-records", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	raw, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// The half of ADR-0021 §2 that was never built: a name for something the peer list cannot
// describe. dns_zones and dns_records have been in the schema since the first migration
// with no query touching either.
func TestAnAdministratorCanWriteAName(t *testing.T) {
	h := newHarness(t)

	status, record := createRecord(t, h, map[string]any{
		"name": "git", "type": "A", "value": "10.80.0.30",
	})
	if status != http.StatusCreated {
		t.Fatalf("creating a record = %d: %v", status, record)
	}
	// The name it will actually answer to, assembled here rather than by the caller: the
	// suffix is the server's to decide, and a client building it from two fields gets it
	// wrong once.
	if record["fqdn"] == "" || record["fqdn"] == nil {
		t.Error("the response does not say what the record will answer to")
	}

	req, _ := http.NewRequest(http.MethodGet,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/dns-records", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var listed struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Records) != 1 || listed.Records[0]["name"] != "git" {
		t.Errorf("listed records = %v, want the one just written", listed.Records)
	}
}

// Every refusal names what was typed. "That is not a DNS label" without saying what this
// thinks you sent makes somebody re-read their own request to find out.
func TestARecordThatCannotWorkIsRefused(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		name string
		body map[string]any
		says string
	}{
		{
			name: "a label with a dot in it",
			body: map[string]any{"name": "git.internal", "type": "A", "value": "10.80.0.30"},
			says: "git.internal",
		},
		{
			// In the schema and refused rather than stored. The resolver answers from a
			// flat name-to-address map; an alias would arrive at every device and do
			// nothing.
			name: "a CNAME",
			body: map[string]any{"name": "git", "type": "CNAME", "value": "hq-gateway"},
			says: "CNAME",
		},
		{
			name: "an A record holding an IPv6 address",
			body: map[string]any{"name": "git", "type": "A", "value": "fd7a:115c::1"},
			says: "IPv4",
		},
		{
			name: "a value that is not an address",
			body: map[string]any{"name": "git", "type": "A", "value": "hq-gateway"},
			says: "hq-gateway",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := createRecord(t, h, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%v)", status, body)
			}
			message, _ := body["message"].(string)
			if !bytes.Contains([]byte(message), []byte(tc.says)) {
				t.Errorf("message = %q, want it to name %q", message, tc.says)
			}
		})
	}
}

// The same name twice is a conflict rather than a silent second row.
func TestTheSameRecordTwiceIsRefused(t *testing.T) {
	h := newHarness(t)
	if status, body := createRecord(t, h, map[string]any{
		"name": "git", "type": "A", "value": "10.80.0.30",
	}); status != http.StatusCreated {
		t.Fatalf("first create = %d: %v", status, body)
	}
	status, body := createRecord(t, h, map[string]any{
		"name": "git", "type": "A", "value": "10.80.0.30",
	})
	if status != http.StatusConflict {
		t.Errorf("second create = %d, want 409 (%v)", status, body)
	}
}

// A record may be removed, and removing one that is not there says so rather than
// pretending it worked.
func TestARecordCanBeRemoved(t *testing.T) {
	h := newHarness(t)
	_, record := createRecord(t, h, map[string]any{
		"name": "git", "type": "A", "value": "10.80.0.30",
	})
	id, _ := record["id"].(string)

	del := func(recordID string) int {
		req, _ := http.NewRequest(http.MethodDelete,
			h.server.URL+"/api/v1/networks/"+h.netID.String()+"/dns-records/"+recordID, nil)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if status := del(id); status != http.StatusNoContent {
		t.Errorf("deleting = %d, want 204", status)
	}
	if status := del(id); status != http.StatusNotFound {
		t.Errorf("deleting it again = %d, want 404", status)
	}
}

// Writing needs the administrative token; reading is browser-readable like the rest of a
// network's state (ADR-0022 §5).
func TestWritingARecordNeedsMoreThanABrowserSession(t *testing.T) {
	h := newHarness(t)
	cookie := h.login()

	write := h.withCookie(http.MethodPost, "/api/v1/networks/"+h.netID.String()+"/dns-records", cookie)
	defer func() { _ = write.Body.Close() }()
	if write.StatusCode != http.StatusUnauthorized {
		t.Errorf("a browser session writing a record = %d, want 401", write.StatusCode)
	}

	read := h.withCookie(http.MethodGet, "/api/v1/networks/"+h.netID.String()+"/dns-records", cookie)
	defer func() { _ = read.Body.Close() }()
	if read.StatusCode != http.StatusOK {
		t.Errorf("a browser session reading records = %d, want 200", read.StatusCode)
	}
}
