package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func postOrg(t *testing.T, h *harness, body map[string]any, auth bool) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/organizations", bytes.NewReader(raw))
	if auth {
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
	}
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

// The first thing a deployment needs, and the last endpoint to exist. Until now the
// quickstart told people to run psql, which meant standing meshp up required database
// access — for a row with two fields in it.
func TestAnOrganisationCanBeCreatedAndListed(t *testing.T) {
	h := newHarness(t)

	status, created := postOrg(t, h, map[string]any{"slug": "globex", "name": "Globex"}, true)
	if status != http.StatusCreated {
		t.Fatalf("creating = %d: %v", status, created)
	}
	// Named the way network creation names its id, so a caller stringing the two together
	// in a shell does not have to notice they disagree.
	if created["organization_id"] == nil {
		t.Errorf("the response does not carry organization_id: %v", created)
	}

	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var listed struct {
		Organizations []map[string]any `json:"organizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}

	var found map[string]any
	for _, org := range listed.Organizations {
		if org["slug"] == "globex" {
			found = org
		}
	}
	if found == nil {
		t.Fatalf("the new organisation is not listed: %v", listed.Organizations)
	}
	// Zero networks is the shape of an organisation somebody created and did not finish
	// setting up, and telling it apart from a working one should not need a second call.
	if count, _ := found["network_count"].(float64); count != 0 {
		t.Errorf("network_count = %v, want 0 for a fresh organisation", found["network_count"])
	}
}

func TestAnOrganisationThatCannotWorkIsRefused(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		name string
		body map[string]any
		says string
	}{
		{"a slug with a space", map[string]any{"slug": "globex corp", "name": "Globex"}, "globex corp"},
		{"a slug in capitals", map[string]any{"slug": "GLOBEX", "name": "Globex"}, "GLOBEX"},
		// Not defaulted to the slug: a display name and a URL-safe identifier are different
		// things, and quietly making one the other is how everything ends up called "acme"
		// in a list somebody has to read.
		{"no name", map[string]any{"slug": "globex"}, "name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := postOrg(t, h, tc.body, true)
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

func TestTheSameOrganisationTwiceIsRefused(t *testing.T) {
	h := newHarness(t)
	if status, body := postOrg(t, h, map[string]any{"slug": "globex", "name": "Globex"}, true); status != http.StatusCreated {
		t.Fatalf("first create = %d: %v", status, body)
	}
	status, body := postOrg(t, h, map[string]any{"slug": "globex", "name": "Globex Again"}, true)
	if status != http.StatusConflict {
		t.Errorf("second create = %d, want 409 (%v)", status, body)
	}
}

// A signed-in person sees their own organisation and no other, and cannot create one.
//
// This used to assert that the browser's credential reached neither half, because that
// credential was derived from a shared secret and had no identity. It has one now, so the
// interesting question changed: reading is allowed and *scoped*, because knowing which
// organisation you are in is not a privilege — /api/v1/me already answers it — while
// creating a tenant stays deployment administration and needs the token itself.
func TestAPersonSeesTheirOwnOrganisationAndCannotCreateOne(t *testing.T) {
	h := newHarness(t)

	// A second tenant, so "their own" is a real restriction rather than a list of one.
	if status, body := postOrg(t, h, map[string]any{"slug": "globex", "name": "Globex"}, true); status != http.StatusCreated {
		t.Fatalf("creating a second organisation = %d: %v", status, body)
	}

	cookie := h.login()
	status, _, body := doJSONWithCookie(t, h, http.MethodGet, "/api/v1/organizations", cookie)
	if status != http.StatusOK {
		t.Fatalf("reading = %d: %v", status, body)
	}
	orgs, _ := body["organizations"].([]any)
	if len(orgs) != 1 {
		t.Fatalf("%d organisations, want only their own", len(orgs))
	}
	if first, _ := orgs[0].(map[string]any); first["slug"] != "acme" {
		t.Errorf("they see %v, want their own organisation", first["slug"])
	}

	resp := h.withCookie(http.MethodPost, "/api/v1/organizations", cookie)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("creating an organisation with a browser session = %d, want 403", resp.StatusCode)
	}
}
