package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// writeAuditEvents puts n events in the network, all in one transaction.
//
// One transaction on purpose: created_at defaults to the transaction's timestamp, so every
// row written here shares it exactly. That is the case a timestamp cursor gets wrong, and it
// is not contrived — the events this table already holds are written alongside the act they
// describe, so a revocation and its policy change land together.
func writeAuditEvents(t *testing.T, h *harness, n int) {
	t.Helper()
	netID := h.netID
	err := h.store.InTx(h.ctx, func(q *dbgen.Queries) error {
		for i := range n {
			metadata, _ := json.Marshal(map[string]any{"sequence": i, "reason": "because"})
			if _, err := q.CreateAuditEvent(h.ctx, dbgen.CreateAuditEventParams{
				NetworkID:    &netID,
				ActorKind:    "device",
				ActorLabel:   fmt.Sprintf("device-%d", i),
				Action:       "route.switched",
				ResourceKind: "route_group",
				Metadata:     metadata,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type auditPage struct {
	Events []struct {
		ID         string          `json:"id"`
		Action     string          `json:"action"`
		ActorKind  string          `json:"actor_kind"`
		ActorLabel string          `json:"actor_label"`
		Metadata   json.RawMessage `json:"metadata"`
	} `json:"events"`
	NextBefore string `json:"next_before"`
}

func getAudit(t *testing.T, h *harness, query string) auditPage {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/audit"+query, nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET audit%s = %d: %s", query, resp.StatusCode, body)
	}
	var page auditPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	return page
}

// Four subsystems have been writing here since the beginning and only a test ever read one
// back, so "auditable" meant "queryable in psql".
func TestTheAuditTrailIsReadable(t *testing.T) {
	h := newHarness(t)
	writeAuditEvents(t, h, 3)

	page := getAudit(t, h, "")
	if len(page.Events) != 3 {
		t.Fatalf("%d events, want 3", len(page.Events))
	}
	if page.Events[0].Action != "route.switched" {
		t.Errorf("action = %q", page.Events[0].Action)
	}
	// Newest first: the last one written comes back first.
	if page.Events[0].ActorLabel != "device-2" {
		t.Errorf("first event is %q, want the newest (device-2)", page.Events[0].ActorLabel)
	}
	// An object, not a string holding an object. A reader should not have to parse twice.
	var metadata map[string]any
	if err := json.Unmarshal(page.Events[0].Metadata, &metadata); err != nil {
		t.Fatalf("metadata is not an object: %v (%s)", err, page.Events[0].Metadata)
	}
	if metadata["reason"] != "because" {
		t.Errorf("metadata = %v, want the writer's own fields", metadata)
	}
}

// Paging repeats nothing and skips nothing, including across events that share a timestamp
// exactly — which is why the cursor is an id.
func TestPagingTheAuditTrailLosesNothing(t *testing.T) {
	h := newHarness(t)
	writeAuditEvents(t, h, 10)

	seen := map[string]bool{}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("paging did not terminate")
		}
		query := "?limit=3"
		if cursor != "" {
			query += "&before=" + cursor
		}
		page := getAudit(t, h, query)
		for _, event := range page.Events {
			if seen[event.ID] {
				t.Fatalf("event %s came back twice", event.ID)
			}
			seen[event.ID] = true
		}
		if page.NextBefore == "" {
			break
		}
		cursor = page.NextBefore
	}
	if len(seen) != 10 {
		t.Errorf("saw %d events across every page, want 10", len(seen))
	}
}

// The last page says so by omitting the cursor, rather than by returning an empty page after
// it — a caller should not have to make one more request to learn there was nothing left.
func TestTheLastPageSaysItIsTheLast(t *testing.T) {
	h := newHarness(t)
	writeAuditEvents(t, h, 3)

	if page := getAudit(t, h, "?limit=3"); page.NextBefore != "" {
		t.Errorf("next_before = %q on a page holding everything, want it absent", page.NextBefore)
	}
	if page := getAudit(t, h, "?limit=2"); page.NextBefore == "" {
		t.Error("next_before is absent while an event remains unread")
	}
}

// A cursor that will not parse is refused rather than ignored. Treating it as "start from
// the newest" would make a paging caller loop over the first page while looking busy.
func TestABadCursorIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, query := range []string{"?before=nonsense", "?before=-1", "?limit=0", "?limit=100000"} {
		req, _ := http.NewRequest(http.MethodGet,
			h.server.URL+"/api/v1/networks/"+h.netID.String()+"/audit"+query, nil)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET audit%s = %d, want 400", query, resp.StatusCode)
		}
	}
}

// Some credential is required. The trail carries actor labels, source addresses and the
// reasons administrators typed, and none of that is public.
func TestTheAuditTrailNeedsACredential(t *testing.T) {
	h := newHarness(t)

	resp, err := http.Get(h.server.URL + "/api/v1/networks/" + h.netID.String() + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status without a credential = %d, want 401", resp.StatusCode)
	}
}

// And the browser's cookie is one of them, as of the amendment to ADR-0022 §5: that cookie
// is scoped to reads within one network, and this is one. It shipped behind the
// administrative token in #125 purely because §5 named endpoints rather than a kind, which
// left the page unable to answer "why did my outbound IP change?" while the record that
// answers it sat one route away.
func TestABrowserSessionReachesTheAuditTrail(t *testing.T) {
	h := newHarness(t)
	writeAuditEvents(t, h, 1)

	resp := h.withCookie(http.MethodGet, "/api/v1/networks/"+h.netID.String()+"/audit", h.login())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a browser session reading the audit trail = %d, want 200", resp.StatusCode)
	}

	var page auditPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 {
		t.Errorf("%d events, want 1", len(page.Events))
	}
}

// The widening is to reads and no further. Everything that changes something is still
// refused, which is the property the whole of §5 rests on.
//
// Refused with 403 rather than 401 since permissions arrived: the session is a credential
// this control plane recognises, and saying "who are you" to something it has just
// identified was always the wrong answer. It holds every permission that reads and none
// that writes, so this is a refusal about what it may do.
func TestABrowserSessionStillCannotWrite(t *testing.T) {
	h := newHarness(t)

	resp := h.withCookie(http.MethodPost,
		"/api/v1/networks/"+h.netID.String()+"/enrollment-tokens", h.login())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a browser session minting an enrolment token = %d, want 403", resp.StatusCode)
	}
}

// A network with no history is an empty list, not a 404. "Nothing has happened here" and
// "there is no such network" read the same to a caller that only sees a status code.
func TestAnEmptyAuditTrailIsAnEmptyList(t *testing.T) {
	h := newHarness(t)
	page := getAudit(t, h, "")
	if len(page.Events) != 0 {
		t.Errorf("%d events in a network where nothing has happened", len(page.Events))
	}
}
