package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/logx"
)

// refusal is the body an API refusal carries.
type refusal struct {
	status  int
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (h *harness) refuse(method, path, body string) refusal {
	h.t.Helper()
	req := mustRequest(h.t, method, h.server.URL+path, body)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	out := refusal{status: resp.StatusCode}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// An administrator who gets something wrong is told what.
//
// These all used to answer 500 with "the request could not be completed", because the API
// turns errors it does not recognise into a bare 500 and the explanations written for a
// person were among them. The rule is right — an error whose text nobody has reviewed must
// not be echoed — so the fix is a type that carries the review, not a wider hole.
func TestARefusedRequestSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.branchGroup(t, `{"slug":"branch","kind":"subnet","prefixes":["192.168.10.0/24"]}`)

	for name, tc := range map[string]struct {
		method, path, body string
		expect             string
	}{
		"an egress group carrying prefixes of its own": {
			http.MethodPost, h.netPath("/route-groups"),
			`{"slug":"bad","kind":"egress","prefixes":["192.168.1.0/24"]}`,
			"takes no prefixes of its own",
		},
		"a subnet group carrying nothing": {
			http.MethodPost, h.netPath("/route-groups"),
			`{"slug":"empty","kind":"subnet"}`,
			"needs at least one prefix",
		},
		"a kind that does not exist": {
			http.MethodPost, h.netPath("/route-groups"),
			`{"slug":"weird","kind":"magic","prefixes":["192.168.1.0/24"]}`,
			"egress, subnet, service",
		},
		"a slug that will not go in a URL": {
			http.MethodPost, h.netPath("/route-groups"),
			`{"slug":"Branch LAN","kind":"subnet","prefixes":["192.168.1.0/24"]}`,
			"lowercase letters, digits and hyphens",
		},
		"a policy that would oscillate": {
			http.MethodPut, h.netPath("/route-groups/branch/failover"),
			`{"enabled":true,"fail_threshold":5,"recover_threshold":2}`,
			"below fail_threshold",
		},
		"a quorum nothing can satisfy": {
			http.MethodPut, h.netPath("/route-groups/branch/failover"),
			`{"enabled":true,"probe_targets":["1.1.1.1:443"],"probe_quorum":2}`,
			"cannot be met by",
		},
		"a probe target that is a hostname": {
			http.MethodPut, h.netPath("/route-groups/branch/failover"),
			`{"enabled":true,"probe_targets":["one.one.one.one:443"]}`,
			"literal address and port",
		},
	} {
		got := h.refuse(tc.method, tc.path, tc.body)
		if got.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, got.status)
		}
		if !strings.Contains(got.Message, tc.expect) {
			t.Errorf("%s: message %q does not contain %q", name, got.Message, tc.expect)
		}
	}
}

// And an error nobody has reviewed still stays in the log.
//
// The point of the type is that echoing a message is a decision somebody made, not
// something that happens to every error that reaches the handler.
func TestAnUnreviewedErrorIsStillOpaque(t *testing.T) {
	h := newHarness(t)

	// A network id that is well formed and does not exist. Whatever the database says about
	// it is not something a caller should be reading.
	got := h.refuse(http.MethodPost,
		"/api/v1/networks/00000000-0000-0000-0000-000000000000/route-groups",
		`{"slug":"orphan","kind":"subnet","prefixes":["192.168.1.0/24"]}`)
	if got.status == http.StatusBadRequest && strings.Contains(got.Message, "route_groups") {
		t.Errorf("a database error reached the caller: %q", got.Message)
	}
}

// A refusal names what the caller sent, so what the caller sent is bounded and sanitised
// before it is logged.
//
// This is the difference between this branch and the sentinel table beside it: those errors
// have fixed text written here, while an InvalidError quotes a slug, a kind or a probe
// target straight back.
//
// The assertion is on truncation rather than on a forged log line, and finding that out was
// the useful part. A first attempt asserted that a newline in a slug could not start a new
// record — and it passed with the fix removed, because slog's text handler quotes control
// characters and every construction site uses %q anyway. Escaping here is defence in depth
// against a handler that is less careful, and a test that cannot tell the two versions apart
// is worse than none.
//
// Length is the half that is neither. slog does not bound a value at all, so without this a
// caller can put as much as they like into the log on every failed request, which is a cheap
// way to fill somebody's disk or their log bill.
func TestARefusalBoundsWhatTheCallerSent(t *testing.T) {
	var buf bytes.Buffer
	h := newHarnessWithLog(t, slog.New(slog.NewTextHandler(&buf, nil)))

	huge := strings.Repeat("A", 4096)
	got := h.refuse(http.MethodPost, h.netPath("/route-groups"),
		`{"slug":"`+huge+`","kind":"subnet","prefixes":["192.168.1.0/24"]}`)
	if got.status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", got.status)
	}

	logged := buf.String()
	if !strings.Contains(logged, "request refused") {
		t.Fatalf("the refusal was not logged at all:\n%s", logged)
	}
	if !strings.Contains(logged, "(truncated)") {
		t.Errorf("a %d-byte slug reached the log whole, so any caller can write as much as "+
			"they like on every failed request", len(huge))
	}
	if strings.Contains(logged, strings.Repeat("A", logx.MaxValueBytes*2)) {
		t.Error("the log line carries more of the caller's input than logx bounds it to")
	}
}
