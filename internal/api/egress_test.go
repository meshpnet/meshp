package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/sessionclient"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// answer is what both of these endpoints say.
type answer struct {
	status   int
	Enforced bool `json:"enforced"`
	Changed  bool `json:"changed"`
}

// readFailClosed asks what this network's policy is.
func (h *harness) readFailClosed(path string) answer {
	h.t.Helper()
	return h.failClosed(http.MethodGet, path, "")
}

// writeFailClosed records one, and returns whatever came back — including the refusals,
// since what this endpoint refuses is most of what is worth testing about it.
func (h *harness) writeFailClosed(path, body string) answer {
	h.t.Helper()
	return h.failClosed(http.MethodPut, path, body)
}

// failClosed does the round trip and consumes the response, so a test that only looks at a
// status code does not leak a connection.
func (h *harness) failClosed(method, path, body string) answer {
	h.t.Helper()
	req := mustRequest(h.t, method, h.server.URL+path, body)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	out := answer{status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		return out
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// A network nobody has configured is enforcing, which is what ADR-0011 asks for and what
// every agent is already doing. The point of reading it back is that an administrator should
// not have to infer a fleet's safety from what its devices happen to be up to.
func TestANewNetworkIsEnforcing(t *testing.T) {
	h := newHarness(t)

	got := h.readFailClosed(h.netPath("/egress-fail-closed"))
	if got.status != http.StatusOK {
		t.Fatalf("returned %d", got.status)
	}
	if !got.Enforced {
		t.Error("a network nobody has configured reports that its devices may fail open")
	}
}

func TestOptingOutAndBackIn(t *testing.T) {
	h := newHarness(t)
	path := h.netPath("/egress-fail-closed")

	out := h.writeFailClosed(path, `{"enforced":false}`)
	if out.status != http.StatusOK {
		t.Fatalf("opting out returned %d", out.status)
	}
	if out.Enforced || !out.Changed {
		t.Errorf("opting out reported enforced=%v changed=%v", out.Enforced, out.Changed)
	}
	if h.readFailClosed(path).Enforced {
		t.Error("the opt-out did not stick")
	}

	back := h.writeFailClosed(path, `{"enforced":true}`)
	if !back.Enforced || !back.Changed {
		t.Errorf("turning it back on reported enforced=%v changed=%v", back.Enforced, back.Changed)
	}
	if !h.readFailClosed(path).Enforced {
		t.Error("turning it back on did not stick")
	}
}

// The guard worth having.
//
// `enforced` is a pointer precisely so a body that leaves it out is refused rather than read
// as Go's zero value — which for a bool is false, which here means every device in the
// network may send traffic in the clear when its tunnel drops. A body of `{}`, an explicit
// null, or a script whose variable was empty would each otherwise turn off a safety property
// and be answered with a 200.
//
// The misspelling is the other half of the same hole, closed by decode refusing unknown
// fields: `{"enforce":false}` accepted and ignored would report success and change nothing,
// leaving an administrator believing the fleet had been reconfigured.
func TestTurningItOffHasToBeSaidOutLoud(t *testing.T) {
	h := newHarness(t)
	path := h.netPath("/egress-fail-closed")

	for _, body := range []string{
		`{}`,
		`{"enforced":null}`,
		`{"enforce":false}`,
	} {
		if got := h.writeFailClosed(path, body); got.status != http.StatusBadRequest {
			t.Errorf("%s returned %d, want 400", body, got.status)
		}
	}

	// And nothing was changed on the way past.
	if !h.readFailClosed(path).Enforced {
		t.Error("a refused request still turned fail-closed off")
	}
}

// Writing the same answer twice reports that it changed nothing, so an operator running this
// from a configuration loop can tell a no-op from a reconfiguration.
func TestWritingTheSameAnswerReportsNoChange(t *testing.T) {
	h := newHarness(t)
	path := h.netPath("/egress-fail-closed")

	if !h.writeFailClosed(path, `{"enforced":false}`).Changed {
		t.Fatal("the first write reported no change")
	}
	second := h.writeFailClosed(path, `{"enforced":false}`)
	if second.Changed || second.Enforced {
		t.Errorf("the second write reported enforced=%v changed=%v", second.Enforced, second.Changed)
	}
}

// A network that does not exist is a 404 rather than a 500 or a silent success, so a typo in
// a script does not look like a fleet that has been reconfigured.
func TestAnUnknownNetworkIsNotFound(t *testing.T) {
	h := newHarness(t)
	missing := "/api/v1/networks/" + uuid.New().String() + "/egress-fail-closed"

	if got := h.readFailClosed(missing); got.status != http.StatusNotFound {
		t.Errorf("reading returned %d, want 404", got.status)
	}
	if got := h.writeFailClosed(missing, `{"enforced":false}`); got.status != http.StatusNotFound {
		t.Errorf("writing returned %d, want 404", got.status)
	}
}

// This is a fleet's safety property, so it is not something an unauthenticated caller may
// read or change.
func TestFailClosedNeedsTheAdminToken(t *testing.T) {
	h := newHarness(t)
	path := h.server.URL + h.netPath("/egress-fail-closed")

	for _, req := range []*http.Request{
		mustRequest(t, http.MethodGet, path, ""),
		mustRequest(t, http.MethodPut, path, `{"enforced":false}`),
	} {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status != http.StatusUnauthorized {
			t.Errorf("%s answered an unauthenticated caller with %d", req.Method, status)
		}
	}
}

// The mechanism has to be reachable from where an administrator actually stands: a request
// to the admin API, and a connected agent that changes what it enforces because of it
// (ADR-0018). Everything else in this file tests a piece.
//
// Well inside the 25-second heartbeat, so this can only pass if the change was pushed. A
// test that allowed longer could not tell a working push from a missing one — which is
// precisely how the push came to be absent from every mutation path while the unit tests
// passed.
func TestOptingOutReachesAConnectedAgent(t *testing.T) {
	h := newHarness(t)

	identity, wg := newDevice(t)
	joined, err := enrollclient.New(h.server.URL, nil).Join(h.ctx, enrollclient.JoinRequest{
		Token: h.mintToken(1, time.Hour), Identity: identity, WireGuard: wg,
		Name: "laptop", OS: "linux", AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("the device could not join: %v", err)
	}

	rec := newRecorder()
	agentCtx, stopAgent := context.WithCancel(h.ctx)
	defer stopAgent()
	client := sessionclient.New(sessionclient.Options{
		ControlURL:   h.server.URL,
		Identity:     identity,
		MembershipID: joined.MembershipID,
		AgentVersion: "test",
	})
	go func() { _ = client.Run(agentCtx, rec) }()

	// It starts out enforcing, because that is what a network nobody has configured means.
	first := rec.waitForTunnel(t, func(c *meshpv1.TunnelConfig) bool { return c != nil }, 10*time.Second)
	if first.GetFailClosedPolicy() == meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED {
		t.Fatal("a device in a network nobody has configured was told it may fail open")
	}

	if got := h.writeFailClosed(h.netPath("/egress-fail-closed"), `{"enforced":false}`); got.status != http.StatusOK {
		t.Fatalf("opting out returned %d", got.status)
	}

	rec.waitForTunnel(t, func(c *meshpv1.TunnelConfig) bool {
		return c.GetFailClosedPolicy() == meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED
	}, 5*time.Second)
}

// waitForTunnel blocks until the agent holds a tunnel configuration that satisfies want.
func (r *recorder) waitForTunnel(t *testing.T, want func(*meshpv1.TunnelConfig) bool, within time.Duration) *meshpv1.TunnelConfig {
	t.Helper()
	deadline := time.After(within)
	for {
		r.mu.Lock()
		var last *meshpv1.TunnelConfig
		if len(r.applied) > 0 {
			last = r.applied[len(r.applied)-1].Tunnel()
		}
		r.mu.Unlock()
		if want(last) {
			return last
		}
		select {
		case <-r.changed:
		case <-deadline:
			t.Fatalf("the agent still holds %v after %s", last, within)
			return nil
		}
	}
}

func mustRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}
