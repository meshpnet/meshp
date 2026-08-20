package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
)

// login exchanges the administrative token for a browser session and returns the cookie.
//
// The cookie is carried by hand rather than by a cookie jar, because Go's jar honours the
// Secure attribute and would refuse to send it back over the test server's plaintext
// loopback — which is the browser behaviour this cookie wants and not what these tests are
// about. What is under test is the server's side of it.
func (h *harness) login() *http.Cookie {
	h.t.Helper()
	resp := h.loginWith(testAdminToken)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		h.t.Fatalf("signing in returned %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == uiCookieName {
			return c
		}
	}
	h.t.Fatalf("signing in set no %s cookie", uiCookieName)
	return nil
}

func (h *harness) loginWith(token string) *http.Response {
	h.t.Helper()
	body, _ := json.Marshal(map[string]string{"token": token})
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/ui/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// withCookie makes a request carrying the browser session and no bearer token.
func (h *harness) withCookie(method, path string, cookie *http.Cookie) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.server.URL+path, bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// The cookie is what the page will actually hold, so it has to carry the flags that make
// holding it safe. Asserted here rather than trusted, because every one of them is a silent
// failure: a cookie that works identically without HttpOnly is readable by any script that
// gets onto the page.
func TestSigningInSetsAHardenedCookie(t *testing.T) {
	h := newHarness(t)
	cookie := h.login()

	if !cookie.HttpOnly {
		t.Error("the cookie is not HttpOnly, so a script on the page can read it")
	}
	if !cookie.Secure {
		t.Error("the cookie is not Secure, so it can cross a plaintext hop")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict — it is what stands in for a CSRF token", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
	if cookie.Value == "" {
		t.Error("the cookie carries no value")
	}
	if cookie.Value == testAdminToken {
		t.Fatal("the cookie carries the administrative token itself, which is the one thing it must never do")
	}
}

// The whole point: it reads.
func TestTheCookieReadsTheOverview(t *testing.T) {
	h := newHarness(t)
	h.enrol("a-device")
	cookie := h.login()

	resp := h.withCookie(http.MethodGet, h.netPath("/overview"), cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reading the overview with a browser session returned %d", resp.StatusCode)
	}

	listing := h.withCookie(http.MethodGet, "/api/v1/networks", cookie)
	defer func() { _ = listing.Body.Close() }()
	if listing.StatusCode != http.StatusOK {
		t.Errorf("listing networks with a browser session returned %d", listing.StatusCode)
	}
}

// And the whole point of the point: it does nothing else.
//
// This is the test that makes shipping a UI against a single shared secret defensible, so
// it walks every route that changes something rather than sampling one. A stolen browser
// session must read a network and be unable to mint a token, publish a policy, revoke a
// device or touch a route group.
func TestTheCookieCannotReachAnythingThatWrites(t *testing.T) {
	h := newHarness(t)
	membership := h.enrol("a-device").MembershipID.String()
	cookie := h.login()

	writes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, h.netPath("/enrollment-tokens")},
		{http.MethodGet, h.netPath("/enrollment-tokens")},
		{http.MethodGet, h.netPath("/devices")},
		{http.MethodDelete, h.netPath("/devices/" + membership)},
		{http.MethodGet, h.netPath("/acl")},
		{http.MethodPut, h.netPath("/acl")},
		{http.MethodPost, "/api/v1/networks"},
		{http.MethodGet, h.netPath("/route-groups")},
		{http.MethodPost, h.netPath("/route-groups")},
		{http.MethodDelete, h.netPath("/route-groups/anything")},
		{http.MethodPost, h.netPath("/route-groups/anything/advertisers")},
	}
	for _, route := range writes {
		resp := h.withCookie(route.method, route.path, cookie)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with only a browser session returned %d, want 401 — the cookie is "+
				"not weaker than the token it came from", route.method, route.path, resp.StatusCode)
		}
	}
}

// A wrong token mints nothing. Otherwise the endpoint is a way to turn a guess into a
// credential that outlives the guessing.
func TestSigningInWithTheWrongToken(t *testing.T) {
	h := newHarness(t)

	resp := h.loginWith("not-the-admin-token")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("returned %d, want 401", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == uiCookieName && c.Value != "" {
			t.Fatal("a refused sign-in still set a session cookie")
		}
	}
}

// Signing out is what "revocable server-side" means, so the cookie has to stop working
// even though the browser still holds it.
func TestSigningOutRevokesTheSession(t *testing.T) {
	h := newHarness(t)
	cookie := h.login()

	out := h.withCookie(http.MethodDelete, "/api/v1/ui/session", cookie)
	_ = out.Body.Close()
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("signing out returned %d, want 204", out.StatusCode)
	}

	resp := h.withCookie(http.MethodGet, "/api/v1/networks", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the cookie still reads after signing out, returned %d", resp.StatusCode)
	}
}

// A page nobody is watching stops being able to read. A page somebody is watching does not.
func TestTheSessionExpiresWhenIdleAndIsHeldOpenByUse(t *testing.T) {
	h := newHarness(t)
	cookie := h.login()

	// Used well inside the idle window, repeatedly, past the point a fixed lifetime of one
	// idle window would have ended it. A dashboard polling every few seconds must not log
	// itself out.
	for range 4 {
		h.clk.Advance(uiSessionIdle - time.Minute)
		resp := h.withCookie(http.MethodGet, "/api/v1/networks", cookie)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a session in use returned %d, want 200", resp.StatusCode)
		}
	}

	h.clk.Advance(uiSessionIdle + time.Minute)
	resp := h.withCookie(http.MethodGet, "/api/v1/networks", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an idle session still reads, returned %d", resp.StatusCode)
	}
}

// Use extends the idle window but never the ceiling, so a page left open on a wall does not
// hold a credential derived from the deployment's root password indefinitely.
func TestTheSessionHasACeilingUseDoesNotRaise(t *testing.T) {
	h := newHarness(t)
	cookie := h.login()

	// Polled continuously, so the idle window is refreshed every time and only the absolute
	// deadline can end this.
	for range int(uiSessionMaxAge/(uiSessionIdle-time.Minute)) + 2 {
		h.clk.Advance(uiSessionIdle - time.Minute)
		resp := h.withCookie(http.MethodGet, "/api/v1/networks", cookie)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return // the ceiling ended it, which is the point
		}
	}
	t.Errorf("a continuously polled session outlived its %s ceiling", uiSessionMaxAge)
}

// Signing in over plaintext to something that is not loopback is refused rather than
// downgraded, so configuring TLS is a requirement for any deployment somebody browses to.
func TestSigningInIsRefusedOverPlaintextToARemoteHost(t *testing.T) {
	h := newHarness(t)

	body, _ := json.Marshal(map[string]string{"token": testAdminToken})
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/ui/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// The connection is still loopback; what the server can see of where the browser
	// thinks it is, is the Host header, and that is what decides.
	req.Host = "control.example.net"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("returned %d, want 400", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == uiCookieName && c.Value != "" {
			t.Error("a refused sign-in over plaintext still set a session cookie")
		}
	}
}

// A forged or stale cookie is not a session. The store is keyed by a hash of what the
// browser presents, so this also covers the case of somebody who has seen the map.
func TestAnInventedCookieIsNotASession(t *testing.T) {
	h := newHarness(t)
	h.login() // so there is a real session in the store to be confused with

	resp := h.withCookie(http.MethodGet, "/api/v1/networks",
		&http.Cookie{Name: uiCookieName, Value: "made-up"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an invented cookie returned %d, want 401", resp.StatusCode)
	}
}

// The store's own bounds, exercised directly because the HTTP path cannot reach them
// without a thousand sign-ins.
func TestTheSessionStoreSweepsAndRefusesToGrowWithoutBound(t *testing.T) {
	clk := clock.NewFake()
	store := newUISessions(clk)

	first, _, err := store.create()
	if err != nil {
		t.Fatal(err)
	}
	if !store.valid(first) {
		t.Fatal("a fresh session is not valid")
	}

	// Expired entries go on the next sign-in rather than lingering, so an abandoned page
	// does not hold a slot against the bound below.
	clk.Advance(uiSessionMaxAge + time.Hour)
	if _, _, err := store.create(); err != nil {
		t.Fatalf("creating a session after everything expired: %v", err)
	}
	if store.valid(first) {
		t.Error("an expired session is still valid")
	}
	if got := len(store.byHash); got != 1 {
		t.Errorf("the store holds %d sessions, want 1 — the expired one was not swept", got)
	}

	for range maxUISessions {
		if _, _, err := store.create(); err != nil {
			if !errors.Is(err, errTooManySessions) {
				t.Fatalf("creating a session: %v", err)
			}
			return // refused rather than growing, which is the point
		}
	}
	t.Errorf("the store grew past %d sessions without refusing", maxUISessions)
}
