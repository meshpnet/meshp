package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/authz"
)

// login signs in as a reader and returns the cookie.
//
// A reader, because that is the successor to the credential these tests were written for: a
// browser session that reads everything and writes nothing. That used to be a property of
// the credential itself, derived from the administrative token and bounded by having no
// identity to attach permissions to. It is now a property of the person holding it, which
// is the whole of what ADR-0024 changed here.
//
// The cookie is carried by hand rather than by a cookie jar, because Go's jar honours the
// Secure attribute and would refuse to send it back over the test server's plaintext
// loopback — which is the browser behaviour this cookie wants and not what these tests are
// about. What is under test is the server's side of it.
func (h *harness) login() *http.Cookie {
	h.t.Helper()
	return h.loginAs("reader")
}

// loginAs signs in as somebody holding exactly one built-in role.
func (h *harness) loginAs(role string) *http.Cookie {
	h.t.Helper()
	email := role + "@example.com"
	user := createUser(h.t, h, email)
	takeAwayEveryRole(h.t, h, user)
	grantRole(h.t, h, user, map[string]any{"role": role})
	return signIn(h.t, h, email, testPassword)
}

// withCookie makes a request carrying the browser session and no bearer token.
//
// Origin is set because a browser sets it on every unsafe method, and the cross-site request
// forgery check refuses a cookie-authenticated write without it. A test helper that omitted
// it would make every write in this file fail for the wrong reason — and would hide whether
// the permission underneath was ever checked.
func (h *harness) withCookie(method, path string, cookie *http.Cookie) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.server.URL+path, bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", h.server.URL)
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
	if strings.Contains(cookie.Value, testPassword) {
		t.Fatal("the cookie carries the password, which is the one thing it must never do")
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

// And the whole point of the point: it changes nothing.
//
// This is the test that makes shipping a UI against a single shared secret defensible, so it
// walks every route rather than sampling one — and it walks them out of the route table
// rather than out of a list somebody maintains here, so a write endpoint added next month is
// covered on the day it is added rather than on the day somebody remembers this test.
//
// What it asserts changed shape when permissions arrived. It used to be "every one of these
// paths answers 401"; it is now "no route requiring a permission that is not a read can be
// reached", which is the property that was always meant and is now something the code can
// express.
func TestTheCookieCannotReachAnythingThatChangesSomething(t *testing.T) {
	h := newHarness(t)
	membership := h.enrol("a-device").MembershipID.String()
	cookie := h.login()

	checked := 0
	for _, rt := range h.srv.routes() {
		if rt.perm == "" || authz.IsRead(rt.perm) {
			continue
		}
		method, pattern, ok := strings.Cut(rt.pattern, " ")
		if !ok {
			t.Fatalf("route %q has no method", rt.pattern)
		}
		checked++

		resp := h.withCookie(method, h.fillPath(pattern, membership), cookie)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s with only a browser session returned %d, want 403 — the cookie is "+
				"not weaker than the token it came from", method, pattern, resp.StatusCode)
		}
	}
	if checked == 0 {
		t.Fatal("no route required a permission that writes, so this asserted nothing")
	}
}

// The other half, said out loud because it is a widening and widenings should not be
// discovered by reading a diff.
//
// The browser credential used to reach two endpoints. It now reaches every route whose
// permission is a read, which is a larger set — the device list, the policy, the route
// groups, the enrolment token metadata. That is deliberate: the rule "this session reads and
// does not write" is one somebody can hold in their head, while "this session reaches these
// two URLs" is a list, and a list is what ADR-0022 §5 had to amend twice. Everything here is
// derived from a secret that could already do all of it and more.
func TestTheCookieReachesEveryRouteThatOnlyReads(t *testing.T) {
	h := newHarness(t)
	cookie := h.login()

	checked := 0
	for _, rt := range h.srv.routes() {
		if rt.perm == "" || !authz.IsRead(rt.perm) {
			continue
		}
		method, pattern, _ := strings.Cut(rt.pattern, " ")
		checked++

		resp := h.withCookie(method, h.fillPath(pattern, uuid.NewString()), cookie)
		_ = resp.Body.Close()
		// Not "200": some of these answer 404 for a network with nothing in it, which is
		// the handler having been reached. What matters is that the guard let it past.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			t.Errorf("%s %s with a browser session returned %d; a read should be reachable",
				method, pattern, resp.StatusCode)
		}
	}
	if checked == 0 {
		t.Fatal("no route required a permission that reads, so this asserted nothing")
	}
}

// fillPath turns a route pattern into a URL. The values only have to parse: every assertion
// here is about the guard, which runs before any handler looks at them.
func (h *harness) fillPath(pattern, membership string) string {
	org := orgOf(h.t, h)
	for placeholder, value := range map[string]string{
		"{networkID}":      h.netID.String(),
		"{organizationID}": org.String(),
		"{membershipID}":   membership,
		"{userID}":         uuid.NewString(),
		"{tokenID}":        uuid.NewString(),
		"{recordID}":       uuid.NewString(),
		"{bindingID}":      uuid.NewString(),
		"{slug}":           "anything",
	} {
		pattern = strings.ReplaceAll(pattern, placeholder, value)
	}
	return pattern
}

// Signing in over plaintext to something that is not loopback is refused rather than
// downgraded, so configuring TLS is a requirement for any deployment somebody browses to.
func TestSigningInIsRefusedOverPlaintextToARemoteHost(t *testing.T) {
	h := newHarness(t)

	body, _ := json.Marshal(map[string]string{"email": "alice@example.com", "password": testPassword})
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

// A forged or stale cookie is not a session. What the database holds is a hash of what the
// browser presents, so this also covers somebody who has read the table.
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

// The administrative token no longer signs anybody in to the page.
//
// It still works on the API, because a locked-out deployment needs a way back (ADR-0024 §5).
// What it does not do any more is mint a browser session — there is no credential-without-an
// identity left for one to be. Asserted rather than assumed, because restoring that path
// would be a two-line change that reintroduces a shared secret to the one surface people
// actually look at, and nothing else would fail.
func TestSigningInNoLongerTakesTheAdministrativeToken(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"token": testAdminToken})
	h := newHarness(t)

	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/ui/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("signing in with the administrative token = %d, want 400", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == uiCookieName && c.Value != "" {
			t.Fatal("the administrative token still mints a browser session")
		}
	}
}

// A deployment with no accounts cannot sign in here at all, and that is correct: there is
// nothing to look at until somebody creates the first account, and creating one is an API
// call the bootstrap secret still makes.
func TestADeploymentWithNoAccountsCannotSignIn(t *testing.T) {
	h := newHarness(t)

	body, _ := json.Marshal(map[string]string{
		"email": "nobody@example.com", "password": testPassword,
	})
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/ui/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("signing in to a deployment with no accounts = %d, want 401", resp.StatusCode)
	}
}
