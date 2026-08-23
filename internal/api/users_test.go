package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

const testPassword = "correct horse battery staple"

// orgOf returns the organisation the harness seeded.
func orgOf(t *testing.T, h *harness) uuid.UUID {
	t.Helper()
	orgs, err := h.store.ListOrganizations(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orgs) == 0 {
		t.Fatal("the harness seeded no organisation")
	}
	return orgs[0].ID
}

// doJSON makes a request and returns what the assertions need — a status, the cookies and a
// decoded body — rather than the response itself, so the response never escapes and can be
// closed in one place instead of in every caller.
func doJSON(t *testing.T, method, url string, body any, cookie *http.Cookie, token bool) (int, []*http.Cookie, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	if token {
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
	}
	if cookie != nil {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, resp.Cookies(), out
}

// createUser makes one with the administrative token, the way a fresh deployment must.
func createUser(t *testing.T, h *harness, email string) uuid.UUID {
	t.Helper()
	org := orgOf(t, h)
	status, _, body := doJSON(t, http.MethodPost,
		h.server.URL+"/api/v1/organizations/"+org.String()+"/users",
		map[string]any{"email": email, "name": "Test", "password": testPassword}, nil, true)
	if status != http.StatusCreated {
		t.Fatalf("creating %s = %d: %v", email, status, body)
	}
	id, err := uuid.Parse(body["user_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// signIn returns the cookie a browser would hold.
func signIn(t *testing.T, h *harness, email, plain string) *http.Cookie {
	t.Helper()
	status, cookies, body := doJSON(t, http.MethodPost, h.server.URL+"/api/v1/ui/session",
		map[string]any{"email": email, "password": plain}, nil, false)
	if status != http.StatusCreated {
		t.Fatalf("signing in as %s = %d: %v", email, status, body)
	}
	for _, c := range cookies {
		if c.Name == uiCookieName {
			return c
		}
	}
	t.Fatal("signing in set no cookie")
	return nil
}

// The whole of the slice, end to end: a person is created, signs in, and is recognised.
func TestAPersonCanBeCreatedAndSignIn(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")

	cookie := signIn(t, h, "alice@example.com", testPassword)

	status, _, body := doJSON(t, http.MethodGet, h.server.URL+"/api/v1/me", nil, cookie, false)
	if status != http.StatusOK {
		t.Fatalf("GET /me = %d: %v", status, body)
	}
	if body["email"] != "alice@example.com" {
		t.Errorf("signed in as %v, want alice@example.com", body["email"])
	}
}

// The session is a row, not a process's memory. A second server on the same database — which
// is what a restart or a second replica looks like from a browser — accepts the same cookie.
func TestASessionSurvivesTheProcessThatMintedIt(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)

	mux := http.NewServeMux()
	New(h.store, nil, nil, Config{AdminToken: testAdminToken, Clock: h.clk}).Routes(mux)
	other := httptest.NewServer(mux)
	defer other.Close()

	status, _, body := doJSON(t, http.MethodGet, other.URL+"/api/v1/me", nil, cookie, false)
	if status != http.StatusOK {
		t.Fatalf("a session did not survive a different process: %d %v", status, body)
	}
}

// Every refusal is the same refusal. A stranger who can tell "no such account" from "wrong
// password" can enumerate who has an account here.
func TestEverySignInRefusalLooksTheSame(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")

	var seen []string
	for _, tc := range []struct{ email, password string }{
		{"alice@example.com", "the wrong password entirely"},
		{"nobody@example.com", testPassword},
		{"nobody@example.com", "the wrong password entirely"},
	} {
		status, _, body := doJSON(t, http.MethodPost, h.server.URL+"/api/v1/ui/session",
			map[string]any{"email": tc.email, "password": tc.password}, nil, false)
		if status != http.StatusUnauthorized {
			t.Errorf("signing in as %s = %d, want 401", tc.email, status)
		}
		message, _ := body["message"].(string)
		seen = append(seen, message)
	}
	for _, message := range seen[1:] {
		if message != seen[0] {
			t.Errorf("refusals differ: %q and %q", seen[0], message)
		}
	}
}

// Suspending somebody ends the session they already hold. A suspension that left one running
// would be a decision the system agreed with and did not act on.
func TestSuspendingEndsTheSessionAlreadyHeld(t *testing.T) {
	h := newHarness(t)
	userID := createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)
	org := orgOf(t, h)

	if status, _, body := doJSON(t, http.MethodGet, h.server.URL+"/api/v1/me", nil, cookie, false); status != http.StatusOK {
		t.Fatalf("the session did not work before suspension: %d %v", status, body)
	}

	status, _, body := doJSON(t, http.MethodPut,
		h.server.URL+"/api/v1/organizations/"+org.String()+"/users/"+userID.String()+"/suspended",
		map[string]any{"suspended": true}, nil, true)
	if status != http.StatusOK {
		t.Fatalf("suspending = %d: %v", status, body)
	}

	if status, _, _ := doJSON(t, http.MethodGet, h.server.URL+"/api/v1/me", nil, cookie, false); status != http.StatusUnauthorized {
		t.Errorf("a suspended user's session still works: %d", status)
	}
	// And they cannot sign in again.
	status, _, _ = doJSON(t, http.MethodPost, h.server.URL+"/api/v1/ui/session",
		map[string]any{"email": "alice@example.com", "password": testPassword}, nil, false)
	if status != http.StatusUnauthorized {
		t.Errorf("a suspended user signed in: %d", status)
	}
}

// Changing a password ends every session, including the one that asked. A password is usually
// changed because somebody else may have seen it, and the change would be worth much less if
// it left their session running.
func TestChangingAPasswordEndsEverySession(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	first := signIn(t, h, "alice@example.com", testPassword)
	second := signIn(t, h, "alice@example.com", testPassword)

	status, _, body := doJSON(t, http.MethodPost, h.server.URL+"/api/v1/me/password",
		map[string]any{"current_password": testPassword, "new_password": "a different long passphrase"}, first, false)
	if status != http.StatusOK {
		t.Fatalf("changing the password = %d: %v", status, body)
	}

	for name, cookie := range map[string]*http.Cookie{"the session that asked": first, "another session": second} {
		if status, _, _ := doJSON(t, http.MethodGet, h.server.URL+"/api/v1/me", nil, cookie, false); status != http.StatusUnauthorized {
			t.Errorf("%s still works after a password change: %d", name, status)
		}
	}

	// And the new password works.
	_ = signIn(t, h, "alice@example.com", "a different long passphrase")
}

// The current password is required even though the caller is already signed in: a session
// left open on an unlocked laptop should not be enough to take an account over.
func TestChangingAPasswordNeedsTheCurrentOne(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)

	status, _, _ := doJSON(t, http.MethodPost, h.server.URL+"/api/v1/me/password",
		map[string]any{"current_password": "not it", "new_password": "a different long passphrase"}, cookie, false)
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	// The old password still works, so nothing was changed on the way to refusing.
	_ = signIn(t, h, "alice@example.com", testPassword)
}

// Until roles land, a signed-in person is an administrator. This is temporary and the test
// says so, so that whoever implements permissions knows to come and change it.
func TestASignedInPersonReachesAdministrativeRoutesForNow(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)

	status, _, body := doJSON(t, http.MethodGet, h.server.URL+"/api/v1/organizations", nil, cookie, false)
	if status != http.StatusOK {
		t.Fatalf("a signed-in person could not read an administrative route: %d %v", status, body)
	}
}

// A weak password is refused where the person can fix it, and the message says what would be
// acceptable rather than only that this is not.
func TestAWeakPasswordIsRefused(t *testing.T) {
	h := newHarness(t)
	org := orgOf(t, h)

	status, _, body := doJSON(t, http.MethodPost,
		h.server.URL+"/api/v1/organizations/"+org.String()+"/users",
		map[string]any{"email": "bob@example.com", "name": "Bob", "password": "short"}, nil, true)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %v", status, body)
	}
	message, _ := body["message"].(string)
	if !bytes.Contains([]byte(message), []byte("12 characters")) {
		t.Errorf("message = %q, want it to say what would be acceptable", message)
	}
}

// Signing out ends the session rather than only clearing the cookie, so a copy of the value
// taken from somewhere else stops working too.
func TestSigningOutEndsTheSession(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)

	if status, _, _ := doJSON(t, http.MethodDelete, h.server.URL+"/api/v1/ui/session", nil, cookie, false); status != http.StatusNoContent {
		t.Fatalf("signing out = %d, want 204", status)
	}
	if status, _, _ := doJSON(t, http.MethodGet, h.server.URL+"/api/v1/me", nil, cookie, false); status != http.StatusUnauthorized {
		t.Errorf("the cookie still works after signing out: %d", status)
	}
}
