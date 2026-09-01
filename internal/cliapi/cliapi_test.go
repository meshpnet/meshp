package cliapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A refusal and an unanswered call are different things, and only one of them is about the
// credential. Telling somebody their token was rejected when the host never answered sends
// them to rotate a token that is fine.
func TestARefusalAndAnUnreachableHostAreNotTheSame(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","message":"sign in"}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL, "mp_token")
	if err != nil {
		t.Fatal(err)
	}
	err = client.Do(context.Background(), http.MethodGet, "/api/v1/me", nil, nil)

	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("a 401 did not produce an *Error: %v", err)
	}
	if !apiErr.Unauthorised() {
		t.Error("a 401 is not reported as unauthorised")
	}
	if apiErr.Code != "unauthorized" {
		t.Errorf("code = %q, want the server's own code", apiErr.Code)
	}

	// A host that never answers is not an *Error at all, so a caller cannot mistake it for
	// a refusal by matching loosely.
	unreachable, err := New("https://198.51.100.99:1", "mp_token")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = unreachable.Do(ctx, http.MethodGet, "/api/v1/me", nil, nil)
	if errors.As(err, &apiErr) {
		t.Errorf("an unreachable host produced an *Error, which reads as a refusal: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Errorf("an unreachable host said %v; it should name what it could not reach", err)
	}
}

// The token goes in the Authorization header, which is what the control plane reads.
func TestTheTokenIsPresentedAsABearerToken(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL, "mp_secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Do(context.Background(), http.MethodGet, "/api/v1/me", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer mp_secret" {
		t.Errorf("Authorization = %q, want a bearer token", got)
	}
}

// A cookie-authenticated write must carry an Origin naming the host, or the control plane
// refuses it — a defence written for browsers that a CLI has to satisfy anyway (ADR-0022 §5).
// login is the only thing that uses a cookie, and it mints the token everything else uses.
func TestACookieRequestCarriesAnOrigin(t *testing.T) {
	var origin, cookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin, cookie = r.Header.Get("Origin"), r.Header.Get("Cookie")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	err = client.DoWithCookie(context.Background(), http.MethodPost, "/api/v1/me/tokens",
		"meshp_ui=abc", map[string]string{"name": "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "meshp_ui=abc" {
		t.Errorf("Cookie = %q", cookie)
	}
	if origin != server.URL {
		t.Errorf("Origin = %q, want %q — without it the control plane refuses the write", origin, server.URL)
	}
}

// A sign-in that succeeds and sets no cookie is a failure, not a session.
func TestASignInWithNoCookieIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenSession(context.Background(), "a@b.c", "pw"); err == nil {
		t.Error("a sign-in that set no cookie was treated as a session")
	}
}

// A mistyped address is reported by the command that was mistyped, not as a connection
// failure several steps later.
func TestABadAddressIsRefusedBeforeAnyRequest(t *testing.T) {
	if _, err := New("not a url", "t"); err == nil {
		t.Error("a URL with no scheme was accepted")
	}
}
