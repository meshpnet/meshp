package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pageServerFor builds a server with no database behind it.
//
// The page is static, so nothing it serves needs a store — and a test that stood one up
// would only run where PostgreSQL does, which is the wrong place for the assertions below.
func pageServerFor(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	New(nil, nil, nil, Config{}).Routes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// get fetches a URL and returns what the assertions below need.
//
// The status, the headers and the body rather than the *http.Response, so the response
// never escapes this function — which is what lets it be closed in one place instead of in
// every caller.
func get(t *testing.T, url string) (int, http.Header, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(body)
}

// The page is reachable, and reachable without a credential.
//
// Deliberately so: the page is a static file and holds no data, and requiring a session to
// fetch the thing whose only job is to ask for one would be a loop. Everything it reads is
// behind `readable` (ADR-0022 §5), and that is where the credential belongs.
func TestThePageIsServedWithoutACredential(t *testing.T) {
	ts := pageServerFor(t)

	status, header, body := get(t, ts.URL+"/")
	if status != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", status)
	}
	if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, "/main.js") {
		t.Error("the page does not load main.js, so nothing would render")
	}
}

// Everything index.html asks for is served.
//
// Derived from the page rather than listed, because a list is the thing that went wrong.
// The embed directive names its files on purpose — so nothing lands in web/ and gets served
// by accident — and the cost is that a new module is not served until somebody adds it, with
// nothing failing at build time when they do not. web/testdata/fixture.py serves that
// directory from disk, so the page works perfectly against the fixture and 404s in the real
// binary. That has now happened twice, with dom.js and again with main.js.
func TestEverythingThePageAsksForIsServed(t *testing.T) {
	ts := pageServerFor(t)

	_, _, page := get(t, ts.URL+"/")

	var refs []string
	for _, attr := range []string{`src="`, `href="`} {
		rest := page
		for {
			i := strings.Index(rest, attr)
			if i < 0 {
				break
			}
			rest = rest[i+len(attr):]
			end := strings.IndexByte(rest, '"')
			if end < 0 {
				break
			}
			// Local paths only: a link to the repository is not this server's to answer.
			if ref := rest[:end]; strings.HasPrefix(ref, "/") {
				refs = append(refs, ref)
			}
			rest = rest[end:]
		}
	}

	if len(refs) == 0 {
		t.Fatal("the page references nothing local, which cannot be right")
	}
	for _, ref := range refs {
		if status, _, _ := get(t, ts.URL+ref); status != http.StatusOK {
			t.Errorf("the page asks for %s and it answers %d — is it in web/embed.go?", ref, status)
		}
	}
}

func TestTheAssetsAreServed(t *testing.T) {
	ts := pageServerFor(t)

	for _, tc := range []struct{ path, wantType, wantBody string }{
		{"/main.js", "javascript", "bootstrap"},
		{"/app.js", "javascript", "poll_after_seconds"},
		{"/dom.js", "javascript", "morphChildren"},
		{"/app.css", "text/css", "--bg"},
	} {
		status, header, body := get(t, ts.URL+tc.path)
		if status != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", tc.path, status)
			continue
		}
		if ct := header.Get("Content-Type"); !strings.Contains(ct, tc.wantType) {
			t.Errorf("GET %s Content-Type = %q, want it to name %s", tc.path, ct, tc.wantType)
		}
		if !strings.Contains(body, tc.wantBody) {
			t.Errorf("GET %s does not contain %q", tc.path, tc.wantBody)
		}
	}
}

// The regression that took the container down, and the one this package could not see.
//
// meshp-control registers `/api/v1/` on its mux while the database is still coming up, so
// the API's own routes go on beside it. A `GET /` catch-all conflicts with a pattern that
// names no method — neither is more specific — and ServeMux reports that by panicking at
// registration. Every test here passed while the shipped binary died at startup, because
// they all built a mux holding only these routes.
func TestThePageDoesNotClaimTheWholeURLSpace(t *testing.T) {
	mux := http.NewServeMux()
	// What the control plane has already registered by the time the API is wired up.
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "still starting up", http.StatusServiceUnavailable)
	})

	// Panics on a conflicting pattern, which is the whole assertion.
	New(nil, nil, nil, Config{}).Routes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// Both still answer: the page at the root, and the bootstrap route for anything under
	// /api/v1 that the API did not claim.
	if status, _, _ := get(t, ts.URL+"/"); status != http.StatusOK {
		t.Errorf("GET / = %d, want 200", status)
	}
	if status, _, body := get(t, ts.URL+"/api/v1/not-a-route"); status != http.StatusServiceUnavailable {
		t.Errorf("GET /api/v1/not-a-route = %d (%q), want the bootstrap route's 503", status, body)
	}
}

// An unknown path is not quietly answered with the page.
//
// The page routes on the fragment, which never reaches a server, so there is no history
// mode to support and no reason to fall back to index.html. A server that did would turn
// every mistyped URL into a dashboard, which looks like it worked.
func TestAnUnknownPathIsNotThePage(t *testing.T) {
	ts := pageServerFor(t)

	for _, path := range []string{"/networks/not-a-route", "/api/v1/not-a-route", "/index.html/extra"} {
		status, _, body := get(t, ts.URL+path)
		if status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, status)
		}
		if strings.Contains(body, "/app.js") {
			t.Errorf("GET %s was answered with the page", path)
		}
	}
}

// The cookie is HttpOnly, which stops a script reading it — but any script on this origin
// can spend it, because the browser attaches it here. These headers are what keeps a
// foreign script off the origin, so they are asserted rather than assumed.
func TestThePageCarriesItsSecurityHeaders(t *testing.T) {
	ts := pageServerFor(t)

	_, header, _ := get(t, ts.URL+"/")
	csp := header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("Content-Security-Policy = %q, want it to contain %q", csp, want)
		}
	}
	if got := header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

// Only the three files are embedded.
//
// A go:embed pattern is one character away from being much wider than it looks, and the
// failure is silent: `embed.go` itself, or a stray note left in this directory, would
// simply start being served. This is what notices.
func TestOnlyThePageIsEmbedded(t *testing.T) {
	ts := pageServerFor(t)

	for _, path := range []string{"/embed.go", "/app.js.map", "/.gitignore"} {
		status, _, _ := get(t, ts.URL+path)
		if status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404: something beyond the page is embedded", path, status)
		}
	}
}
