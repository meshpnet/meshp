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
	if !strings.Contains(body, "/app.js") {
		t.Error("the page does not load app.js, so nothing would render")
	}
}

func TestTheAssetsAreServed(t *testing.T) {
	ts := pageServerFor(t)

	for _, tc := range []struct{ path, wantType, wantBody string }{
		{"/app.js", "javascript", "poll_after_seconds"},
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

// An unknown API path must answer as an API, not as a page.
//
// The page handler is the catch-all for GET, so this is the one that would regress
// silently: a caller that asked for JSON and was handed HTML with a 404 learns nothing
// about what it got wrong, and a client library would fail while parsing rather than
// while checking the status.
func TestAnUnknownAPIPathAnswersAsAnAPI(t *testing.T) {
	ts := pageServerFor(t)

	status, header, body := get(t, ts.URL+"/api/v1/there-is-no-such-thing")
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", status)
	}
	if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(body, "no_such_endpoint") {
		t.Errorf("body = %q, want it to name the failure", body)
	}
	if strings.Contains(body, "<html") {
		t.Error("an API path was answered with the page")
	}
}

// An unknown path is not quietly answered with the page.
//
// The page routes on the fragment, which never reaches a server, so there is no history
// mode to support and no reason to fall back to index.html. A server that did would turn
// every mistyped URL into a dashboard, which looks like it worked.
func TestAnUnknownPathIsNotThePage(t *testing.T) {
	ts := pageServerFor(t)

	status, _, body := get(t, ts.URL+"/networks/not-a-route")
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", status)
	}
	if strings.Contains(body, "/app.js") {
		t.Error("an unknown path was answered with the page")
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
