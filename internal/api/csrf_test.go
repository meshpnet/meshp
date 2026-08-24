package api

import (
	"bytes"
	"net/http"
	"testing"
)

// asCookie makes a request with a browser session and whatever Origin the caller names,
// including none.
func (h *harness) asCookie(method, path string, cookie *http.Cookie, origin string) int {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.server.URL+path, bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A write a browser was tricked into making from another site is refused.
//
// SameSite=Strict is the strong defence and the browser enforces it, so this never runs in a
// browser that implements it correctly. That is exactly why it is here: it is what remains
// when that one is bypassed, and a defence with a single layer is one that has never been
// asked what happens if it fails.
//
// Until permissions arrived the browser's credential could only read, and the worst a forged
// request could achieve was making somebody read something. A cookie that can revoke a
// device deserves the second layer.
func TestAWriteFromAnotherSiteIsRefused(t *testing.T) {
	h := newHarness(t)
	cookie := h.loginAs("owner")
	path := "/api/v1/networks/" + h.netID.String() + "/enrollment-tokens"

	for _, tc := range []struct {
		name   string
		origin string
	}{
		{"another site entirely", "https://attacker.example"},
		{"a lookalike host", "https://" + h.server.Listener.Addr().String() + ".attacker.example"},
		{"no origin at all", ""},
		{"not a URL", "null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.asCookie(http.MethodPost, path, cookie, tc.origin); got != http.StatusForbidden {
				t.Errorf("a write with Origin %q = %d, want 403", tc.origin, got)
			}
		})
	}

	// And the same request from this site works, or the check would be refusing everything
	// and this test would pass for the wrong reason.
	if got := h.asCookie(http.MethodPost, path, cookie, h.server.URL); got != http.StatusCreated {
		t.Errorf("a write from this site = %d, want 201", got)
	}
}

// Reads are not checked, because there is nothing to forge: a cross-site read the browser
// would have attached the cookie to is one SameSite already stopped, and refusing a GET
// without an Origin would break every page load, which sends none.
func TestAReadNeedsNoOrigin(t *testing.T) {
	h := newHarness(t)
	cookie := h.loginAs("reader")

	if got := h.asCookie(http.MethodGet, "/api/v1/networks", cookie, ""); got != http.StatusOK {
		t.Errorf("a read with no Origin = %d, want 200", got)
	}
}

// A machine is not checked, because a bearer token is not something a browser attaches to a
// request another site caused. Requiring an Origin here would break every caller that is not
// a browser — `curl` sends none — to defend against an attack they cannot suffer.
func TestAMachineNeedsNoOrigin(t *testing.T) {
	h := newHarness(t)

	req, _ := http.NewRequest(http.MethodPost,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/enrollment-tokens",
		bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAdminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("the administrative token writing with no Origin = %d, want 201", resp.StatusCode)
	}
}
