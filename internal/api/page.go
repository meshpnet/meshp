package api

import (
	"net/http"
	"strings"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/web"
)

// contentSecurityPolicy is what the page is allowed to do.
//
// The browser's credential is an HttpOnly cookie, which stops a script reading it — but a
// script running on this origin can spend it, because the browser attaches it to every
// request here. So the value of the cookie being HttpOnly depends on no foreign script
// running, and this is what says so to the browser rather than leaving it to review.
//
// 'none' by default and widened one directive at a time. `form-action 'none'` is not
// decoration: the sign-in form takes the administrative token, and its submit handler
// cancels the real submission — a policy that forbids form submission entirely means a
// bug in that handler cannot turn into a token in somebody's access log.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// handlePage serves the view (ADR-0022 §2).
//
// From the same binary and the same port as the API it reads, so a self-hoster's
// deployment stays the one unit deploy/systemd describes rather than gaining a second
// artefact, a second port and a CORS policy between two halves of one product.
func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	// This is the catch-all for GET, so anything under /api/ that matched no route above
	// arrives here. It must not be answered with HTML: a caller that asked for JSON and
	// got a page back learns nothing about what it got wrong.
	if strings.HasPrefix(r.URL.Path, "/api/") {
		httpx.Error(w, s.log, http.StatusNotFound, "no_such_endpoint", "no such endpoint")
		return
	}

	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// The files change when the binary does and carry no version in their names, so a
	// cached copy would outlive an upgrade. no-cache revalidates rather than forbidding
	// storage; they are three small files and this is not the expensive part of a poll.
	w.Header().Set("Cache-Control", "no-cache")

	pageServer.ServeHTTP(w, r)
}

// pageServer serves the embedded files. Built once: it holds no request state, and
// rebuilding it per request would re-read the FS index every time.
//
// There is no history-mode fallback to index.html for unknown paths. The page routes on
// the fragment, which never reaches a server, so a request for a path that is not a file
// is a request for something that does not exist — and answering it with the page would
// turn every typo into a dashboard that silently shows the wrong thing.
var pageServer = http.FileServerFS(web.FS)
