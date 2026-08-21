package api

import (
	"io/fs"
	"net/http"

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

// routePage registers the view (ADR-0022 §2), one route per embedded file.
//
// Explicitly, rather than as a `GET /` catch-all. The catch-all is the obvious way to
// serve a page and it is wrong here twice over.
//
// It panics. A pattern registered without a method conflicts with `GET /` — neither is
// more specific — and meshp-control registers `/api/v1/` on its mux before the database is
// up, so the two together take the process down at startup. Every test in this package
// passed while that was true, because they build a mux holding only these routes.
//
// And it over-serves. A catch-all answers /anything-at-all with the page, which turns a
// mistyped URL into a dashboard that looks like it worked. Registering exactly what is
// embedded means the served set and the embedded set cannot drift, because they are the
// same list read once.
func (s *Server) routePage(mux *http.ServeMux) {
	entries, err := fs.ReadDir(web.FS, ".")
	if err != nil {
		// Unreachable: the FS is built at compile time from a fixed pattern. Logged rather
		// than ignored, because the failure it would describe is a page that silently is
		// not there.
		s.log.Error("could not read the embedded page", "error", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		mux.Handle("GET /"+entry.Name(), http.HandlerFunc(s.handlePage))
	}
	// {$} matches the root and nothing below it, so this claims one path rather than the
	// whole space beneath it.
	mux.Handle("GET /{$}", http.HandlerFunc(s.handlePage))
}

// handlePage serves the view.
//
// From the same binary and the same port as the API it reads, so a self-hoster's
// deployment stays the one unit deploy/systemd describes rather than gaining a second
// artefact, a second port and a CORS policy between two halves of one product.
func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
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
// There is no history-mode fallback to index.html, and no route reaches this for a path
// that is not an embedded file. The page routes on the fragment, which never reaches a
// server, so there is nothing for a fallback to serve.
var pageServer = http.FileServerFS(web.FS)
