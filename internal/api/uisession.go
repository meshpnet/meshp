package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/meshpnet/meshp/internal/httpx"
)

// The browser's credential (ADR-0022 §5, rewritten by ADR-0024).
//
// It used to be derived from the administrative token and bounded by being unable to write,
// because a credential minted from a shared secret has no identity to attach permissions to.
// That is over: the cookie now names a row in `user_sessions`, belonging to a person, and
// what it may do is what that person may do. There is no separate browser credential left in
// this file — what remains is the sign-in that mints one and the sign-out that ends it.
const (
	// uiCookieName is prefixed because the prefix is enforced by the browser: a cookie
	// named __Host- may only be set over TLS, with no Domain, and Path=/. A page that
	// somehow reached this over plaintext could not have its cookie set at all rather
	// than having it set insecurely.
	uiCookieName = "__Host-meshp_ui"
)

// handleUILogin signs a person in.
//
// An email address and a password, and no longer the administrative token: a browser session
// is a person now, and a shared secret is not one. A deployment with no accounts yet cannot
// sign in here at all, which is correct — it has nothing to look at until somebody creates
// the first user, and creating one is an API call the bootstrap secret still makes
// (ADR-0024 §5).
//
// The credential arrives in the body rather than in a header because that is what a login
// form produces. What reaches the browser afterwards is HttpOnly, so no script on the page
// can read it back out.
func (s *Server) handleUILogin(w http.ResponseWriter, r *http.Request) {
	if !s.canSetSecureCookie(r) {
		// Refused rather than downgraded. A cookie without Secure over a plaintext hop is
		// a credential on the wire, and one that silently worked would make configuring TLS
		// optional for a deployment somebody browses to (ADR-0022 §5).
		httpx.Error(w, s.log, http.StatusBadRequest, "tls_required",
			"signing in needs TLS: set MESHP_TLS_CERT and MESHP_TLS_KEY, or MESHP_TLS_DOMAINS "+
				"for automatic certificates. A TLS-terminating proxy in front is not visible "+
				"from here and is not assumed; reach this over loopback to sign in without one.")
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`

		// Organization narrows the search when one address exists in several. Almost every
		// deployment has one, so almost nobody sends it — the sign-in form asks for it only
		// after being told the address is ambiguous.
		Organization string `json:"organization"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if body.Email == "" {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"sign in with an email address and password")
		return
	}
	s.signInWithPassword(w, r, body.Email, body.Password, body.Organization)
}

// handleUILogout ends the session and clears the cookie.
func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(uiCookieName); err == nil {
		// Ending a session that does not exist is success: a browser signing out with a
		// cookie this deployment has already forgotten has got what it asked for.
		if err := s.store.SignOut(r.Context(), cookie.Value); err != nil {
			// Logged and not returned: the cookie is cleared below either way, and telling
			// a browser its sign-out failed would leave somebody clicking it again.
			s.log.Error("could not end a signed-in session", "error", err)
		}
	}
	// Cleared whether or not there was a session to end, so a browser holding a cookie this
	// process has forgotten does not keep presenting it.
	http.SetCookie(w, &http.Cookie{
		Name:     uiCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// canSetSecureCookie reports whether this request may be given a Secure cookie.
//
// TLS on this connection, or loopback. X-Forwarded-Proto is deliberately not consulted:
// this package already refuses to trust X-Forwarded-For for rate limiting, on the grounds
// that a client can set it, and a header that decides whether a credential may be issued
// is a worse thing to take on trust than one that decides a rate-limit bucket.
//
// Loopback is allowed because every current browser treats localhost as a secure context
// and will store a Secure cookie set over http there, which is what keeps the quickstart
// working without a certificate.
func (s *Server) canSetSecureCookie(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return isLoopbackRequest(r)
}

func isLoopbackRequest(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}
