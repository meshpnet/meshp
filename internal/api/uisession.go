package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/logx"
)

// The browser's credential, and the whole of what makes a UI defensible before user
// accounts exist (ADR-0022 §5).
//
// It is derived from the administrative token and strictly weaker than it: it authorises
// the two read endpoints and nothing else, so a stolen browser session reads a network and
// cannot mint an enrolment token, publish a policy or revoke a device. That asymmetry is
// the entire justification for shipping a page against a single shared secret, and it stops
// being sufficient the moment the UI grows a write path — at which point per-user accounts
// are a prerequisite rather than a follow-up. The users, roles and role_bindings tables
// have been in the schema since the first migration, waiting for a reader.
const (
	// uiCookieName is prefixed because the prefix is enforced by the browser: a cookie
	// named __Host- may only be set over TLS, with no Domain, and Path=/. A page that
	// somehow reached this over plaintext could not have its cookie set at all rather
	// than having it set insecurely.
	uiCookieName = "__Host-meshp_ui"

	// uiSessionIdle is how long a session survives without being used.
	//
	// Sliding, because the page this exists for polls every few seconds: a dashboard
	// somebody is watching never expires under them, and one abandoned on an unlocked
	// laptop is dead within the window. A fixed lifetime would have to choose between
	// those two and would get one of them wrong.
	uiSessionIdle = 30 * time.Minute

	// uiSessionMaxAge is the ceiling that no amount of use extends.
	//
	// Without it a page left open on a wall holds a credential derived from the
	// deployment's root password forever, and "revocable server-side" would mean
	// "revocable if somebody remembers".
	uiSessionMaxAge = 12 * time.Hour

	// maxUISessions bounds the store. Logins are rare and each entry is small, so this is
	// not a capacity decision — it is what stops an endpoint that allocates on success
	// from being a way to grow the heap once somebody has the token.
	maxUISessions = 1024
)

// uiSession is one logged-in browser.
type uiSession struct {
	// idleDeadline moves forward on use; absoluteDeadline never does.
	idleDeadline     time.Time
	absoluteDeadline time.Time
}

// uiSessions holds them, in memory and in this process only.
//
// Deliberately not in PostgreSQL. A browser session is ephemeral by the same argument
// ADR-0012 makes for presence — losing it costs a login, not correctness — and writing one
// row per page load into the tables that hold desired state would be the wrong trade. The
// consequence is that a restart logs everybody out, and that multi-replica does not work,
// which is already true of this control plane for other reasons ADR-0022 sets out.
type uiSessions struct {
	clk clock.Clock

	mu sync.Mutex
	// Keyed by the SHA-256 of the token rather than by the token. The value a browser
	// presents is then not sitting in this process's memory, so a heap dump or a core file
	// does not hand somebody a live session.
	byHash map[[32]byte]uiSession
}

// errTooManySessions means the store is full. Refusing is deliberate: evicting somebody
// else's session instead would make a flood of sign-ins a way to log out whoever is
// actually watching.
var errTooManySessions = errors.New("api: too many browser sessions")

func newUISessions(clk clock.Clock) *uiSessions {
	if clk == nil {
		clk = clock.System{}
	}
	return &uiSessions{clk: clk, byHash: make(map[[32]byte]uiSession)}
}

// create mints a session and returns the value the browser will present.
func (u *uiSessions) create() (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	now := u.clk.Now()
	absolute := now.Add(uiSessionMaxAge)

	u.mu.Lock()
	defer u.mu.Unlock()
	// Swept here rather than on a timer: logins are the only thing that grows this map, so
	// they are the only moment it needs tidying, and a goroutine per server for a map that
	// is usually empty is not worth owning.
	u.sweepLocked(now)
	if len(u.byHash) >= maxUISessions {
		// Refusing rather than evicting somebody else's session. Eviction would make a
		// flood of logins a way to log out whoever is actually watching.
		return "", time.Time{}, errTooManySessions
	}
	u.byHash[sha256.Sum256([]byte(token))] = uiSession{
		idleDeadline:     now.Add(uiSessionIdle),
		absoluteDeadline: absolute,
	}
	return token, absolute, nil
}

// valid reports whether a presented token names a live session, and extends it if so.
func (u *uiSessions) valid(token string) bool {
	if token == "" {
		return false
	}
	key := sha256.Sum256([]byte(token))
	now := u.clk.Now()

	u.mu.Lock()
	defer u.mu.Unlock()
	session, ok := u.byHash[key]
	if !ok {
		return false
	}
	if now.After(session.idleDeadline) || now.After(session.absoluteDeadline) {
		delete(u.byHash, key)
		return false
	}
	// The idle window moves; the ceiling does not, and the new window is clamped to it so
	// a busy page cannot walk past the absolute deadline one poll at a time.
	session.idleDeadline = now.Add(uiSessionIdle)
	if session.idleDeadline.After(session.absoluteDeadline) {
		session.idleDeadline = session.absoluteDeadline
	}
	u.byHash[key] = session
	return true
}

// revoke ends one session. Ending a session that does not exist is success: a browser
// logging out with a cookie this process has already forgotten has got what it asked for.
func (u *uiSessions) revoke(token string) {
	if token == "" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.byHash, sha256.Sum256([]byte(token)))
}

func (u *uiSessions) sweepLocked(now time.Time) {
	for key, session := range u.byHash {
		if now.After(session.idleDeadline) || now.After(session.absoluteDeadline) {
			delete(u.byHash, key)
		}
	}
}

// handleUILogin exchanges the administrative token for a cookie.
//
// The token arrives in the body rather than in a header, because that is what a login form
// produces and the point of this endpoint is that the token is typed once and never stored.
// What reaches the browser afterwards is HttpOnly, so no script on the page can read it
// back out, and the token itself never becomes something JavaScript holds between requests.
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
		Token string `json:"token"`

		// A person signing in with their own account (ADR-0024). Which path this request
		// takes is decided by whether it carries an email rather than by a separate
		// endpoint: one cookie, one sign-in URL, one thing a browser has to know about.
		Email        string `json:"email"`
		Password     string `json:"password"`
		Organization string `json:"organization"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	if body.Email != "" {
		s.signInWithPassword(w, r, body.Email, body.Password, body.Organization)
		return
	}

	// The administrative token, which is the bootstrap path and is on its way out. ADR-0024
	// §5 keeps it working — a deployment that has locked itself out has no other way back —
	// and stops teaching it.
	if s.cfg.AdminToken == "" {
		httpx.Error(w, s.log, http.StatusServiceUnavailable, "admin_disabled",
			"sign in with an email address and password, or set MESHP_ADMIN_TOKEN to bootstrap the first account")
		return
	}
	// Constant time, for the reason adminOnly gives: otherwise the secret can be learned
	// one byte at a time from how long this takes.
	if subtle.ConstantTimeCompare([]byte(body.Token), []byte(s.cfg.AdminToken)) != 1 {
		s.log.Warn("a browser sign-in was refused", "remote", logx.Safe(clientKey(r)))
		httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized",
			"that is not the administrative token")
		return
	}

	token, expires, err := s.ui.create()
	if err != nil {
		s.log.Error("could not mint a browser session", "error", err)
		httpx.Error(w, s.log, http.StatusServiceUnavailable, "unavailable",
			"could not start a session; try again")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  uiCookieName,
		Value: token,
		Path:  "/",
		// HttpOnly so no script reads it, Secure so it never crosses a plaintext hop, and
		// SameSite=Strict so another origin cannot make a browser spend it — which is also
		// what stands in for a CSRF token on the sign-out route below.
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
		MaxAge:   int(uiSessionMaxAge / time.Second),
	})
	httpx.WriteJSON(w, s.log, http.StatusCreated, map[string]any{
		"expires_at": expires.UTC(),
		// Said out loud so a consumer is not left to infer it from a 401 later.
		"authorises": []string{"read"},
	})
}

// handleUILogout ends the session and clears the cookie.
func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(uiCookieName); err == nil {
		// Both stores, because one cookie now names either kind of session and this end
		// cannot tell which without asking. Ending one that does not exist is free.
		s.ui.revoke(cookie.Value)
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

// readable gates an endpoint on either the administrative token or a browser session.
//
// The only middleware that accepts a cookie, and it is applied only to the endpoints that
// answer questions. Everything that creates or changes something stays on adminOnly, which
// is what keeps the browser's credential strictly weaker than the one it came from.
func (s *Server) readable(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A signed-in person first, and without reference to the administrative token: a
		// deployment that has created accounts and unset MESHP_ADMIN_TOKEN is the end state
		// ADR-0024 is heading towards, and it must not be one where nobody can read
		// anything.
		if s.sessionUser(r) != nil {
			next(w, r)
			return
		}
		if s.cfg.AdminToken == "" {
			httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized",
				"sign in, or set MESHP_ADMIN_TOKEN to bootstrap the first account")
			return
		}
		if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.AdminToken)) == 1 {
			next(w, r)
			return
		}
		if cookie, err := r.Cookie(uiCookieName); err == nil && s.ui.valid(cookie.Value) {
			next(w, r)
			return
		}
		httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized",
			"a valid administrative token or browser session is required")
	})
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
