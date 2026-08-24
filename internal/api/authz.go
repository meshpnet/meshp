package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/authz"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/secret"
	"github.com/meshpnet/meshp/internal/store"
)

// caller is who a request is.
//
// Deliberately not "who a request is and what it may do". What a caller may do depends on
// where it is asking — a role granted on one network says nothing about another, and an
// organisation-wide permission is not granted by a binding narrowed to a network — so the
// permission set is resolved against the scope the route names rather than carried around.
type caller struct {
	// user is the signed-in person, or nil for the credentials that are not people.
	//
	// A token caller leaves this nil even though it has an owner. Nothing that requires a
	// person should accept a machine holding that person's credential: minting a token,
	// changing a password. Setting this to the owner would make both work, silently.
	user *store.User

	// token is a machine acting through somebody's API token (ADR-0024 §2). What it may do
	// is its owner's current permissions intersected with the scope it was minted with,
	// resolved at every request.
	token *store.APIToken

	// bootstrap is the administrative token itself: the deployment's root credential, which
	// holds every permission including ones that do not exist yet (ADR-0024 §5).
	bootstrap bool
}

type callerKey struct{}

func withCaller(ctx context.Context, c caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// callerFrom is who this request is, as decided by the middleware that let it through.
//
// Every handler behind an authenticated guard has one. A handler that reads this and finds
// nothing is one somebody registered as public, which is a bug in the route table rather
// than a case to handle.
func callerFrom(r *http.Request) caller {
	c, _ := r.Context().Value(callerKey{}).(caller)
	return c
}

// identify works out who is asking, without deciding whether they may.
//
// Three credentials, in the order that matters. A signed-in person is checked first and
// without reference to the administrative token: a deployment that has created accounts and
// unset MESHP_ADMIN_TOKEN is where ADR-0024 is heading, and it must not be one where nobody
// can do anything.
func (s *Server) identify(r *http.Request) (caller, bool) {
	if user := s.sessionUser(r); user != nil {
		return caller{user: user}, true
	}

	presented := bearer(r)
	if s.cfg.AdminToken != "" &&
		subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.AdminToken)) == 1 {
		s.warnBootstrapTokenUsed(r)
		return caller{bootstrap: true}, true
	}

	// An API token is recognised by its prefix before any lookup, so a header carrying
	// something else costs nothing. Checked after the administrative token rather than
	// before, because that comparison is constant time and cheap and this one is a query.
	if secret.LooksLike(store.APITokenPrefix, presented) {
		token, err := s.store.FindToken(r.Context(), presented)
		if err != nil {
			// Expired, revoked, unknown, or owned by a suspended account: all the same
			// answer. A machine holding a dead credential learns that it is dead, and
			// every one of those needs the same thing done about it.
			s.log.Warn("an API token was refused",
				"path", logx.Safe(r.URL.Path), "remote", logx.Safe(clientKey(r)))
			return caller{}, false
		}
		return caller{token: &token}, true
	}

	return caller{}, false
}

// permissionsInNetwork is what this caller may do in one network.
//
// A query per request for a signed-in person, and per request on purpose: permissions baked
// into a session at sign-in would leave somebody who has just been demoted holding their old
// powers until they happened to sign out. That is the one thing a permission system must not
// do, and it is worth a lookup.
func (s *Server) permissionsInNetwork(r *http.Request, c caller, networkID uuid.UUID) (authz.Set, error) {
	switch {
	case c.bootstrap:
		return authz.All(), nil
	case c.token != nil:
		return s.store.TokenPermissions(r.Context(), *c.token, &networkID)
	default:
		return s.store.PermissionsInNetwork(r.Context(), networkID, c.user.ID)
	}
}

// permissionsInOrganization is what this caller may do across one organisation.
//
// Organisation-wide bindings only — a grant narrowed to one network never reaches here. A
// person asking about an organisation that is not theirs holds nothing in it, which the
// query answers without this needing to compare anything.
func (s *Server) permissionsInOrganization(r *http.Request, c caller, orgID uuid.UUID) (authz.Set, error) {
	switch {
	case c.bootstrap:
		return authz.All(), nil
	case c.token != nil:
		if c.token.OrganizationID != orgID {
			// A token belongs to one organisation, as its owner does. Asked about another,
			// it holds nothing — rather than falling through to a lookup that would answer
			// the same way but for a reason somebody would have to work out.
			return authz.NewSet(nil), nil
		}
		return s.store.TokenPermissions(r.Context(), *c.token, nil)
	default:
		return s.store.PermissionsInOrganization(r.Context(), orgID, c.user.ID)
	}
}

// refuse says no to somebody who is who they say they are and may not do this.
//
// 403 rather than 404, and the permission is named. The catalogue is public API, so naming
// it discloses nothing, and it turns "that didn't work" into a sentence somebody can hand to
// whoever administers their organisation.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, c caller, held authz.Set, want authz.Permission) {
	who := "this session"
	switch {
	case c.user != nil:
		who = c.user.Email
	case c.token != nil:
		who = "token " + c.token.Name + " (" + c.token.OwnerEmail + ")"
	}
	s.log.Info("request refused",
		"path", logx.Safe(r.URL.Path), "code", "forbidden",
		"who", logx.Safe(who), "permission", string(want))

	if held.Empty() {
		// Told apart from an ordinary refusal because the fix is different: somebody has
		// to be given a role, rather than a different one. This is the shape of an account
		// created before it was granted anything.
		httpx.Error(w, s.log, http.StatusForbidden, "forbidden",
			"you hold no role here, so you may do nothing; ask somebody who can grant one")
		return
	}
	httpx.Error(w, s.log, http.StatusForbidden, "forbidden",
		"this needs the "+string(want)+" permission, which you do not hold here")
}

func (s *Server) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AdminToken == "" {
		httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized",
			"sign in, or set MESHP_ADMIN_TOKEN to bootstrap the first account")
		return
	}
	s.log.Warn("request rejected",
		"path", logx.Safe(r.URL.Path), "remote", logx.Safe(clientKey(r)))
	httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized",
		"sign in, or present a valid administrative token")
}

// callerOrganization is the one organisation this caller belongs to, or nil for the
// administrative token, which belongs to none.
func callerOrganization(c caller) *uuid.UUID {
	switch {
	case c.user != nil:
		return &c.user.OrganizationID
	case c.token != nil:
		return &c.token.OrganizationID
	default:
		return nil
	}
}

// safeMethod reports whether a request only reads.
func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// sameOrigin reports whether an unsafe request came from this site.
//
// The cross-site request forgery defence, and it is written down rather than assumed because
// what it is defending changed. While the browser's credential could only read, SameSite=Strict
// carried the whole burden and that was adequate: the worst a forged request could achieve was
// to make somebody's browser read something on their behalf. A cookie that can revoke a device
// deserves an argument.
//
// Two things now stand in the way, and they fail independently:
//
//   - SameSite=Strict, so a browser does not attach the cookie to a request another site
//     caused at all. This is the strong one and it is enforced by the browser.
//   - This check, which is what remains if that is bypassed — by a browser that does not
//     implement it, or by a bug in one. A cross-origin form POST cannot suppress the Origin
//     header, and a cross-origin fetch that sets one this endpoint would accept cannot get
//     past the preflight, because nothing here answers with CORS headers.
//
// Hosts are compared and schemes are not. A TLS-terminating proxy in front leaves r.TLS nil
// while the browser sends an https Origin, and this package deliberately does not consult
// X-Forwarded-Proto — a header a client can set should not decide whether a write is allowed.
// Scheme downgrade is the cookie's problem and the cookie is Secure, so it never travels over
// plaintext to be replayed.
//
// Only cookie-authenticated requests are checked. A bearer token is not attached by a browser
// to anything, so there is nothing to forge; and requiring an Origin from `curl`, which sends
// none, would break every machine caller to defend against an attack they cannot suffer.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Absent, on an unsafe method, from a request carrying a cookie. Every browser
		// sends it for POST, PUT and DELETE, so this is not one — and a request that is
		// not a browser has no business using the browser's credential.
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}
