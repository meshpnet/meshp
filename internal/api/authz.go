package api

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/authz"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/store"
)

// caller is who a request is.
//
// Deliberately not "who a request is and what it may do". What a caller may do depends on
// where it is asking — a role granted on one network says nothing about another, and an
// organisation-wide permission is not granted by a binding narrowed to a network — so the
// permission set is resolved against the scope the route names rather than carried around.
type caller struct {
	// user is the signed-in person, or nil for the two credentials that are not people.
	user *store.User

	// bootstrap is the administrative token itself: the deployment's root credential, which
	// holds every permission including ones that do not exist yet (ADR-0024 §5).
	bootstrap bool

	// readOnly is a browser session minted from the administrative token (ADR-0022 §5).
	// Strictly weaker than the secret it came from: it holds every permission that only
	// reads and nothing else, which is the whole argument for having shipped a page before
	// there were accounts. Nothing mints these once people sign in with their own accounts.
	readOnly bool
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
	if s.cfg.AdminToken != "" {
		if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.AdminToken)) == 1 {
			s.warnBootstrapTokenUsed(r)
			return caller{bootstrap: true}, true
		}
		if cookie, err := r.Cookie(uiCookieName); err == nil && s.ui.valid(cookie.Value) {
			return caller{readOnly: true}, true
		}
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
	case c.readOnly:
		return authz.ReadOnly(), nil
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
	case c.readOnly:
		return authz.ReadOnly(), nil
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
	if c.user != nil {
		who = c.user.Email
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
