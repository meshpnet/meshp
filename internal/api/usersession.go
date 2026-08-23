package api

import (
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/store"
)

// sessionUser returns the person this request is signed in as, or nil.
//
// Nil and no error is the ordinary answer for a request carrying no cookie, so callers can
// treat "not signed in" as a state rather than a failure. A database error is also nil:
// somebody who cannot be authenticated is not authenticated, and the alternative — failing
// open — is the one outcome that must not happen when the store is unwell.
func (s *Server) sessionUser(r *http.Request) *store.User {
	cookie, err := r.Cookie(uiCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	user, err := s.store.SessionUser(r.Context(), cookie.Value)
	if err != nil {
		s.log.Error("could not read a browser session", "error", err)
		return nil
	}
	return user
}

// signInWithPassword opens a session for a person.
//
// The other half of handleUILogin. Which path a request takes is decided by whether it
// carries an email, not by a separate endpoint: there is one cookie, one sign-in URL, and
// one thing a browser has to know about. When ADR-0024's later slices remove the
// administrative token from this endpoint, what is left is this function and no new route.
func (s *Server) signInWithPassword(w http.ResponseWriter, r *http.Request, email, plain, orgSlug string) {
	// Named by slug rather than id, because somebody typing this into a sign-in form has a
	// slug and would have to look an id up. Resolved before the password is checked, and a
	// slug that does not exist is refused exactly like a wrong password: whether an
	// organisation exists is not a question this endpoint should answer to a stranger.
	var orgID uuid.UUID
	if orgSlug != "" {
		orgs, err := s.store.ListOrganizations(r.Context())
		if err != nil {
			s.respondError(w, r, err)
			return
		}
		for _, org := range orgs {
			if org.Slug == orgSlug {
				orgID = org.ID
			}
		}
		if orgID == uuid.Nil {
			s.refuseSignIn(w, r, email)
			return
		}
	}

	session, err := s.store.SignIn(r.Context(), store.SignInRequest{
		Email:        email,
		Password:     plain,
		Organization: orgID,
		UserAgent:    r.UserAgent(),
		SourceIP:     requestAddr(r),
	})
	switch {
	case errors.Is(err, store.ErrSignInAmbiguous):
		// Named as its own failure because it is the one a person can act on, and the
		// action is not "try a different password". ADR-0021 refuses an ambiguous name the
		// same way rather than picking one.
		httpx.Error(w, s.log, http.StatusConflict, "ambiguous_sign_in",
			"that address exists in more than one organisation; sign in with the organisation as well")
		return
	case errors.Is(err, store.ErrSignInRefused):
		s.refuseSignIn(w, r, email)
		return
	case err != nil:
		s.respondError(w, r, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  uiCookieName,
		Value: session.Token,
		Path:  "/",
		// The same flags the administrative cookie carries, for the same reasons: HttpOnly
		// so no script reads it, Secure so it never crosses a plaintext hop, SameSite=Strict
		// so another origin cannot make a browser spend it.
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
		MaxAge:   int(store.SessionMaxAge / time.Second),
	})
	httpx.WriteJSON(w, s.log, http.StatusCreated, map[string]any{
		"user_id":         session.User.ID,
		"email":           session.User.Email,
		"organization_id": session.User.OrganizationID,
		"expires_at":      session.ExpiresAt.UTC(),
	})
}

// refuseSignIn is every way a sign-in can fail that a stranger must not be able to tell
// apart: no such address, wrong password, suspended, deleted, or an organisation that does
// not exist. One message, one status, one log line.
func (s *Server) refuseSignIn(w http.ResponseWriter, r *http.Request, email string) {
	// The address is logged because an operator investigating a burst of failures needs to
	// know whether somebody is guessing at one account or sweeping many. It crosses a trust
	// boundary from whoever typed it, so it is bounded first.
	s.log.Warn("a sign-in was refused",
		"email", logx.Safe(email), "remote", logx.Safe(clientKey(r)))
	httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized",
		"that email address and password do not match")
}

// handleChangeOwnPassword lets a signed-in person change their own password.
//
// Their own, and no one else's. Setting somebody else's is an administrative act and is not
// this route, which is what stops one compromised session from locking a colleague out.
//
// The current password is required even though the caller is already signed in: a session
// left open on an unlocked laptop should not be enough to take an account over.
func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	user := s.sessionUser(r)
	if user == nil {
		httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized",
			"this needs a browser session; sign in first")
		return
	}

	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	// Checked by signing in again rather than by a separate comparison, so there is one
	// place in this codebase that decides whether a password is right.
	if _, err := s.store.SignIn(r.Context(), store.SignInRequest{
		Email:        user.Email,
		Password:     body.Current,
		Organization: user.OrganizationID,
	}); err != nil {
		s.refuseSignIn(w, r, user.Email)
		return
	}

	if err := s.store.SetPassword(r.Context(), user.ID, body.New); err != nil {
		s.respondError(w, r, err)
		return
	}

	// Every session ended, including this one — SetPassword does that, and it is the point.
	// A password is usually changed because somebody else may have seen it, and the change
	// would be worth much less if it left their session running.
	http.SetCookie(w, &http.Cookie{
		Name: uiCookieName, Value: "", Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"changed": true,
		// Said rather than left to be discovered by the next request failing.
		"message": "password changed; every session was ended, including this one",
	})
}

// handleWhoAmI answers who this request is signed in as.
//
// The endpoint a page calls on load to decide whether to show a sign-in form. Answers 200
// with the user or 401 with nothing, so there is no shape for "signed in as nobody".
func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	user := s.sessionUser(r)
	if user == nil {
		httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized", "not signed in")
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"user_id":         user.ID,
		"email":           user.Email,
		"name":            user.Name,
		"organization_id": user.OrganizationID,
	})
}

// requestAddr is the caller's address, for the session record.
//
// From the connection, never from a header. This package already refuses to trust
// X-Forwarded-For for rate limiting on the grounds that a client can set it, and a value
// recorded against a session is read later by somebody deciding whether a sign-in was
// theirs — which is a worse thing to let a stranger write.
func requestAddr(r *http.Request) *netip.Addr {
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	addr := addrPort.Addr().Unmap()
	return &addr
}

// actor is who this request is, for the audit trail.
//
// A signed-in person where there is one; the bootstrap secret otherwise. There is no third
// answer: a request that reached an audited handler got past adminOnly, which accepts
// exactly those two things.
//
// The label for a person is their email rather than their display name, because an audit
// line is read months later by somebody trying to reach whoever did it, and a display name
// is not a way to reach anyone.
func (s *Server) actor(r *http.Request) store.Actor {
	if user := s.sessionUser(r); user != nil {
		return store.UserActor(*user)
	}
	return store.BootstrapActor()
}

// warnBootstrapTokenUsed says, at most occasionally, that the administrative token was used
// on a deployment that has accounts.
//
// ADR-0024 §5 keeps the token working — a deployment locked out of its own control plane has
// no other way back — and asks that using it stop being invisible. Once an account exists,
// reaching for the shared secret means somebody is using it *instead of* an account, and
// that is a fact an operator should be able to see in a log rather than infer.
//
// Throttled hard, and for two reasons rather than one. The obvious one is log noise: the
// commercial layer polls with a bearer token and would otherwise write a line per request.
// The less obvious one is the query behind it — "does this deployment have accounts" is a
// count, and asking it per request would put a scan of the users table in front of every
// administrative call to save a message nobody reads more than once an hour.
func (s *Server) warnBootstrapTokenUsed(r *http.Request) {
	const every = time.Hour

	now := s.cfg.Clock.Now()
	last := s.bootstrapWarnedAt.Load()
	if last != nil && now.Sub(*last) < every {
		return
	}
	if !s.bootstrapWarnedAt.CompareAndSwap(last, &now) {
		// Another request got there first. One of us logs; it does not matter which.
		return
	}

	accounts, err := s.store.AnyUsers(r.Context())
	if err != nil || !accounts {
		// No accounts is the ordinary bootstrap state and says nothing worth logging. A
		// failed count is not worth a second message either — whatever is wrong with the
		// database will be reported by the request that actually needed it.
		return
	}
	s.log.Warn("the bootstrap administrative token was used on a deployment that has accounts",
		"path", logx.Safe(r.URL.Path),
		"remote", logx.Safe(clientKey(r)),
		"hint", "sign in as a user instead; this token is the way back in when nobody can, "+
			"and every use of it is recorded as nobody in particular")
}
