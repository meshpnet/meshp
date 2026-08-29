package api

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strconv"
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
// The whole of handleUILogin now. It used to be one of two paths, chosen by whether the
// request carried an email — the other took the administrative token — and the prediction
// written here was that removing that path would leave this function and no new route.
// That is what happened.
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
	var slow store.SignInThrottled
	switch {
	case errors.As(err, &slow):
		// A 429 rather than the shared refusal, and it is not a leak: the count is kept for
		// every address whether or not an account exists, so being told to wait says nothing
		// about whether there is anybody here to sign in as (ADR-0027). Answering 401 would
		// tell somebody who has mistyped six times that their password is wrong, which is
		// false and makes them keep trying.
		seconds := int(math.Ceil(slow.RetryAfter.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		s.log.Warn("a sign-in was refused for arriving too fast",
			"email", logx.Safe(email), "remote", logx.Safe(clientKey(r)), "retry_after_s", seconds)
		httpx.Error(w, s.log, http.StatusTooManyRequests, "rate_limited",
			fmt.Sprintf("too many failed sign-ins for that address; try again in %d second(s). "+
				"Nothing is locked: the wait is at most a minute and a correct password clears it.",
				seconds))
		return
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
	c := callerFrom(r)
	if c.token != nil {
		// A machine holding somebody's credential must not be able to take their account
		// over with it. The token is theirs to act *within*, not theirs to change.
		httpx.Error(w, s.log, http.StatusForbidden, "person_required",
			"an API token cannot change its owner's password")
		return
	}
	user := c.user
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
	c := callerFrom(r)

	// A machine gets an answer too, and it is a different answer. "What am I, and what was
	// I minted to do" is the first thing a machine asks, and telling it only who its owner
	// is would hide the part that decides whether its next request will work.
	if c.token != nil {
		out := map[string]any{
			"kind":            "api_token",
			"token_id":        c.token.ID,
			"name":            c.token.Name,
			"owner":           c.token.OwnerEmail,
			"organization_id": c.token.OrganizationID,
			"permissions":     c.token.Scope,
			"expires_at":      c.token.ExpiresAt.UTC(),
			// Said plainly, because the scope is a ceiling rather than a grant and a
			// machine reading its own permissions would otherwise assume it holds them.
			"note": "these are the permissions this token may use; what it can actually do " +
				"is these intersected with what its owner holds now",
		}
		if c.token.Network != nil {
			out["network_id"] = *c.token.Network
		}
		httpx.WriteJSON(w, s.log, http.StatusOK, out)
		return
	}

	user := c.user
	if user == nil {
		httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized", "not signed in")
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"kind":            "user",
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
// Taken from what the guard already worked out rather than looked up again: every audited
// handler sits behind a guard that identified the caller, and asking the database a second
// time would put a session read in front of every write to save carrying one value.
//
// A signed-in person where there is one, the API token where a machine is acting through
// somebody's credential, and the bootstrap secret otherwise. The browser session
// derived from that secret holds only read permissions, so it never reaches an audited
// handler — and if it ever did it would be recorded as what it is, which is the shared
// credential rather than a person.
//
// The label for a person is their email rather than their display name, because an audit
// line is read months later by somebody trying to reach whoever did it, and a display name
// is not a way to reach anyone.
func (s *Server) actor(r *http.Request) store.Actor {
	c := callerFrom(r)
	switch {
	case c.user != nil:
		return store.UserActor(*c.user)
	case c.token != nil:
		return store.TokenActor(c.token.ID, c.token.Name, c.token.OwnerEmail)
	default:
		return store.BootstrapActor()
	}
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
	// The hint says what to do, not that something is odd. Whoever reads this line is
	// running a script they wrote months ago and has no reason to know what replaced the
	// credential in it, so a warning that only reports a smell costs them a search.
	s.log.Warn("the bootstrap administrative token was used on a deployment that has accounts",
		"path", logx.Safe(r.URL.Path),
		"remote", logx.Safe(clientKey(r)),
		"what_to_do", "replace this credential with an API token: sign in at POST /api/v1/ui/session, "+
			"then mint one at POST /api/v1/me/tokens naming the permissions it needs",
		"why", "the bootstrap secret has no identity, so the audit trail can only record that it was used "+
			"and not by whom; it cannot be scoped to one network, and revoking it locks out everything else "+
			"still using it",
		"keep_it", "it is still how you get back in when nobody can sign in — see docs/self-hosting.md")
}
