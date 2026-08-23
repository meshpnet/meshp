// Package api serves meshp-control's HTTP interface.
//
// Two audiences, deliberately separated:
//
//   - Device endpoints under /api/v1/enroll are reachable without a credential,
//     because a device that has nothing yet cannot authenticate. The enrolment
//     token in the body is the credential.
//   - Administrative endpoints require a bootstrap secret. That is a placeholder
//     until users and sessions exist, and it is marked as one everywhere it appears.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/enroll"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/ipam"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/session"
	"github.com/meshpnet/meshp/internal/store"
)

// maxBodyBytes caps request bodies. Every field these endpoints accept is a key, a
// signature or a short string, so anything larger is either a mistake or an attempt
// to make the process allocate.
const maxBodyBytes = 32 << 10

// Config wires a Server.
type Config struct {
	// AdminToken gates the administrative endpoints. When empty they return 503
	// rather than running open: a control plane that will mint enrolment tokens for
	// anyone who asks is worse than one whose admin API is switched off.
	//
	// This is a bootstrap mechanism, not an authentication system. It is a single
	// shared secret with no identity, no scoping and no audit trail beyond "the
	// admin token was used". It exists so tokens can be minted before users and
	// sessions are built, and it should be removed when they are.
	AdminToken string

	// EnrolRatePerSecond and EnrolBurst limit the unauthenticated endpoints.
	EnrolRatePerSecond float64
	EnrolBurst         float64

	Clock clock.Clock
	Log   *slog.Logger
}

// Server holds the dependencies the handlers need.
type Server struct {
	store   *store.Store
	enroll  *enroll.Service
	session *session.Server
	cfg     Config
	log     *slog.Logger
	limit   *limiter

	// presence answers who is connected. Nil when there is no session server, which is
	// how the read endpoints stay usable in a test that does not stand one up: a device
	// with no presence reads as disconnected, which is what it is.
	presence Presence

	// ui holds the browser sessions minted from the administrative token (ADR-0022 §5).
	ui *uiSessions
}

// New builds a Server. store and svc may not be nil; the caller waits until the
// database is ready before constructing one.
func New(st *store.Store, svc *enroll.Service, sess *session.Server, cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.EnrolRatePerSecond <= 0 {
		cfg.EnrolRatePerSecond = 2
	}
	if cfg.EnrolBurst <= 0 {
		cfg.EnrolBurst = 20
	}
	srv := &Server{
		store:   st,
		enroll:  svc,
		session: sess,
		cfg:     cfg,
		log:     cfg.Log,
		limit:   newLimiter(cfg.EnrolRatePerSecond, cfg.EnrolBurst, 10_000, cfg.Clock),
		ui:      newUISessions(cfg.Clock),
	}
	// Taken through the interface rather than held as a *Hub, so the thing that replaces
	// it for multi-replica deployments (ADR-0012) has one place to arrive. A typed nil
	// would satisfy the interface and panic on use, so the hub is only assigned when there
	// is one.
	if sess != nil {
		srv.presence = sess.Hub()
	}
	return srv
}

// Routes registers the API on a mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/enroll/challenge", s.rateLimited(s.handleChallenge))
	mux.Handle("POST /api/v1/enroll", s.rateLimited(s.handleRedeem))

	// Sessions. The challenge endpoint is unauthenticated for the same reason
	// enrolment's is — a device proves itself by signing what it gets back — so it is
	// rate limited alongside them. The upgrade itself is not: it authenticates in its
	// first frame, and throttling reconnects is how a brief control-plane outage turns
	// into a long one when every agent comes back at once.
	mux.Handle("POST /api/v1/session/challenge", s.rateLimited(s.handleSessionChallenge))
	mux.Handle("GET /api/v1/session", http.HandlerFunc(s.handleSession))

	mux.Handle("POST /api/v1/networks/{networkID}/enrollment-tokens", s.adminOnly(s.handleCreateToken))
	mux.Handle("GET /api/v1/networks/{networkID}/enrollment-tokens", s.adminOnly(s.handleListTokens))
	mux.Handle("DELETE /api/v1/networks/{networkID}/enrollment-tokens/{tokenID}", s.adminOnly(s.handleRevokeToken))

	mux.Handle("GET /api/v1/networks/{networkID}/devices", s.adminOnly(s.handleListMemberships))
	mux.Handle("DELETE /api/v1/networks/{networkID}/devices/{membershipID}", s.adminOnly(s.handleRevokeMembership))

	// The names an administrator writes down, which nothing can derive from the peer list
	// (ADR-0021 §2). Reading is browser-readable like the rest of a network's state;
	// writing is not, which is the line ADR-0022 §5 draws.
	mux.Handle("GET /api/v1/networks/{networkID}/dns-records", s.readable(s.handleListDNSRecords))
	mux.Handle("POST /api/v1/networks/{networkID}/dns-records", s.adminOnly(s.handleCreateDNSRecord))
	mux.Handle("DELETE /api/v1/networks/{networkID}/dns-records/{recordID}", s.adminOnly(s.handleDeleteDNSRecord))

	mux.Handle("GET /api/v1/networks/{networkID}/acl", s.adminOnly(s.handleGetPolicy))
	mux.Handle("PUT /api/v1/networks/{networkID}/acl", s.adminOnly(s.handlePublishPolicy))
	mux.Handle("GET /api/v1/networks/{networkID}/acl/versions", s.adminOnly(s.handleListPolicyVersions))

	// The tenant networks belong to. Administrative both ways: an organisation is not
	// scoped to a network, so the browser's credential does not reach it (ADR-0022 §5).
	mux.Handle("POST /api/v1/organizations", s.adminOnly(s.handleCreateOrganization))
	mux.Handle("GET /api/v1/organizations", s.adminOnly(s.handleListOrganizations))

	// People (ADR-0024). Every account these make is an administrator account until roles
	// land, which adminOnly says at more length.
	mux.Handle("POST /api/v1/organizations/{organizationID}/users", s.adminOnly(s.handleCreateUser))
	mux.Handle("GET /api/v1/organizations/{organizationID}/users", s.adminOnly(s.handleListUsers))
	mux.Handle("PUT /api/v1/organizations/{organizationID}/users/{userID}/suspended", s.adminOnly(s.handleSetUserSuspended))
	mux.Handle("PUT /api/v1/organizations/{organizationID}/users/{userID}/password", s.adminOnly(s.handleSetUserPassword))
	mux.Handle("DELETE /api/v1/organizations/{organizationID}/users/{userID}", s.adminOnly(s.handleDeleteUser))

	// Who this request is, and the one password a session may change without help. Neither
	// is behind adminOnly: they are about the caller rather than about the deployment, and
	// gating "who am I" on being an administrator would make the sign-in page unable to ask.
	mux.Handle("GET /api/v1/me", http.HandlerFunc(s.handleWhoAmI))
	mux.Handle("POST /api/v1/me/password", http.HandlerFunc(s.handleChangeOwnPassword))

	mux.Handle("POST /api/v1/networks", s.adminOnly(s.handleCreateNetwork))
	mux.Handle("GET /api/v1/networks", s.readable(s.handleListNetworks))

	// The one read endpoint (ADR-0022). Everything else under /api/v1 creates or changes
	// something; this answers a question about a network, and the commercial layer builds
	// its cross-tenant roll-up on it, so its shape is not this page's to choose.
	mux.Handle("GET /api/v1/networks/{networkID}/overview", s.readable(s.handleNetworkOverview))

	// The audit trail. Readable by the browser as of the amendment to ADR-0022 §5: the
	// cookie is scoped to reads within one network, and this is one — it carries more than
	// the overview does, and it carries it about the same network.
	mux.Handle("GET /api/v1/networks/{networkID}/audit", s.readable(s.handleListAuditEvents))

	// Signing in, which is the only route that takes the administrative token in a body.
	// Rate limited with the enrolment endpoints: it is the one place a wrong secret can be
	// guessed at, and while guessing a 32-byte secret is not a real threat, an endpoint
	// that allocates on success should not be free to hammer.
	mux.Handle("POST /api/v1/ui/session", s.rateLimited(s.handleUILogin))
	mux.Handle("DELETE /api/v1/ui/session", http.HandlerFunc(s.handleUILogout))

	// The page itself (ADR-0022 §2), registered as one route per embedded file rather
	// than as a catch-all — see routePage for why that distinction is load-bearing.
	s.routePage(mux)

	// Its own sub-resource rather than a field on a general network update, because this
	// is the one setting here that can decide whether a laptop leaks. A PUT that names it
	// in the path cannot be made by accident, reads unambiguously in an access log, and
	// leaves no room for a partial update that silently carries it along.
	mux.Handle("GET /api/v1/networks/{networkID}/egress-fail-closed", s.adminOnly(s.handleGetEgressFailClosed))
	mux.Handle("PUT /api/v1/networks/{networkID}/egress-fail-closed", s.adminOnly(s.handleSetEgressFailClosed))

	mux.Handle("GET /api/v1/networks/{networkID}/route-groups", s.adminOnly(s.handleListRouteGroups))
	mux.Handle("POST /api/v1/networks/{networkID}/route-groups", s.adminOnly(s.handleCreateRouteGroup))
	mux.Handle("DELETE /api/v1/networks/{networkID}/route-groups/{slug}", s.adminOnly(s.handleDeleteRouteGroup))
	mux.Handle("POST /api/v1/networks/{networkID}/route-groups/{slug}/advertisers", s.adminOnly(s.handleAdvertise))
	mux.Handle("DELETE /api/v1/networks/{networkID}/route-groups/{slug}/advertisers/{membershipID}", s.adminOnly(s.handleWithdraw))
	mux.Handle("PUT /api/v1/networks/{networkID}/route-groups/{slug}/failover", s.adminOnly(s.handleSetRouteGroupFailover))
}

// rateLimited wraps an unauthenticated handler.
func (s *Server) rateLimited(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limit.allow(clientKey(r)) {
			w.Header().Set("Retry-After", "1")
			httpx.Error(w, s.log, http.StatusTooManyRequests,
				"rate_limited", "too many enrolment attempts; slow down")
			return
		}
		next(w, r)
	})
}

// adminOnly gates a handler behind the bootstrap secret, or a signed-in person.
//
// A signed-in person passes, and that is the whole permission model for now: ADR-0024 §4
// puts roles in a later slice, so **every user account is an administrator account**. It
// cannot be otherwise — there are no limits to apply — and it is written here rather than
// left to be discovered, because an endpoint that creates users looks like one that could
// create a limited one.
func (s *Server) adminOnly(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.sessionUser(r) != nil {
			next(w, r)
			return
		}
		if s.cfg.AdminToken == "" {
			httpx.Error(w, s.log, http.StatusServiceUnavailable, "admin_disabled",
				"sign in, or set MESHP_ADMIN_TOKEN to bootstrap the first account")
			return
		}

		presented := bearer(r)
		// Constant time, so a caller cannot learn the secret one byte at a time from
		// how long the comparison takes.
		if subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.AdminToken)) != 1 {
			s.log.Warn("administrative request rejected",
				"path", logx.Safe(r.URL.Path), "remote", logx.Safe(clientKey(r)))
			httpx.Error(w, s.log, http.StatusUnauthorized, "unauthorized",
				"a valid administrative token is required")
			return
		}
		next(w, r)
	})
}

func bearer(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

// decode reads a JSON body with a size cap and rejects unknown fields.
//
// Rejecting unknown fields turns a typo into an error instead of a silently ignored
// setting — an enrolment that quietly dropped a misspelled field would look like it
// worked and behave like it did not.
func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("request body: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body: expected exactly one JSON object")
	}
	return nil
}

// failure describes how a known error is reported.
type failure struct {
	status  int
	code    string
	message string
}

// knownFailures maps the sentinels callers are allowed to know about.
//
// Being specific about token state — unknown, expired, revoked, already used — does
// make these endpoints an oracle for whether a token exists. That is a deliberate
// trade: guessing a 160-bit token is hopeless, so the oracle is worth nothing, while
// "that token expired an hour ago" is worth a great deal to whoever is trying to get
// a laptop onto a network.
//
// Anything absent from this map becomes a bare 500 with the detail in the log only.
// An unrecognised error is one whose text nobody has reviewed for what it discloses.
var knownFailures = []struct {
	err error
	failure
}{
	{enroll.ErrTokenMalformed, failure{http.StatusBadRequest, "token_malformed", "that does not look like an enrolment token"}},
	{enroll.ErrTokenUnknown, failure{http.StatusUnauthorized, "token_unknown", "that enrolment token is not recognised"}},
	{enroll.ErrTokenExpired, failure{http.StatusUnauthorized, "token_expired", "that enrolment token has expired; ask for a new one"}},
	{enroll.ErrTokenRevoked, failure{http.StatusUnauthorized, "token_revoked", "that enrolment token has been revoked"}},
	{enroll.ErrTokenExhausted, failure{http.StatusConflict, "token_exhausted", "that enrolment token has already been used"}},
	{enroll.ErrChallengeInvalid, failure{http.StatusBadRequest, "challenge_invalid", "the challenge is not valid for this token and key"}},
	{store.ErrRecordExists, failure{http.StatusConflict, "record_exists", "that record already exists"}},
	{store.ErrOrganizationExists, failure{http.StatusConflict, "organization_exists", "an organisation with that name already exists"}},
	{store.ErrUserExists, failure{http.StatusConflict, "user_exists", "a user with that address already exists in this organisation"}},
	{store.ErrNoSuchUser, failure{http.StatusNotFound, "no_such_user", "no such user in this organisation"}},
	{store.ErrNoSuchRecord, failure{http.StatusNotFound, "no_such_record", "no such record in this network"}},
	{enroll.ErrChallengeExpired, failure{http.StatusBadRequest, "challenge_expired", "the challenge has expired; request another"}},
	{enroll.ErrProofFailed, failure{http.StatusUnauthorized, "proof_failed", "the signature over the challenge did not verify"}},
	{enroll.ErrAlreadyInNetwork, failure{http.StatusConflict, "already_enrolled", "this device is already enrolled in that network"}},
	{enroll.ErrDeviceRevoked, failure{http.StatusForbidden, "device_revoked", "this device has been revoked"}},
	{enroll.ErrWireGuardKeyInUse, failure{http.StatusConflict, "key_in_use", "that WireGuard key is already in use; generate a fresh one for each network"}},
	{enroll.ErrNoAddressPool, failure{http.StatusConflict, "no_address_pool", "that network has no address pool to allocate from"}},
	{ipam.ErrExhausted, failure{http.StatusConflict, "pool_exhausted", "that network's address pool is full"}},
	{ipam.ErrAllQuarantined, failure{http.StatusConflict, "pool_cooling_down", "every free address in that network is in its reuse cooldown"}},
}

// respondError maps an error to a response, logging what it does not recognise.
func (s *Server) respondError(w http.ResponseWriter, r *http.Request, err error) {
	// A refusal caused by what the caller sent, whose text was written to be shown to them.
	// Checked before the table because there is no sentinel to match: the review that lets
	// this text out travels on the error itself. Without this branch an administrator who
	// creates an egress group with prefixes, or a failover policy that would oscillate, gets
	// "the request could not be completed" and has to go and read the server's log to find
	// the explanation that was already written for them.
	var invalid *store.InvalidError
	if errors.As(err, &invalid) {
		// Through logx.SafeError, unlike the table below. Those errors are sentinels whose
		// text is fixed and written here; this one is built from what the caller sent — a
		// slug, a kind, a probe target.
		//
		// Length is the part that bites today: slog does not bound a value, so without this
		// a caller can put as much as they like into the log on every failed request, which
		// is a cheap way to fill a disk or a log bill. Control characters are belt and
		// braces — every construction site uses %q and slog's own handler quotes them
		// again — and they are here so this stays true if either of those changes.
		s.log.Info("request refused",
			"path", logx.Safe(r.URL.Path), "code", "invalid", "error", logx.SafeError(err))
		httpx.Error(w, s.log, http.StatusBadRequest, "invalid", invalid.Message)
		return
	}

	for _, known := range knownFailures {
		if errors.Is(err, known.err) {
			s.log.Info("request refused",
				"path", logx.Safe(r.URL.Path), "code", known.code, "error", err)
			httpx.Error(w, s.log, known.status, known.code, known.message)
			return
		}
	}

	// Unrecognised: the client learns nothing, the operator learns everything.
	s.log.Error("request failed", "path", logx.Safe(r.URL.Path), "error", err)
	httpx.Error(w, s.log, http.StatusInternalServerError, "internal",
		"the request could not be completed")
}

// isNotFound is a thin alias so handlers do not each import the store package for
// one predicate.
func isNotFound(err error) bool { return store.IsNotFound(err) }
