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
	return &Server{
		store:   st,
		enroll:  svc,
		session: sess,
		cfg:     cfg,
		log:     cfg.Log,
		limit:   newLimiter(cfg.EnrolRatePerSecond, cfg.EnrolBurst, 10_000, cfg.Clock),
	}
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

// adminOnly gates a handler behind the bootstrap secret.
func (s *Server) adminOnly(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			httpx.Error(w, s.log, http.StatusServiceUnavailable, "admin_disabled",
				"the administrative API is not configured; set MESHP_ADMIN_TOKEN")
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
