// Package api serves meshp-control's HTTP interface.
//
// Two audiences, deliberately separated:
//
//   - Device endpoints under /api/v1/enroll are reachable without a credential,
//     because a device that has nothing yet cannot authenticate. The enrolment
//     token in the body is the credential.
//   - Everything else requires a permission, held either in one network or across
//     one organisation (ADR-0024 §4). The route table in Routes is where each
//     endpoint says which, and a route that says nothing does not start.
//
// The bootstrap secret still works and holds everything, including permissions that
// do not exist yet. It is how a fresh deployment creates its first account and how a
// locked-out one gets back in, and every use of it is recorded as what it is: the
// shared credential, rather than a person (ADR-0024 §5).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/meshpnet/meshp/internal/authz"
	"github.com/meshpnet/meshp/internal/bus"
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

	// Bus tells other control-plane replicas that a network changed (ADR-0025). Nil is a
	// single-replica deployment, where the local hub is the only thing to nudge.
	Bus bus.Bus

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

	// bus tells the other replicas that a network changed (ADR-0025). Nil in a test that
	// stands no bus up, which reads as a single-replica deployment — the local hub is
	// still nudged, so nothing a test asserts about one process changes.
	bus bus.Bus

	// bootstrapWarnedAt is when the administrative token was last complained about, so the
	// complaint is occasional rather than per request. See warnBootstrapTokenUsed.
	bootstrapWarnedAt atomic.Pointer[time.Time]
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
		bus:     cfg.Bus,
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
//
// Every route is a row in the table below, and every row says how it is gated. That is not
// tidiness: a route registered with no guard is the failure this shape exists to make
// impossible, and the zero value of guardKind is `guardUnset`, which panics here rather than
// serving. A permission that is not in the catalogue panics too — a typo would otherwise
// produce a route nobody can reach and nothing would say so.
func (s *Server) Routes(mux *http.ServeMux) {
	for _, rt := range s.routes() {
		switch rt.kind {
		case guardUnset:
			panic("api: " + rt.pattern + " was registered without saying how it is gated")
		case guardNetwork, guardOrganization, guardCallerOrganization:
			if !authz.Known(string(rt.perm)) {
				panic("api: " + rt.pattern + " needs " + string(rt.perm) +
					", which is not in the permission catalogue")
			}
		default:
			if rt.perm != "" {
				panic("api: " + rt.pattern + " names a permission that its guard never checks")
			}
		}
		mux.Handle(rt.pattern, s.gate(rt))
	}

	// The page itself (ADR-0022 §2), registered as one route per embedded file rather
	// than as a catch-all — see routePage for why that distinction is load-bearing.
	s.routePage(mux)
}

// guardKind is how a route decides whether a request may proceed.
type guardKind int

const (
	// guardUnset is the zero value and is not a guard. Registering a route with it panics,
	// which is the point: adding an endpoint should not be possible without deciding who
	// may reach it, and the decision should not be able to default to the permissive one.
	guardUnset guardKind = iota

	// guardThrottled is unauthenticated and rate limited. A device with nothing yet cannot
	// authenticate, so the token in the body is the credential (ADR-0006).
	guardThrottled

	// guardOpen is unauthenticated and not rate limited. Two routes: the session upgrade,
	// which authenticates in its own first frame and must not be throttled because
	// throttling reconnects turns a brief outage into a long one, and signing out, which
	// has to work for a browser holding a session this process has already forgotten.
	guardOpen

	// guardSignedIn is any caller this control plane can identify, with no permission
	// required. For routes about the caller rather than about the deployment: who am I,
	// which organisation am I in, what permissions exist.
	guardSignedIn

	// guardBootstrap is the administrative token itself, and not a person however powerful.
	//
	// One thing needs it: creating an organisation. A user belongs to exactly one
	// organisation, so there is no organisation a person could hold a permission over that
	// would authorise creating another — making a tenant is deployment administration, and
	// the deployment's credential is the honest gate for it.
	guardBootstrap

	// guardNetwork requires a permission held in the network named by {networkID}. An
	// organisation-wide grant satisfies it, and so does one narrowed to that network.
	guardNetwork

	// guardOrganization requires a permission held across the organisation named by
	// {organizationID}. A grant narrowed to a single network never satisfies one.
	guardOrganization

	// guardCallerOrganization requires a permission held across the caller's own
	// organisation, for the two routes that name no scope in their path. A person belongs
	// to exactly one organisation, so there is no ambiguity for them; the administrative
	// token belongs to none, and holds everything.
	guardCallerOrganization
)

// route is one endpoint and what it takes to reach it.
type route struct {
	pattern string
	handler http.HandlerFunc
	kind    guardKind

	// perm is required by the three guards that check one, and must be empty otherwise.
	// A permission written next to a guard that ignores it reads like a control and is not
	// one, which is worse than no permission at all.
	perm authz.Permission
}

// routes is every endpoint this control plane serves, and the permission each needs.
//
// The mapping from route to permission is the public surface of ADR-0024 §4: ADR-0009 makes
// the commercial layer a consumer of it, and ADR-0023 records that such surface cannot be
// reshaped freely afterwards. A permission is chosen here once.
func (s *Server) routes() []route {
	return []route{
		// Enrolment. A device that has nothing yet cannot authenticate, so the token in
		// the body is the credential.
		{pattern: "POST /api/v1/enroll/challenge", handler: s.handleChallenge, kind: guardThrottled},
		{pattern: "POST /api/v1/enroll", handler: s.handleRedeem, kind: guardThrottled},

		// Sessions. The challenge endpoint is unauthenticated for the same reason
		// enrolment's is — a device proves itself by signing what it gets back — so it is
		// rate limited alongside them. The upgrade itself is not: it authenticates in its
		// first frame, and throttling reconnects is how a brief control-plane outage turns
		// into a long one when every agent comes back at once.
		{pattern: "POST /api/v1/session/challenge", handler: s.handleSessionChallenge, kind: guardThrottled},
		{pattern: "GET /api/v1/session", handler: s.handleSession, kind: guardOpen},

		// Enrolment tokens. Minting one is how a device gets onto a network, which is why
		// an operator holds it and a reader does not.
		{pattern: "POST /api/v1/networks/{networkID}/enrollment-tokens",
			handler: s.handleCreateToken, kind: guardNetwork, perm: authz.NetworkEnrollmentTokensWrite},
		{pattern: "GET /api/v1/networks/{networkID}/enrollment-tokens",
			handler: s.handleListTokens, kind: guardNetwork, perm: authz.NetworkEnrollmentTokensRead},
		{pattern: "DELETE /api/v1/networks/{networkID}/enrollment-tokens/{tokenID}",
			handler: s.handleRevokeToken, kind: guardNetwork, perm: authz.NetworkEnrollmentTokensWrite},

		{pattern: "GET /api/v1/networks/{networkID}/devices",
			handler: s.handleListMemberships, kind: guardNetwork, perm: authz.NetworkDevicesRead},
		{pattern: "DELETE /api/v1/networks/{networkID}/devices/{membershipID}",
			handler: s.handleRevokeMembership, kind: guardNetwork, perm: authz.NetworkDevicesRevoke},

		// The names an administrator writes down, which nothing can derive from the peer
		// list (ADR-0021 §2).
		{pattern: "GET /api/v1/networks/{networkID}/dns-records",
			handler: s.handleListDNSRecords, kind: guardNetwork, perm: authz.NetworkDNSRead},
		{pattern: "POST /api/v1/networks/{networkID}/dns-records",
			handler: s.handleCreateDNSRecord, kind: guardNetwork, perm: authz.NetworkDNSWrite},
		{pattern: "DELETE /api/v1/networks/{networkID}/dns-records/{recordID}",
			handler: s.handleDeleteDNSRecord, kind: guardNetwork, perm: authz.NetworkDNSWrite},

		{pattern: "GET /api/v1/networks/{networkID}/acl",
			handler: s.handleGetPolicy, kind: guardNetwork, perm: authz.NetworkACLRead},
		{pattern: "PUT /api/v1/networks/{networkID}/acl",
			handler: s.handlePublishPolicy, kind: guardNetwork, perm: authz.NetworkACLWrite},
		{pattern: "GET /api/v1/networks/{networkID}/acl/versions",
			handler: s.handleListPolicyVersions, kind: guardNetwork, perm: authz.NetworkACLRead},

		// The tenant networks belong to. Creating one is deployment administration rather
		// than something a person can hold a permission over — see guardBootstrap — while
		// which organisation you are in is not a privilege: /api/v1/me already answers it.
		{pattern: "POST /api/v1/organizations", handler: s.handleCreateOrganization, kind: guardBootstrap},

		// Relays, which belong to the deployment rather than to a tenant (#128). Behind the
		// administrative token for the same reason creating an organisation is: the
		// permission families are `network.` and `organization.`, and a relay is neither —
		// inventing a third family for two routes would be surface nobody asked for.
		//
		// Worth revisiting if an MSP operator ever needs to drain a relay without holding
		// the deployment's root credential. That is a real scenario and it is not this one:
		// today the person who runs the relays is the person who runs the control plane.
		{pattern: "GET /api/v1/relays", handler: s.handleListRelays, kind: guardBootstrap},
		{pattern: "PUT /api/v1/relays/{relay}/state", handler: s.handleSetRelayState, kind: guardBootstrap},
		{pattern: "GET /api/v1/organizations", handler: s.handleListOrganizations, kind: guardSignedIn},

		// People (ADR-0024). Creating an account and suspending one are the same
		// permission: both decide who can sign in.
		{pattern: "POST /api/v1/organizations/{organizationID}/users",
			handler: s.handleCreateUser, kind: guardOrganization, perm: authz.OrganizationUsersWrite},
		{pattern: "GET /api/v1/organizations/{organizationID}/users",
			handler: s.handleListUsers, kind: guardOrganization, perm: authz.OrganizationUsersRead},
		{pattern: "PUT /api/v1/organizations/{organizationID}/users/{userID}/suspended",
			handler: s.handleSetUserSuspended, kind: guardOrganization, perm: authz.OrganizationUsersWrite},
		{pattern: "PUT /api/v1/organizations/{organizationID}/users/{userID}/password",
			handler: s.handleSetUserPassword, kind: guardOrganization, perm: authz.OrganizationUsersWrite},
		{pattern: "DELETE /api/v1/organizations/{organizationID}/users/{userID}",
			handler: s.handleDeleteUser, kind: guardOrganization, perm: authz.OrganizationUsersWrite},

		// Who may act, kept apart from every other permission so that "can change the
		// network" and "can change who may change the network" are different answers.
		{pattern: "GET /api/v1/organizations/{organizationID}/roles",
			handler: s.handleListRoles, kind: guardOrganization, perm: authz.OrganizationRolesRead},
		{pattern: "GET /api/v1/organizations/{organizationID}/users/{userID}/roles",
			handler: s.handleListUserRoles, kind: guardOrganization, perm: authz.OrganizationRolesRead},
		{pattern: "POST /api/v1/organizations/{organizationID}/users/{userID}/roles",
			handler: s.handleGrantRole, kind: guardOrganization, perm: authz.OrganizationRolesBind},
		{pattern: "DELETE /api/v1/organizations/{organizationID}/users/{userID}/roles/{bindingID}",
			handler: s.handleRevokeRole, kind: guardOrganization, perm: authz.OrganizationRolesBind},

		// Who this request is, the one password a session may change without help, and
		// what permissions exist at all. None is behind a permission: they are about the
		// caller rather than about the deployment, and gating "who am I" would make the
		// sign-in page unable to ask.
		{pattern: "GET /api/v1/me", handler: s.handleWhoAmI, kind: guardSignedIn},
		{pattern: "POST /api/v1/me/password", handler: s.handleChangeOwnPassword, kind: guardSignedIn},
		{pattern: "GET /api/v1/permissions", handler: s.handleListPermissions, kind: guardSignedIn},

		// What this caller may do, here — which is what the page loads before deciding
		// which controls exist. Behind no permission of its own: it answers a question
		// about the caller, and refusing to tell somebody what they may do would leave a
		// page guessing.
		{pattern: "GET /api/v1/me/permissions", handler: s.handleListOwnPermissions, kind: guardSignedIn},

		// Credentials for machines (ADR-0024 §2). Your own, which is why they hang off /me
		// and are behind no permission: minting and pruning your own credentials is like
		// changing your own password, and needing to be granted the right to do it would
		// leave somebody unable to clean up after themselves.
		//
		// The handlers refuse a machine holding somebody's token, which guardSignedIn
		// cannot express: a token that could mint a token would survive its own revocation.
		{pattern: "POST /api/v1/me/tokens", handler: s.handleMintToken, kind: guardSignedIn},
		{pattern: "GET /api/v1/me/tokens", handler: s.handleListOwnTokens, kind: guardSignedIn},
		{pattern: "DELETE /api/v1/me/tokens/{tokenID}", handler: s.handleRevokeOwnToken, kind: guardSignedIn},

		// Everybody else's, which is an administrative act and is what somebody needs when
		// a person leaves.
		{pattern: "GET /api/v1/organizations/{organizationID}/tokens",
			handler: s.handleListOrganizationTokens, kind: guardOrganization, perm: authz.OrganizationTokensRead},
		{pattern: "DELETE /api/v1/organizations/{organizationID}/tokens/{tokenID}",
			handler: s.handleRevokeOrganizationToken, kind: guardOrganization, perm: authz.OrganizationTokensWrite},

		// Networks, which name no scope in their path: the caller's own organisation is
		// the scope.
		{pattern: "POST /api/v1/networks",
			handler: s.handleCreateNetwork, kind: guardCallerOrganization, perm: authz.OrganizationNetworksCreate},
		{pattern: "GET /api/v1/networks",
			handler: s.handleListNetworks, kind: guardCallerOrganization, perm: authz.OrganizationNetworksRead},

		// The one read endpoint (ADR-0022). Everything else under /api/v1 creates or
		// changes something; this answers a question about a network, and the commercial
		// layer builds its cross-tenant roll-up on it, so its shape is not this page's to
		// choose.
		{pattern: "GET /api/v1/networks/{networkID}/overview",
			handler: s.handleNetworkOverview, kind: guardNetwork, perm: authz.NetworkRead},

		// The audit trail, which is its own permission rather than travelling with
		// network.read: a trail says who did what, and somebody who may watch a dashboard
		// is not automatically somebody who may see the names of everyone who touched it.
		{pattern: "GET /api/v1/networks/{networkID}/audit",
			handler: s.handleListAuditEvents, kind: guardNetwork, perm: authz.NetworkAuditRead},

		// Signing in. Rate limited with the enrolment endpoints: it is where a wrong
		// password can be guessed at, and an endpoint that hashes on every attempt should
		// not be free to hammer. Signing out is not — it has to work for a browser holding
		// a session this process has already forgotten.
		{pattern: "POST /api/v1/ui/session", handler: s.handleUILogin, kind: guardThrottled},
		{pattern: "DELETE /api/v1/ui/session", handler: s.handleUILogout, kind: guardOpen},

		// Its own sub-resource rather than a field on a general network update, because
		// this is the one setting here that can decide whether a laptop leaks. A PUT that
		// names it in the path cannot be made by accident, reads unambiguously in an access
		// log, and leaves no room for a partial update that silently carries it along.
		{pattern: "GET /api/v1/networks/{networkID}/egress-fail-closed",
			handler: s.handleGetEgressFailClosed, kind: guardNetwork, perm: authz.NetworkEgressRead},
		{pattern: "PUT /api/v1/networks/{networkID}/egress-fail-closed",
			handler: s.handleSetEgressFailClosed, kind: guardNetwork, perm: authz.NetworkEgressWrite},

		// Route groups. Changing which advertiser carries a prefix is what somebody does at
		// two in the morning when a link is down; changing which prefixes exist is not. The
		// two are different permissions for that reason.
		{pattern: "GET /api/v1/networks/{networkID}/route-groups",
			handler: s.handleListRouteGroups, kind: guardNetwork, perm: authz.NetworkRoutesRead},
		{pattern: "POST /api/v1/networks/{networkID}/route-groups",
			handler: s.handleCreateRouteGroup, kind: guardNetwork, perm: authz.NetworkRoutesWrite},
		{pattern: "DELETE /api/v1/networks/{networkID}/route-groups/{slug}",
			handler: s.handleDeleteRouteGroup, kind: guardNetwork, perm: authz.NetworkRoutesWrite},
		{pattern: "POST /api/v1/networks/{networkID}/route-groups/{slug}/advertisers",
			handler: s.handleAdvertise, kind: guardNetwork, perm: authz.NetworkRoutesWrite},
		{pattern: "DELETE /api/v1/networks/{networkID}/route-groups/{slug}/advertisers/{membershipID}",
			handler: s.handleWithdraw, kind: guardNetwork, perm: authz.NetworkRoutesWrite},
		{pattern: "PUT /api/v1/networks/{networkID}/route-groups/{slug}/failover",
			handler: s.handleSetRouteGroupFailover, kind: guardNetwork, perm: authz.NetworkRoutesFailover},
	}
}

// gate turns a route into a handler that decides whether the request may proceed.
//
// Two lookups for a signed-in person: the session, and the permissions. The second is per
// request rather than resolved at sign-in, so revoking a role takes effect on the next
// request rather than whenever somebody happens to close their browser.
func (s *Server) gate(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch rt.kind {
		case guardOpen:
			rt.handler(w, r)
			return
		case guardThrottled:
			if !s.limit.allow(clientKey(r)) {
				w.Header().Set("Retry-After", "1")
				httpx.Error(w, s.log, http.StatusTooManyRequests,
					"rate_limited", "too many attempts; slow down")
				return
			}
			rt.handler(w, r)
			return
		}

		c, ok := s.identify(r)
		if !ok {
			s.unauthenticated(w, r)
			return
		}
		r = r.WithContext(withCaller(r.Context(), c))

		// A browser session that is about to change something must have been sent by this
		// site. See sameOrigin: the page can now revoke a device, so the defence is an
		// argument rather than an inherited assumption.
		if c.user != nil && !safeMethod(r.Method) && !sameOrigin(r) {
			s.log.Warn("a cross-origin write was refused",
				"path", logx.Safe(r.URL.Path), "origin", logx.Safe(r.Header.Get("Origin")))
			httpx.Error(w, s.log, http.StatusForbidden, "cross_origin",
				"this request did not come from this site")
			return
		}

		switch rt.kind {
		case guardSignedIn:
			rt.handler(w, r)

		case guardBootstrap:
			if !c.bootstrap {
				// Not a permission failure, so it does not go through refuse: no
				// permission would help, and saying which one was missing would be
				// pointing at something that does not exist.
				httpx.Error(w, s.log, http.StatusForbidden, "forbidden",
					"this needs the administrative token; it is deployment administration "+
						"rather than something a role can grant")
				return
			}
			rt.handler(w, r)

		case guardNetwork:
			networkID, ok := s.pathUUID(w, r, "networkID")
			if !ok {
				return
			}
			held, err := s.permissionsInNetwork(r, c, networkID)
			if err != nil {
				s.respondError(w, r, err)
				return
			}
			if !held.Allows(rt.perm) {
				s.refuse(w, r, c, held, rt.perm)
				return
			}
			rt.handler(w, r)

		case guardOrganization:
			orgID, ok := s.pathUUID(w, r, "organizationID")
			if !ok {
				return
			}
			held, err := s.permissionsInOrganization(r, c, orgID)
			if err != nil {
				s.respondError(w, r, err)
				return
			}
			if !held.Allows(rt.perm) {
				s.refuse(w, r, c, held, rt.perm)
				return
			}
			rt.handler(w, r)

		case guardCallerOrganization:
			// The administrative token belongs to no organisation and holds everything, so
			// there is nothing to resolve for it. A token belongs to its owner's, which is
			// the one permissionsInOrganization asks about below.
			if c.bootstrap {
				rt.handler(w, r)
				return
			}
			org := callerOrganization(c)
			if org == nil {
				// Unreachable: identify returns bootstrap, a person or a token, and the
				// first is handled above. Answered rather than dereferenced, because the
				// alternative is a panic that only shows up when it is wrong.
				httpx.Error(w, s.log, http.StatusForbidden, "forbidden",
					"this caller belongs to no organisation")
				return
			}
			held, err := s.permissionsInOrganization(r, c, *org)
			if err != nil {
				s.respondError(w, r, err)
				return
			}
			if !held.Allows(rt.perm) {
				s.refuse(w, r, c, held, rt.perm)
				return
			}
			rt.handler(w, r)

		default:
			// Unreachable: Routes panics on guardUnset before anything is registered.
			httpx.Error(w, s.log, http.StatusInternalServerError, "internal",
				"the request could not be completed")
		}
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
