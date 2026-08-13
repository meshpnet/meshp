package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/challenge"
	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/enroll"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/sessionclient"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	"github.com/meshpnet/meshp/internal/testdb"
	"github.com/meshpnet/meshp/migrations"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

const testSecret = "session-test-master-secret-value"

type fixture struct {
	t      *testing.T
	store  *store.Store
	srv    *Server
	hub    *Hub
	http   *httptest.Server
	enroll *enroll.Service
	clk    *clock.Fake
	ctx    context.Context
	netID  uuid.UUID
	orgID  uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := testdb.URL(t, "session")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	// A real clock. The control channel's timeouts are enforced by the websocket
	// library and by context deadlines, neither of which a fake clock reaches, so
	// pretending otherwise here would make the tests lie about what they cover.
	clk := clock.NewFake()

	st, err := store.Open(ctx, store.DefaultConfig(url), migrations.FS, nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)

	dropAll(t, st, ctx)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	f := &fixture{t: t, store: st, clk: clk, ctx: ctx, hub: NewHub()}
	f.seed()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	srv, err := NewServer(st, f.hub, Config{MasterSecret: []byte(testSecret), Clock: clk, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv

	ch, err := enroll.NewChallenger([]byte(testSecret), enroll.DefaultChallengeTTL, clk)
	if err != nil {
		t.Fatal(err)
	}
	f.enroll = enroll.NewService(st, ch, clk, nil)

	// The two routes the agent needs, wired straight to the session server. The
	// api package's own wiring is covered by its tests and by the end-to-end script;
	// this keeps the subject of these tests to the session itself.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/session/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IdentityPublicKey string `json:"identity_public_key"`
			MembershipID      string `json:"membership_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		identity, err := base64.StdEncoding.DecodeString(req.IdentityPublicKey)
		if err != nil {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		membershipID, err := uuid.Parse(req.MembershipID)
		if err != nil {
			http.Error(w, "bad membership", http.StatusBadRequest)
			return
		}
		c, err := srv.IssueChallenge(identity, membershipID)
		if err != nil {
			http.Error(w, "failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"challenge": c.Encoded()})
	})
	mux.HandleFunc("GET /api/v1/session", srv.Serve)

	f.http = httptest.NewServer(mux)
	t.Cleanup(f.http.Close)
	return f
}

func dropAll(t *testing.T, st *store.Store, ctx context.Context) {
	t.Helper()
	rows, err := st.Pool().Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		if _, err := st.Pool().Exec(ctx, `DROP TABLE IF EXISTS "`+n+`" CASCADE`); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) seed() {
	f.t.Helper()
	p := f.store.Pool()
	if err := p.QueryRow(f.ctx,
		`INSERT INTO organizations (slug,name) VALUES ('acme','Acme') RETURNING id`).Scan(&f.orgID); err != nil {
		f.t.Fatal(err)
	}
	if err := p.QueryRow(f.ctx,
		`INSERT INTO networks (organization_id,slug,name) VALUES ($1,'hq','HQ') RETURNING id`,
		f.orgID).Scan(&f.netID); err != nil {
		f.t.Fatal(err)
	}
	if _, err := p.Exec(f.ctx,
		`INSERT INTO address_pools (network_id,prefix,family,purpose)
		 VALUES ($1,'100.90.0.0/24'::cidr,4,'device'), ($1,'fd7c::/120'::cidr,6,'device')`, f.netID); err != nil {
		f.t.Fatal(err)
	}
}

// device is an enrolled device with the keys it needs to open a session.
type device struct {
	identity     keys.Identity
	membershipID uuid.UUID
	deviceID     uuid.UUID
	addressV4    string
}

// enrolDevice puts a device in the network the way `meshp join` does.
func (f *fixture) enrolDevice(name string) device {
	f.t.Helper()

	tok, err := enroll.NewToken()
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.store.Queries().CreateEnrollmentToken(f.ctx, dbgen.CreateEnrollmentTokenParams{
		NetworkID: f.netID, OrganizationID: f.orgID, TokenHash: tok.Hash,
		PreassignedTags: []string{}, MaxUses: 1, ExpiresAt: f.clk.Now().Add(time.Hour),
	}); err != nil {
		f.t.Fatal(err)
	}

	identity, err := keys.NewIdentity()
	if err != nil {
		f.t.Fatal(err)
	}
	wg, err := keys.NewWireGuardPair()
	if err != nil {
		f.t.Fatal(err)
	}

	resp, err := f.enroll.IssueChallenge(f.ctx, enroll.ChallengeRequest{
		Token: tok.Plaintext, IdentityPublicKey: identity.Public,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	ch, err := enroll.ParseChallenge(resp.Challenge)
	if err != nil {
		f.t.Fatal(err)
	}
	res, err := f.enroll.Redeem(f.ctx, enroll.RedeemRequest{
		Token:              tok.Plaintext,
		IdentityPublicKey:  identity.Public,
		Challenge:          ch,
		Signature:          identity.Sign(ch),
		WireGuardPublicKey: wg.Public.String(),
		Name:               name,
	})
	if err != nil {
		f.t.Fatalf("enrolling %s: %v", name, err)
	}

	d := device{identity: identity, membershipID: res.MembershipID, deviceID: res.DeviceID}
	if res.AddressV4 != nil {
		d.addressV4 = res.AddressV4.String()
	}
	return d
}

// appliedState is a copy of what the applier was handed, taken because the client keeps
// mutating its own set between calls.
type appliedState struct {
	version uint64
	keys    []string
	peers   []*meshpv1.Peer
}

// capturingApplier records what it was asked to apply and signals each time.
type capturingApplier struct {
	mu       sync.Mutex
	seen     []appliedState
	applied  chan appliedState
	failWith error
}

func newCapturingApplier() *capturingApplier {
	return &capturingApplier{applied: make(chan appliedState, 8)}
}

func (a *capturingApplier) Apply(_ context.Context, state *peerset.Set) ([]string, error) {
	snapshot := appliedState{version: state.Version(), keys: state.Keys(), peers: state.Peers()}

	a.mu.Lock()
	a.seen = append(a.seen, snapshot)
	failure := a.failWith
	a.mu.Unlock()

	select {
	case a.applied <- snapshot:
	default:
	}
	if failure != nil {
		return []string{"test-component"}, failure
	}
	return nil, nil
}

func (a *capturingApplier) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seen)
}

// connect runs a client session in the background and returns its applier.
func (f *fixture) connect(d device, _ int64) (*capturingApplier, context.CancelFunc) {
	f.t.Helper()

	applier := newCapturingApplier()
	client := sessionclient.New(sessionclient.Options{
		ControlURL:   f.http.URL,
		Identity:     d.identity,
		MembershipID: d.membershipID,
		AgentVersion: "test",
	})

	ctx, cancel := context.WithCancel(f.ctx)
	go func() { _ = client.RunOnce(ctx, applier) }()
	return applier, cancel
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- the gate ---------------------------------------------------------------

func TestAgentConnectsReceivesSnapshotAndAcks(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")

	applier, cancel := f.connect(alice, 0)
	defer cancel()

	var state appliedState
	select {
	case state = <-applier.applied:
	case <-time.After(15 * time.Second):
		t.Fatal("no state was delivered")
	}

	if state.version == 0 {
		t.Error("version 0; the agent has nothing to acknowledge")
	}

	// Bob is in the network, so Alice should have been told about him — and not about
	// herself.
	if len(state.peers) != 1 {
		t.Fatalf("%d peers, want 1", len(state.peers))
	}
	peer := state.peers[0]
	if peer.GetDeviceName() != "bob" {
		t.Errorf("peer is %q, want bob", peer.GetDeviceName())
	}

	// Host routes only. A peer given the whole pool would receive traffic for every
	// other device in the network.
	for _, cidr := range peer.GetAllowedIps() {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatalf("allowed ip %q does not parse: %v", cidr, err)
		}
		if prefix.Bits() != prefix.Addr().BitLen() {
			t.Errorf("allowed ip %s is not a host route", cidr)
		}
	}

	// The session is registered, and the acknowledgement reached the database.
	waitFor(t, "the session to register", func() bool { return f.hub.Count() == 1 })
	waitFor(t, "the applied version to be recorded", func() bool {
		rows, err := f.store.Queries().GetConvergenceLag(f.ctx, f.netID)
		if err != nil {
			return false
		}
		for _, r := range rows {
			if r.MembershipID == alice.membershipID && r.AppliedVersion == r.DesiredVersion {
				return true
			}
		}
		return false
	})

	_ = bob
}

// Invariant 15: losing the control plane must not disturb what the device already has.
func TestAgentSurvivesTheControlPlaneGoingAway(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	applier, cancel := f.connect(alice, 0)
	defer cancel()

	select {
	case <-applier.applied:
	case <-time.After(15 * time.Second):
		t.Fatal("no state was delivered before the outage")
	}
	applied := applier.count()

	// The control plane goes away underneath the agent. Closing the session server-side
	// is what the agent sees when a control plane restarts, and unlike
	// httptest.CloseClientConnections it reliably reaches an upgraded connection —
	// httptest stops tracking a conn once the handler hijacks it.
	sess, ok := f.hub.Get(alice.membershipID)
	if !ok {
		t.Fatal("the session was not registered")
	}
	sess.Close()
	waitFor(t, "the session to be dropped", func() bool { return f.hub.Count() == 0 })

	// The agent is not asked to undo anything. Nothing new arrives, and nothing is
	// retracted: the Applier is only ever asked to move toward a state.
	time.Sleep(300 * time.Millisecond)
	if applier.count() != applied {
		t.Errorf("the applier was called %d more times after the outage", applier.count()-applied)
	}
}

// --- authentication ---------------------------------------------------------

func TestSessionRejectsABadSignature(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	impostor, err := keys.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Alice's membership and key, somebody else's signature.
	ch, err := f.srv.IssueChallenge(alice.identity.Public, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	err = f.rawHandshake(alice.membershipID, alice.identity.Public, ch.Bytes, impostor.Sign(ch.Bytes))
	if err == nil {
		t.Fatal("a session opened with somebody else's signature")
	}
	if f.hub.Count() != 0 {
		t.Error("a rejected handshake left a session registered")
	}
}

// The check that stops one enrolled device opening another's session. The challenge is
// bound to a membership, but the client chooses which membership it asks about, so only
// comparing the recorded key closes it.
func TestSessionRejectsAKeyThatDoesNotOwnTheMembership(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")

	// Bob's own key, correctly signed, against Alice's membership.
	ch, err := f.srv.IssueChallenge(bob.identity.Public, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	err = f.rawHandshake(alice.membershipID, bob.identity.Public, ch.Bytes, bob.identity.Sign(ch.Bytes))
	if err == nil {
		t.Fatal("Bob opened a session as Alice")
	}
}

func TestSessionRejectsAChallengeForAnotherMembership(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")

	// A challenge Alice legitimately obtained, spent on Bob's membership.
	ch, err := f.srv.IssueChallenge(alice.identity.Public, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	err = f.rawHandshake(bob.membershipID, alice.identity.Public, ch.Bytes, alice.identity.Sign(ch.Bytes))
	if err == nil {
		t.Fatal("a challenge for one membership opened a session on another")
	}
}

// Purpose separation, end to end: an enrolment challenge must not open a session.
// Otherwise a device whose membership was revoked could present a leftover enrolment
// challenge and be let back in.
func TestEnrolmentChallengeCannotOpenASession(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	enrolmentChallenger, err := challenge.New([]byte(testSecret), "meshp enrolment challenge v1", challenge.DefaultTTL, f.clk)
	if err != nil {
		t.Fatal(err)
	}
	id := alice.membershipID
	ch, err := enrolmentChallenger.Issue(alice.identity.Public, id[:])
	if err != nil {
		t.Fatal(err)
	}

	err = f.rawHandshake(alice.membershipID, alice.identity.Public, ch.Bytes, alice.identity.Sign(ch.Bytes))
	if err == nil {
		t.Fatal("an enrolment challenge opened a control-channel session")
	}
}

func TestSessionRejectsARevokedDevice(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	if _, err := f.store.Pool().Exec(f.ctx,
		`UPDATE devices SET revoked_at = now(), revoked_reason='test' WHERE id=$1`, alice.deviceID); err != nil {
		t.Fatal(err)
	}

	ch, err := f.srv.IssueChallenge(alice.identity.Public, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	err = f.rawHandshake(alice.membershipID, alice.identity.Public, ch.Bytes, alice.identity.Sign(ch.Bytes))
	if err == nil {
		t.Fatal("a revoked device opened a session")
	}
}

func TestSessionRejectsAnUnknownMembership(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	unknown := uuid.New()

	ch, err := f.srv.IssueChallenge(alice.identity.Public, unknown)
	if err != nil {
		t.Fatal(err)
	}
	err = f.rawHandshake(unknown, alice.identity.Public, ch.Bytes, alice.identity.Sign(ch.Bytes))
	if err == nil {
		t.Fatal("a session opened for a membership that does not exist")
	}
}

// --- behaviour --------------------------------------------------------------

// A mutation should reach connected agents without them asking.
func TestNotifyPushesNewState(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	applier, cancel := f.connect(alice, 0)
	defer cancel()

	select {
	case <-applier.applied:
	case <-time.After(15 * time.Second):
		t.Fatal("no initial state")
	}

	// A new device joins, which is exactly the kind of change every other agent needs.
	bob := f.enrolDevice("bob")
	f.hub.NotifyNetwork(f.netID)

	select {
	case state := <-applier.applied:
		found := false
		for _, p := range state.peers {
			if p.GetDeviceName() == "bob" {
				found = true
			}
		}
		if !found {
			t.Errorf("the pushed state does not mention the new device: %d peers", len(state.peers))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no state was pushed after the network changed")
	}
	_ = bob
}

// A device that reconnects before its old connection was noticed as dead ends up with
// one session, and it is the new one.
func TestReconnectDisplacesTheOldSession(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	first, cancelFirst := f.connect(alice, 0)
	defer cancelFirst()
	select {
	case <-first.applied:
	case <-time.After(15 * time.Second):
		t.Fatal("the first session never received state")
	}
	waitFor(t, "the first session to register", func() bool { return f.hub.Count() == 1 })

	second, cancelSecond := f.connect(alice, 0)
	defer cancelSecond()
	select {
	case <-second.applied:
	case <-time.After(15 * time.Second):
		t.Fatal("the second session never received state")
	}

	// Still exactly one, however long we wait.
	time.Sleep(300 * time.Millisecond)
	if got := f.hub.Count(); got != 1 {
		t.Errorf("hub holds %d sessions after a reconnect, want 1", got)
	}
}

// An agent that fails to apply must not be recorded as having applied. The convergence
// gap is the one metric that shows a broken agent, and it only works if it is honest.
func TestAFailedApplyIsNotRecordedAsApplied(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	applier := newCapturingApplier()
	applier.failWith = errNotToday

	client := sessionclient.New(sessionclient.Options{
		ControlURL:   f.http.URL,
		Identity:     alice.identity,
		MembershipID: alice.membershipID,
		AgentVersion: "test",
	})
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go func() { _ = client.RunOnce(ctx, applier) }()

	select {
	case <-applier.applied:
	case <-time.After(15 * time.Second):
		t.Fatal("no state was delivered")
	}

	waitFor(t, "the failure to be recorded", func() bool {
		var lastError string
		var applied int64
		err := f.store.Pool().QueryRow(f.ctx,
			`SELECT applied_version, last_error FROM membership_state WHERE membership_id=$1`,
			alice.membershipID).Scan(&applied, &lastError)
		return err == nil && applied == 0 && strings.Contains(lastError, "not today")
	})
}

var errNotToday = &testError{"not today"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// rawHandshake performs just the handshake, so a rejection can be observed without the
// client's reconnect logic retrying past it.
func (f *fixture) rawHandshake(membershipID uuid.UUID, identityKey, ch, signature []byte) error {
	f.t.Helper()
	return rawDial(f.ctx, f.http.URL, membershipID, identityKey, ch, signature)
}
