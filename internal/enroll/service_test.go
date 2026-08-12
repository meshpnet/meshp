package enroll

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/ipam"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	"github.com/meshpnet/meshp/migrations"
)

// Enrolment is a database transaction with cryptography in the middle. Both halves
// have to be real for a test to mean anything, so these run against PostgreSQL and
// skip without it. CI always provides one.
type fixture struct {
	t      *testing.T
	svc    *Service
	store  *store.Store
	clk    *clock.Fake
	orgID  uuid.UUID
	netID  uuid.UUID
	ctx    context.Context
	poolV4 netip.Prefix
	poolV6 netip.Prefix
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := os.Getenv("MESHP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set MESHP_TEST_DATABASE_URL to run enrolment integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	clk := clock.NewFake()
	st, err := store.Open(ctx, store.DefaultConfig(url), migrations.FS, nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)

	// Each test starts from an empty schema so nothing leaks between them.
	dropAllTables(t, st, ctx)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	ch, err := NewChallenger([]byte("integration-test-master-secret"), DefaultChallengeTTL, clk)
	if err != nil {
		t.Fatal(err)
	}

	f := &fixture{
		t:      t,
		svc:    NewService(st, ch, clk, nil),
		store:  st,
		clk:    clk,
		ctx:    ctx,
		poolV4: netip.MustParsePrefix("100.90.0.0/24"),
		poolV6: netip.MustParsePrefix("fd7c:6d65:7368::/120"),
	}
	f.seed()
	return f
}

func dropAllTables(t *testing.T, st *store.Store, ctx context.Context) {
	t.Helper()
	rows, err := st.Pool().Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public'`)
	if err != nil {
		t.Fatalf("listing tables: %v", err)
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
			t.Fatalf("dropping %s: %v", n, err)
		}
	}
}

func (f *fixture) seed() {
	f.t.Helper()
	p := f.store.Pool()

	if err := p.QueryRow(f.ctx,
		`INSERT INTO organizations (slug, name) VALUES ('acme','Acme') RETURNING id`).Scan(&f.orgID); err != nil {
		f.t.Fatalf("seeding organisation: %v", err)
	}
	if err := p.QueryRow(f.ctx,
		`INSERT INTO networks (organization_id, slug, name) VALUES ($1,'hq','HQ') RETURNING id`,
		f.orgID).Scan(&f.netID); err != nil {
		f.t.Fatalf("seeding network: %v", err)
	}
	for _, pool := range []struct {
		prefix netip.Prefix
		family int
	}{{f.poolV4, 4}, {f.poolV6, 6}} {
		if _, err := p.Exec(f.ctx,
			`INSERT INTO address_pools (network_id, prefix, family, purpose) VALUES ($1,$2,$3,'device')`,
			f.netID, pool.prefix, pool.family); err != nil {
			f.t.Fatalf("seeding pool %s: %v", pool.prefix, err)
		}
	}
}

// mintToken creates a token the way an administrator would.
func (f *fixture) mintToken(maxUses int32, validFor time.Duration) (Token, dbgen.EnrollmentToken) {
	f.t.Helper()
	tok, err := NewToken()
	if err != nil {
		f.t.Fatal(err)
	}
	row, err := f.store.Queries().CreateEnrollmentToken(f.ctx, dbgen.CreateEnrollmentTokenParams{
		NetworkID:       f.netID,
		OrganizationID:  f.orgID,
		TokenHash:       tok.Hash,
		PreassignedTags: []string{"laptop"},
		MaxUses:         maxUses,
		ExpiresAt:       f.clk.Now().Add(validFor),
	})
	if err != nil {
		f.t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	return tok, row
}

// device is a client that behaves the way meshpd will.
type device struct {
	identity keys.Identity
	wg       keys.WireGuardPair
}

func newDevice(t *testing.T) device {
	t.Helper()
	id, err := keys.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wg, err := keys.NewWireGuardPair()
	if err != nil {
		t.Fatal(err)
	}
	return device{identity: id, wg: wg}
}

// join performs the full two-step exchange.
//
// A fresh WireGuard keypair is generated per call, deliberately. The identity key
// is shared across every membership a device holds — it is the device's name — but
// the WireGuard key is per membership, so two networks cannot recognise the same
// device by its key (Invariant 19). An earlier version of this helper reused one
// keypair and was rejected by the unique constraint, which is the schema being
// right and the test being wrong.
func (f *fixture) join(d device, token string) (RedeemResult, error) {
	f.t.Helper()

	wg, err := keys.NewWireGuardPair()
	if err != nil {
		return RedeemResult{}, err
	}

	resp, err := f.svc.IssueChallenge(f.ctx, ChallengeRequest{
		Token:             token,
		IdentityPublicKey: d.identity.Public,
	})
	if err != nil {
		return RedeemResult{}, err
	}
	challenge, err := ParseChallenge(resp.Challenge)
	if err != nil {
		return RedeemResult{}, err
	}

	return f.svc.Redeem(f.ctx, RedeemRequest{
		Token:              token,
		IdentityPublicKey:  d.identity.Public,
		Challenge:          challenge,
		Signature:          d.identity.Sign(challenge),
		WireGuardPublicKey: wg.Public.String(),
		Hostname:           "test-host",
		OS:                 "linux",
		OSVersion:          "6.9",
		AgentVersion:       "0.0.1",
	})
}

// --- the gate ---------------------------------------------------------------

func TestEnrolmentProducesADeviceWithAnAddress(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.mintToken(1, time.Hour)

	res, err := f.join(newDevice(t), tok.Plaintext)
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	if res.DeviceID == uuid.Nil || res.MembershipID == uuid.Nil {
		t.Fatalf("result has no identifiers: %+v", res)
	}
	if res.AddressV4 == nil || res.AddressV6 == nil {
		t.Fatalf("device got no address: %+v", res)
	}
	if !f.poolV4.Contains(*res.AddressV4) {
		t.Errorf("v4 address %v is outside the pool %v", res.AddressV4, f.poolV4)
	}
	if !f.poolV6.Contains(*res.AddressV6) {
		t.Errorf("v6 address %v is outside the pool %v", res.AddressV6, f.poolV6)
	}
	if res.InterfaceName != "meshp0" {
		t.Errorf("interface = %q, want meshp0", res.InterfaceName)
	}
	// A new device changes what every other agent should know about.
	if res.StateVersion <= 1 {
		t.Errorf("state version = %d, want it bumped past 1", res.StateVersion)
	}

	// The tags the administrator attached to the token travel to the membership.
	memberships, err := f.store.Queries().ListActiveMemberships(f.ctx, f.netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(memberships) != 1 {
		t.Fatalf("network has %d memberships, want 1", len(memberships))
	}
	if len(memberships[0].Tags) != 1 || memberships[0].Tags[0] != "laptop" {
		t.Errorf("tags = %v, want [laptop]", memberships[0].Tags)
	}

	// The allocation is recorded, not merely handed out — otherwise the next device
	// would be given the same address.
	var allocations int
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT count(*) FROM address_allocations WHERE holder_id = $1`, res.MembershipID).Scan(&allocations); err != nil {
		t.Fatal(err)
	}
	if allocations != 2 {
		t.Errorf("%d allocations recorded, want 2", allocations)
	}

	// And it is auditable (Invariant 13).
	events, err := f.store.Queries().ListAuditEventsForNetwork(f.ctx, dbgen.ListAuditEventsForNetworkParams{
		NetworkID: &f.netID,
		Limit:     10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "device.enrolled" {
		t.Errorf("audit events = %+v, want one device.enrolled", events)
	}
}

// The other half of the gate.
func TestReplayingATokenIsRefused(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.mintToken(1, time.Hour)

	if _, err := f.join(newDevice(t), tok.Plaintext); err != nil {
		t.Fatalf("first join: %v", err)
	}

	// A second device with the same token, which is what a leaked token looks like.
	_, err := f.join(newDevice(t), tok.Plaintext)
	if !errors.Is(err, ErrTokenExhausted) {
		t.Fatalf("second join error = %v, want ErrTokenExhausted", err)
	}

	// And the same device retrying, which is what a botched script looks like.
	d := newDevice(t)
	if _, err := f.join(d, tok.Plaintext); !errors.Is(err, ErrTokenExhausted) {
		t.Errorf("retry error = %v, want ErrTokenExhausted", err)
	}

	memberships, _ := f.store.Queries().ListActiveMemberships(f.ctx, f.netID)
	if len(memberships) != 1 {
		t.Errorf("network has %d memberships after a replay, want 1", len(memberships))
	}
}

// --- token lifecycle --------------------------------------------------------

func TestExpiredTokenIsRefused(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.mintToken(1, 10*time.Minute)

	f.clk.Advance(11 * time.Minute)
	_, err := f.join(newDevice(t), tok.Plaintext)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("error = %v, want ErrTokenExpired", err)
	}
}

func TestRevokedTokenIsRefused(t *testing.T) {
	f := newFixture(t)
	tok, row := f.mintToken(5, time.Hour)

	n, err := f.store.Queries().RevokeEnrollmentToken(f.ctx, dbgen.RevokeEnrollmentTokenParams{
		ID:        row.ID,
		NetworkID: f.netID,
	})
	if err != nil || n != 1 {
		t.Fatalf("RevokeEnrollmentToken: rows=%d err=%v", n, err)
	}

	if _, err := f.join(newDevice(t), tok.Plaintext); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("error = %v, want ErrTokenRevoked", err)
	}
}

func TestUnknownTokenIsRefused(t *testing.T) {
	f := newFixture(t)
	unused, _ := NewToken() // well formed, never stored

	if _, err := f.join(newDevice(t), unused.Plaintext); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("error = %v, want ErrTokenUnknown", err)
	}
}

func TestMultiUseTokenAllowsSeveralDevices(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.mintToken(3, time.Hour)

	seen := map[netip.Addr]bool{}
	for i := range 3 {
		res, err := f.join(newDevice(t), tok.Plaintext)
		if err != nil {
			t.Fatalf("join %d: %v", i+1, err)
		}
		// Every device gets a distinct address, which is the whole point of IPAM.
		if seen[*res.AddressV4] {
			t.Fatalf("address %v handed out twice", res.AddressV4)
		}
		seen[*res.AddressV4] = true
	}

	if _, err := f.join(newDevice(t), tok.Plaintext); !errors.Is(err, ErrTokenExhausted) {
		t.Errorf("fourth join error = %v, want ErrTokenExhausted", err)
	}
}

// --- proof of possession ----------------------------------------------------

// A failed proof must not burn a use of a token that is still good, or anyone able
// to reach the endpoint could exhaust every outstanding token.
func TestBadSignatureIsRefusedAndCostsNoUse(t *testing.T) {
	f := newFixture(t)
	tok, row := f.mintToken(1, time.Hour)
	d := newDevice(t)

	resp, err := f.svc.IssueChallenge(f.ctx, ChallengeRequest{Token: tok.Plaintext, IdentityPublicKey: d.identity.Public})
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := ParseChallenge(resp.Challenge)

	// Signed by somebody else.
	impostor := newDevice(t)
	_, err = f.svc.Redeem(f.ctx, RedeemRequest{
		Token:              tok.Plaintext,
		IdentityPublicKey:  d.identity.Public,
		Challenge:          challenge,
		Signature:          impostor.identity.Sign(challenge),
		WireGuardPublicKey: d.wg.Public.String(),
	})
	if !errors.Is(err, ErrProofFailed) {
		t.Fatalf("error = %v, want ErrProofFailed", err)
	}

	var uses int32
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT uses FROM enrollment_tokens WHERE id = $1`, row.ID).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if uses != 0 {
		t.Errorf("a failed proof consumed %d uses", uses)
	}

	// The honest device can still use it.
	if _, err := f.join(d, tok.Plaintext); err != nil {
		t.Errorf("legitimate join after a failed attempt: %v", err)
	}
}

func TestChallengeFromAnotherEnrolmentIsRefused(t *testing.T) {
	f := newFixture(t)
	tokA, _ := f.mintToken(1, time.Hour)
	tokB, _ := f.mintToken(1, time.Hour)
	d := newDevice(t)

	// A challenge issued for token A, spent against token B.
	resp, err := f.svc.IssueChallenge(f.ctx, ChallengeRequest{Token: tokA.Plaintext, IdentityPublicKey: d.identity.Public})
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := ParseChallenge(resp.Challenge)

	_, err = f.svc.Redeem(f.ctx, RedeemRequest{
		Token:              tokB.Plaintext,
		IdentityPublicKey:  d.identity.Public,
		Challenge:          challenge,
		Signature:          d.identity.Sign(challenge),
		WireGuardPublicKey: d.wg.Public.String(),
	})
	if !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("error = %v, want ErrChallengeInvalid", err)
	}
}

func TestExpiredChallengeIsRefused(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.mintToken(1, 24*time.Hour)
	d := newDevice(t)

	resp, err := f.svc.IssueChallenge(f.ctx, ChallengeRequest{Token: tok.Plaintext, IdentityPublicKey: d.identity.Public})
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := ParseChallenge(resp.Challenge)

	f.clk.Advance(DefaultChallengeTTL + time.Second)
	_, err = f.svc.Redeem(f.ctx, RedeemRequest{
		Token:              tok.Plaintext,
		IdentityPublicKey:  d.identity.Public,
		Challenge:          challenge,
		Signature:          d.identity.Sign(challenge),
		WireGuardPublicKey: d.wg.Public.String(),
	})
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("error = %v, want ErrChallengeExpired", err)
	}
}

func TestMalformedWireGuardKeyIsRefused(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.mintToken(1, time.Hour)
	d := newDevice(t)

	resp, _ := f.svc.IssueChallenge(f.ctx, ChallengeRequest{Token: tok.Plaintext, IdentityPublicKey: d.identity.Public})
	challenge, _ := ParseChallenge(resp.Challenge)

	for _, bad := range []string{"", "not-base64", "AAAA"} {
		_, err := f.svc.Redeem(f.ctx, RedeemRequest{
			Token:              tok.Plaintext,
			IdentityPublicKey:  d.identity.Public,
			Challenge:          challenge,
			Signature:          d.identity.Sign(challenge),
			WireGuardPublicKey: bad,
		})
		if err == nil {
			t.Errorf("accepted WireGuard key %q", bad)
		}
	}
}

// --- ADR-0004: one device, several networks ---------------------------------

func TestSameDeviceJoinsASecondNetwork(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t)

	tok1, _ := f.mintToken(1, time.Hour)
	first, err := f.join(d, tok1.Plaintext)
	if err != nil {
		t.Fatalf("first network: %v", err)
	}

	// A second network, as a customer's would be, with its own address space that
	// deliberately overlaps the first.
	var otherOrg, otherNet uuid.UUID
	p := f.store.Pool()
	if err := p.QueryRow(f.ctx,
		`INSERT INTO organizations (slug,name) VALUES ('customer','Customer') RETURNING id`).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(f.ctx,
		`INSERT INTO networks (organization_id,slug,name) VALUES ($1,'branch','Branch') RETURNING id`,
		otherOrg).Scan(&otherNet); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(f.ctx,
		`INSERT INTO address_pools (network_id,prefix,family,purpose) VALUES ($1,$2,4,'device')`,
		otherNet, f.poolV4); err != nil {
		t.Fatal(err)
	}

	tok2, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Queries().CreateEnrollmentToken(f.ctx, dbgen.CreateEnrollmentTokenParams{
		NetworkID: otherNet, OrganizationID: otherOrg, TokenHash: tok2.Hash,
		PreassignedTags: []string{}, MaxUses: 1, ExpiresAt: f.clk.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	second, err := f.join(d, tok2.Plaintext)
	if err != nil {
		t.Fatalf("second network: %v", err)
	}

	// One device, two memberships — a technician's laptop reaching into a customer
	// network without becoming a second device.
	if second.DeviceID != first.DeviceID {
		t.Errorf("a second enrolment created a new device: %v then %v", first.DeviceID, second.DeviceID)
	}
	if second.MembershipID == first.MembershipID {
		t.Error("the second network reused the first membership")
	}
	// Separate interfaces, because the two networks' address space overlaps.
	if second.InterfaceName == first.InterfaceName {
		t.Errorf("both memberships claim interface %q", first.InterfaceName)
	}

	// Ownership stays with the organisation that first enrolled it.
	var ownerOrg uuid.UUID
	if err := p.QueryRow(f.ctx, `SELECT organization_id FROM devices WHERE id=$1`, first.DeviceID).Scan(&ownerOrg); err != nil {
		t.Fatal(err)
	}
	if ownerOrg != f.orgID {
		t.Errorf("device ownership moved to %v, want %v", ownerOrg, f.orgID)
	}

	// Each membership has its own WireGuard key, so the two networks cannot
	// correlate the device (Invariant 19).
	var distinctKeys int
	if err := p.QueryRow(f.ctx,
		`SELECT count(DISTINCT public_key) FROM wireguard_keys WHERE membership_id = ANY($1)`,
		[]uuid.UUID{first.MembershipID, second.MembershipID}).Scan(&distinctKeys); err != nil {
		t.Fatal(err)
	}
	if distinctKeys != 2 {
		t.Errorf("%d distinct WireGuard keys across two memberships, want 2", distinctKeys)
	}
}

func TestJoiningTheSameNetworkTwiceIsRefused(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t)

	tok1, _ := f.mintToken(1, time.Hour)
	if _, err := f.join(d, tok1.Plaintext); err != nil {
		t.Fatal(err)
	}
	tok2, _ := f.mintToken(1, time.Hour)
	if _, err := f.join(d, tok2.Plaintext); !errors.Is(err, ErrAlreadyInNetwork) {
		t.Fatalf("error = %v, want ErrAlreadyInNetwork", err)
	}
}

func TestRevokedDeviceCannotReEnrol(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t)

	tok1, _ := f.mintToken(1, time.Hour)
	res, err := f.join(d, tok1.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool().Exec(f.ctx,
		`UPDATE devices SET revoked_at = now(), revoked_reason='test' WHERE id=$1`, res.DeviceID); err != nil {
		t.Fatal(err)
	}

	// A valid token does not undo a revocation.
	tok2, _ := f.mintToken(1, time.Hour)
	if _, err := f.join(d, tok2.Plaintext); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("error = %v, want ErrDeviceRevoked", err)
	}
}

// --- races and exhaustion ---------------------------------------------------

// Several devices redeeming one single-use token at the same moment. Exactly one
// may win; the guarded increment inside the transaction is what makes that true.
func TestConcurrentRedemptionOfASingleUseToken(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.mintToken(1, time.Hour)

	const racers = 8
	devices := make([]device, racers)
	challenges := make([][]byte, racers)
	for i := range devices {
		devices[i] = newDevice(t)
		resp, err := f.svc.IssueChallenge(f.ctx, ChallengeRequest{
			Token: tok.Plaintext, IdentityPublicKey: devices[i].identity.Public,
		})
		if err != nil {
			t.Fatal(err)
		}
		challenges[i], _ = ParseChallenge(resp.Challenge)
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		other     []error
	)
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.svc.Redeem(f.ctx, RedeemRequest{
				Token:              tok.Plaintext,
				IdentityPublicKey:  devices[i].identity.Public,
				Challenge:          challenges[i],
				Signature:          devices[i].identity.Sign(challenges[i]),
				WireGuardPublicKey: devices[i].wg.Public.String(),
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrTokenExhausted):
			default:
				other = append(other, err)
			}
		}(i)
	}
	wg.Wait()

	for _, err := range other {
		t.Errorf("unexpected error from a racer: %v", err)
	}
	if succeeded != 1 {
		t.Errorf("%d of %d racers enrolled, want exactly 1", succeeded, racers)
	}

	memberships, _ := f.store.Queries().ListActiveMemberships(f.ctx, f.netID)
	if len(memberships) != 1 {
		t.Errorf("network has %d memberships, want 1", len(memberships))
	}
}

// Two devices enrolling concurrently on a multi-use token must not be given the
// same address. The pool row lock is what prevents it.
func TestConcurrentEnrolmentsGetDistinctAddresses(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.mintToken(20, time.Hour)

	const racers = 10
	type prepared struct {
		d         device
		challenge []byte
	}
	all := make([]prepared, racers)
	for i := range all {
		d := newDevice(t)
		resp, err := f.svc.IssueChallenge(f.ctx, ChallengeRequest{
			Token: tok.Plaintext, IdentityPublicKey: d.identity.Public,
		})
		if err != nil {
			t.Fatal(err)
		}
		ch, _ := ParseChallenge(resp.Challenge)
		all[i] = prepared{d: d, challenge: ch}
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		v4s  = map[netip.Addr]bool{}
		errs []error
	)
	for _, p := range all {
		wg.Add(1)
		go func(p prepared) {
			defer wg.Done()
			res, err := f.svc.Redeem(f.ctx, RedeemRequest{
				Token:              tok.Plaintext,
				IdentityPublicKey:  p.d.identity.Public,
				Challenge:          p.challenge,
				Signature:          p.d.identity.Sign(p.challenge),
				WireGuardPublicKey: p.d.wg.Public.String(),
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if v4s[*res.AddressV4] {
				errs = append(errs, errors.New("address "+res.AddressV4.String()+" handed out twice"))
				return
			}
			v4s[*res.AddressV4] = true
		}(p)
	}
	wg.Wait()

	for _, err := range errs {
		t.Errorf("%v", err)
	}
	if len(v4s) != racers {
		t.Errorf("%d distinct addresses across %d enrolments", len(v4s), racers)
	}
}

func TestNetworkWithoutAnAddressPoolFailsClearly(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.Pool().Exec(f.ctx, `DELETE FROM address_pools WHERE network_id=$1`, f.netID); err != nil {
		t.Fatal(err)
	}
	tok, _ := f.mintToken(1, time.Hour)

	if _, err := f.join(newDevice(t), tok.Plaintext); !errors.Is(err, ErrNoAddressPool) {
		t.Fatalf("error = %v, want ErrNoAddressPool", err)
	}
}

// A pool with nowhere left to go must fail as exhaustion rather than by handing out
// a duplicate or a nonsense address.
func TestPoolExhaustionIsReported(t *testing.T) {
	f := newFixture(t)
	p := f.store.Pool()
	if _, err := p.Exec(f.ctx, `DELETE FROM address_pools WHERE network_id=$1`, f.netID); err != nil {
		t.Fatal(err)
	}
	// A /30 leaves exactly two usable addresses.
	if _, err := p.Exec(f.ctx,
		`INSERT INTO address_pools (network_id,prefix,family,purpose) VALUES ($1,'100.90.7.0/30',4,'device')`,
		f.netID); err != nil {
		t.Fatal(err)
	}
	tok, _ := f.mintToken(5, time.Hour)

	for i := range 2 {
		if _, err := f.join(newDevice(t), tok.Plaintext); err != nil {
			t.Fatalf("join %d: %v", i+1, err)
		}
	}
	_, err := f.join(newDevice(t), tok.Plaintext)
	if err == nil {
		t.Fatal("a third device was enrolled into a /30")
	}
	// The sentinel has to survive the service's wrapping, or an operator sees a
	// generic failure and has no idea their pool is full.
	if !errors.Is(err, ipam.ErrExhausted) && !errors.Is(err, ipam.ErrAllQuarantined) {
		t.Fatalf("exhaustion did not surface as an ipam error: %v", err)
	}
	if !strings.Contains(err.Error(), "100.90.7.0/30") {
		t.Errorf("error does not name the exhausted pool: %v", err)
	}
}
