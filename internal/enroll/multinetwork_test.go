package enroll

import (
	"testing"
	"time"

	"github.com/google/uuid"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// secondNetwork stands up another network in the same organisation, with its own pools.
func (f *fixture) secondNetwork(slug string) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.store.Pool().QueryRow(f.ctx,
		`INSERT INTO networks (organization_id, slug, name) VALUES ($1,$2,$2) RETURNING id`,
		f.orgID, slug).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.store.Pool().Exec(f.ctx,
		`INSERT INTO address_pools (network_id, prefix, family, purpose)
		 VALUES ($1,'100.95.0.0/24'::cidr,4,'device')`, id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// tokenFor mints a token for a network other than the fixture's own.
func (f *fixture) tokenFor(network uuid.UUID) Token {
	f.t.Helper()
	tok, err := NewToken()
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.store.Queries().CreateEnrollmentToken(f.ctx, dbgen.CreateEnrollmentTokenParams{
		NetworkID: network, OrganizationID: f.orgID, TokenHash: tok.Hash,
		PreassignedTags: []string{}, MaxUses: 1, ExpiresAt: f.clk.Now().Add(time.Hour),
	}); err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func (f *fixture) versionOf(network uuid.UUID) int64 {
	f.t.Helper()
	var v int64
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT state_version FROM networks WHERE id = $1`, network).Scan(&v); err != nil {
		f.t.Fatal(err)
	}
	return v
}

// Joining one network changes what the others should send, and they have to be told.
//
// A device's colliding prefixes are a property of the device -- two of *its* networks
// carrying the same prefix (ADR-0020) -- while state versions are per network (ADR-0008).
// Nothing in the first network knows the device joined a second, so without this its version
// never moves, no delta is ever built, and that membership goes on routing the customer's
// real prefix while the range allocated for it sits unused.
//
// This is the defect the end-to-end run found: one interface mapped, the other still carrying
// 192.168.1.0/24. It is invisible to every test that looks at one network at a time, which is
// every other test in this package.
func TestJoiningASecondNetworkTellsTheFirst(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t)

	first, _ := f.mintToken(1, time.Hour)
	if _, err := f.join(d, first.Plaintext); err != nil {
		t.Fatalf("the first join failed: %v", err)
	}
	before := f.versionOf(f.netID)

	// The same device, a second customer.
	other := f.secondNetwork("customer-b")
	if _, err := f.join(d, f.tokenFor(other).Plaintext); err != nil {
		t.Fatalf("the second join failed: %v", err)
	}

	if after := f.versionOf(f.netID); after <= before {
		t.Errorf("the first network's version stayed at %d; it will never send a delta, "+
			"so a colliding prefix there is never given its mapped range", before)
	}
}

// And a network this device is not in is left alone. Bumping every network in the
// organisation would make one join reconcile a whole deployment.
func TestJoiningDoesNotDisturbUnrelatedNetworks(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t)

	bystander := f.secondNetwork("bystander")
	before := f.versionOf(bystander)

	first, _ := f.mintToken(1, time.Hour)
	if _, err := f.join(d, first.Plaintext); err != nil {
		t.Fatalf("join failed: %v", err)
	}

	if after := f.versionOf(bystander); after != before {
		t.Errorf("a network this device is not in moved from %d to %d", before, after)
	}
}

// The first join of a device's life bumps only the network it joined. There is nothing else
// to tell, and a query that returned the network being joined would bump it twice.
func TestAFirstJoinBumpsOnlyItsOwnNetwork(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t)

	before := f.versionOf(f.netID)
	first, _ := f.mintToken(1, time.Hour)
	if _, err := f.join(d, first.Plaintext); err != nil {
		t.Fatalf("join failed: %v", err)
	}

	if after := f.versionOf(f.netID); after != before+1 {
		t.Errorf("version went %d -> %d; a first join should advance it exactly once", before, after)
	}
}
