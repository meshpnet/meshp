package store

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/acl"
)

// seeded is a migrated store with one organisation, one network and a device pool.
type seeded struct {
	*Store
	orgID uuid.UUID
	netID uuid.UUID
}

func seedNetwork(t *testing.T) (seeded, func() uuid.UUID) {
	t.Helper()
	s := openStore(t)
	dropAll(t, s)
	ctx := testContext(t)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var orgID, netID uuid.UUID
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO organizations (slug,name) VALUES ('acme','Acme') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO networks (organization_id,slug,name) VALUES ($1,'hq','HQ') RETURNING id`,
		orgID).Scan(&netID); err != nil {
		t.Fatal(err)
	}

	// addDevice puts a member in the network and returns its membership id.
	n := 0
	addDevice := func() uuid.UUID {
		t.Helper()
		n++
		var deviceID, membershipID uuid.UUID
		if err := s.pool.QueryRow(ctx,
			`INSERT INTO devices (organization_id,name,identity_public_key)
			 VALUES ($1,$2,$3) RETURNING id`,
			orgID, "device", []byte{byte(n)}).Scan(&deviceID); err != nil {
			t.Fatal(err)
		}
		if err := s.pool.QueryRow(ctx,
			`INSERT INTO device_network_memberships
			   (device_id,network_id,interface_name,address_v4,tags,dns_label)
			 VALUES ($1,$2,'meshp0',$3,$4,$5) RETURNING id`,
			deviceID, netID, netip.AddrFrom4([4]byte{100, 90, 0, byte(n)}).String(),
			[]string{"laptop"}, fmt.Sprintf("device-%d", n)).Scan(&membershipID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO wireguard_keys (membership_id,public_key,state)
			 VALUES ($1,$2,'current')`, membershipID, "key-"+membershipID.String()); err != nil {
			t.Fatal(err)
		}
		return membershipID
	}

	return seeded{Store: s, orgID: orgID, netID: netID}, addDevice
}

func simplePolicy() acl.Document {
	return acl.Document{Version: acl.Version, Rules: []acl.Rule{
		{Src: []acl.Selector{"tag:laptop"}, Dst: []acl.Selector{"*"}},
	}}
}

// No policy is a condition, not a failure — and every caller has to be able to tell it
// apart from an empty one, because they mean opposite things.
func TestActivePolicyReportsWhenThereIsNone(t *testing.T) {
	s, _ := seedNetwork(t)
	if _, err := s.ActivePolicy(testContext(t), s.netID); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("error = %v, want ErrNoPolicy", err)
	}
}

func TestPublishAndReadBack(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)

	published, err := s.PublishPolicy(ctx, PublishPolicyRequest{
		NetworkID: s.netID, Document: simplePolicy(), OrganizationID: &s.orgID,
	})
	if err != nil {
		t.Fatalf("PublishPolicy: %v", err)
	}
	if published.Version != 1 {
		t.Errorf("version = %d, want 1", published.Version)
	}

	active, err := s.ActivePolicy(ctx, s.netID)
	if err != nil {
		t.Fatalf("ActivePolicy: %v", err)
	}
	if len(active.Document.Rules) != 1 {
		t.Fatalf("%d rules came back", len(active.Document.Rules))
	}
	if active.Document.Rules[0].Src[0] != "tag:laptop" {
		t.Errorf("the rule changed in storage: %+v", active.Document.Rules[0])
	}
}

// Versions name publications, not contents. Re-publishing an older document is a rollback
// and still moves forward, or the history would be ambiguous.
func TestVersionsAlwaysMoveForward(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)

	for want := int32(1); want <= 3; want++ {
		got, err := s.PublishPolicy(ctx, PublishPolicyRequest{
			NetworkID: s.netID, Document: simplePolicy(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != want {
			t.Fatalf("version = %d, want %d", got.Version, want)
		}
	}

	var active int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM acl_policies WHERE network_id = $1 AND is_active`, s.netID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("%d policies active, want 1", active)
	}
}

// A document this build cannot compile faithfully must never be published: it would sit in
// storage compiling into a filter nobody wrote.
func TestPublishingRefusesAnInvalidDocument(t *testing.T) {
	s, _ := seedNetwork(t)
	_, err := s.PublishPolicy(testContext(t), PublishPolicyRequest{
		NetworkID: s.netID,
		Document:  acl.Document{Version: 99},
	})
	if err == nil {
		t.Fatal("published a document this build does not understand")
	}
}

// Stored and unreadable is not the same as absent. Downgrading it to "no policy" would open
// a network its operator believes is closed.
func TestAnUnreadableStoredPolicyIsAnError(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO acl_policies (network_id, version, document, is_active)
		 VALUES ($1, 1, $2::jsonb, true)`,
		s.netID, `{"version":99,"rules":[]}`); err != nil {
		t.Fatal(err)
	}

	_, err := s.ActivePolicy(ctx, s.netID)
	if err == nil {
		t.Fatal("an unreadable policy was read as usable")
	}
	if errors.Is(err, ErrNoPolicy) {
		t.Fatal("an unreadable policy was reported as no policy at all")
	}
}

func TestPolicyDevicesResolvesMembers(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	first := addDevice()
	addDevice()

	devices, err := s.PolicyDevices(ctx, s.netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Fatalf("%d devices, want 2", len(devices))
	}
	for _, d := range devices {
		if len(d.Addresses) == 0 {
			t.Error("a device came back with no addresses")
		}
		if len(d.Tags) == 0 {
			t.Error("a device came back with no tags; selectors would never match it")
		}
	}

	// A revoked member leaves the list, or its address would stay in every other device's
	// filter granting access to something no longer in the network.
	if _, err := s.RevokeMembership(ctx, RevokeRequest{
		NetworkID: s.netID, MembershipID: first,
	}); err != nil {
		t.Fatal(err)
	}
	devices, err = s.PolicyDevices(ctx, s.netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("%d devices after a revocation, want 1", len(devices))
	}
}

// A policy change is about every device at once, so it names none. One that named a
// membership would look like a change to that device alone.
func TestPolicyChangeNamesNoPeer(t *testing.T) {
	change := PolicyChanged()
	kind, err := change.kind()
	if err != nil {
		t.Fatal(err)
	}
	if kind != "policy" {
		t.Errorf("kind = %q", kind)
	}

	// And a change that claims to be both is refused rather than resolved.
	id := uuid.New()
	confused := Change{Policy: true, MembershipID: &id}
	if _, err := confused.kind(); err == nil {
		t.Error("a change that is both a policy change and a peer change was accepted")
	}

	if _, err := (Change{}).kind(); err == nil {
		t.Error("a change naming nothing at all was accepted")
	}
	key := "k"
	if _, err := (Change{MembershipID: &id, PeerPublicKey: &key}).kind(); err == nil {
		t.Error("a change naming both a membership and a key was accepted")
	}
	if kind, err := PeerUpserted(id).kind(); err != nil || kind != "peer_upsert" {
		t.Errorf("PeerUpserted = %q, %v", kind, err)
	}
}

// Revoking something that is not there is its own answer, and the caller turns it into a
// 404 rather than a 500.
func TestRevokingWhatIsNotThere(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()

	if _, err := s.RevokeMembership(ctx, RevokeRequest{
		NetworkID: s.netID, MembershipID: uuid.New(),
	}); !errors.Is(err, ErrNotAMember) {
		t.Errorf("unknown membership: error = %v, want ErrNotAMember", err)
	}

	if _, err := s.RevokeMembership(ctx, RevokeRequest{
		NetworkID: uuid.New(), MembershipID: membershipID,
	}); !errors.Is(err, ErrNotAMember) {
		t.Errorf("wrong network: error = %v, want ErrNotAMember", err)
	}

	revoked, err := s.RevokeMembership(ctx, RevokeRequest{
		NetworkID: s.netID, MembershipID: membershipID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.WireGuardPublicKey == "" {
		t.Error("revocation did not report which key stopped being a peer")
	}

	if _, err := s.RevokeMembership(ctx, RevokeRequest{
		NetworkID: s.netID, MembershipID: membershipID,
	}); !errors.Is(err, ErrNotAMember) {
		t.Errorf("revoking twice: error = %v, want ErrNotAMember", err)
	}
}
