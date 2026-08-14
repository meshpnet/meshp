package store

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/google/uuid"
)

func subnetGroup(t *testing.T, s seeded, slug string) RouteGroup {
	t.Helper()
	group, err := s.CreateRouteGroup(testContext(t), CreateRouteGroupRequest{
		NetworkID: s.netID, Slug: slug, Kind: KindSubnet,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")},
	})
	if err != nil {
		t.Fatalf("CreateRouteGroup: %v", err)
	}
	return group
}

// A prefix written with host bits set means the range. Storing it as typed would make a
// rule about 256 addresses behave like a rule about one.
func TestRouteGroupPrefixesAreMasked(t *testing.T) {
	s, _ := seedNetwork(t)
	group, err := s.CreateRouteGroup(testContext(t), CreateRouteGroupRequest{
		NetworkID: s.netID, Slug: "branch", Kind: KindSubnet,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.10.55/24")},
	})
	if err != nil {
		t.Fatal(err)
	}

	groups, err := s.RouteGroupsFor(testContext(t), s.netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Prefixes) != 1 {
		t.Fatalf("read back %+v", groups)
	}
	if got := groups[0].Prefixes[0].String(); got != "192.168.10.0/24" {
		t.Errorf("stored %s, want the masked prefix", got)
	}
	if groups[0].ID != group.ID {
		t.Error("the group read back is not the one created")
	}
}

func TestRouteGroupsForAnEmptyNetwork(t *testing.T) {
	s, _ := seedNetwork(t)
	groups, err := s.RouteGroupsFor(testContext(t), s.netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 0 {
		t.Errorf("found %d groups in a network with none", len(groups))
	}
}

// Withdrawing is how an advertiser stops without the group being rebuilt.
func TestAdvertiseThenWithdraw(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()
	group := subnetGroup(t, s, "branch")

	if err := s.Advertise(ctx, AdvertiseRequest{
		NetworkID: s.netID, GroupSlug: "branch", MembershipID: membershipID, Priority: 1,
	}); err != nil {
		t.Fatalf("Advertise: %v", err)
	}

	rows, err := s.Advertisers(ctx, []uuid.UUID{group.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d advertisers, want 1", len(rows))
	}
	if rows[0].WireguardPublicKey == "" {
		t.Error("the advertiser came back with no key, so nothing could be steered at it")
	}

	if err := s.Withdraw(ctx, s.netID, "branch", membershipID); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	rows, err = s.Advertisers(ctx, []uuid.UUID{group.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("%d advertisers after withdrawing", len(rows))
	}
}

// A revoked device must stop being offered, or traffic would be steered at something that
// is no longer in the network.
func TestARevokedAdvertiserIsNotOffered(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()
	group := subnetGroup(t, s, "branch")

	if err := s.Advertise(ctx, AdvertiseRequest{
		NetworkID: s.netID, GroupSlug: "branch", MembershipID: membershipID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeMembership(ctx, RevokeRequest{
		NetworkID: s.netID, MembershipID: membershipID,
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.Advertisers(ctx, []uuid.UUID{group.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("a revoked device is still offered as an advertiser")
	}
}

// Naming a group that is not there is its own answer, which the caller turns into a 404
// rather than a 500.
func TestOperationsOnAnUnknownGroup(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()

	if err := s.Advertise(ctx, AdvertiseRequest{
		NetworkID: s.netID, GroupSlug: "nope", MembershipID: membershipID,
	}); !errors.Is(err, ErrNoSuchRouteGroup) {
		t.Errorf("Advertise: error = %v, want ErrNoSuchRouteGroup", err)
	}
	if err := s.Withdraw(ctx, s.netID, "nope", membershipID); !errors.Is(err, ErrNoSuchRouteGroup) {
		t.Errorf("Withdraw: error = %v, want ErrNoSuchRouteGroup", err)
	}
	if err := s.DeleteRouteGroup(ctx, s.netID, "nope"); !errors.Is(err, ErrNoSuchRouteGroup) {
		t.Errorf("DeleteRouteGroup: error = %v, want ErrNoSuchRouteGroup", err)
	}

	// And withdrawing a device that was never advertising is the same answer.
	subnetGroup(t, s, "branch")
	if err := s.Withdraw(ctx, s.netID, "branch", membershipID); !errors.Is(err, ErrNoSuchRouteGroup) {
		t.Errorf("withdrawing a device that never advertised: error = %v", err)
	}
}

func TestDeletingAGroupTakesItsAdvertisers(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()
	subnetGroup(t, s, "branch")

	if err := s.Advertise(ctx, AdvertiseRequest{
		NetworkID: s.netID, GroupSlug: "branch", MembershipID: membershipID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRouteGroup(ctx, s.netID, "branch"); err != nil {
		t.Fatal(err)
	}

	var advertisers int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM route_advertisers`).Scan(&advertisers); err != nil {
		t.Fatal(err)
	}
	if advertisers != 0 {
		t.Errorf("%d advertisers survived their group", advertisers)
	}
}

// Draining keeps the devices already using an advertiser and refuses new ones, which is how
// maintenance happens without dropping anybody. A state that is not one of the three would
// be silently treated as something.
func TestAdminStateIsChecked(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()
	subnetGroup(t, s, "branch")

	for _, state := range []string{"enabled", "draining", "disabled"} {
		if err := s.Advertise(ctx, AdvertiseRequest{
			NetworkID: s.netID, GroupSlug: "branch", MembershipID: membershipID, AdminState: state,
		}); err != nil {
			t.Errorf("admin state %q was refused: %v", state, err)
		}
	}
	if err := s.Advertise(ctx, AdvertiseRequest{
		NetworkID: s.netID, GroupSlug: "branch", MembershipID: membershipID, AdminState: "paused",
	}); err == nil {
		t.Error("accepted an admin state that is not one of the three")
	}
}

func TestCreatingANetworkWithPools(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)

	network, err := s.CreateNetwork(ctx, s.orgID, "branch", "Branch", []netip.Prefix{
		netip.MustParsePrefix("100.91.0.0/24"),
		netip.MustParsePrefix("fd7c:1::/120"),
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if network.Slug != "branch" {
		t.Errorf("slug = %q", network.Slug)
	}

	rows, err := s.pool.Query(ctx,
		`SELECT family FROM address_pools WHERE network_id = $1 ORDER BY family`, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var families []int16
	for rows.Next() {
		var f int16
		if err := rows.Scan(&f); err != nil {
			t.Fatal(err)
		}
		families = append(families, f)
	}
	if len(families) != 2 || families[0] != 4 || families[1] != 6 {
		t.Errorf("families = %v, want [4 6]", families)
	}

	// An unnamed network takes its slug, so it is never blank in a list.
	unnamed, err := s.CreateNetwork(ctx, s.orgID, "second", "", []netip.Prefix{
		netip.MustParsePrefix("100.92.0.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if unnamed.Name != "second" {
		t.Errorf("name = %q, want the slug", unnamed.Name)
	}
}

func TestSlugsMustBeUsableInAURL(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)
	for _, bad := range []string{"", "Branch LAN", "branch/lan", "-branch", "branch-", "BRANCH"} {
		if _, err := s.CreateNetwork(ctx, s.orgID, bad, "", []netip.Prefix{
			netip.MustParsePrefix("100.93.0.0/24"),
		}); err == nil {
			t.Errorf("accepted network slug %q", bad)
		}
		if _, err := s.CreateRouteGroup(ctx, CreateRouteGroupRequest{
			NetworkID: s.netID, Slug: bad, Kind: KindSubnet,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		}); err == nil {
			t.Errorf("accepted route group slug %q", bad)
		}
	}
}

// A route change is about every device at once, so it names none.
func TestRouteChangeNamesNoPeer(t *testing.T) {
	kind, err := RoutesChanged().kind()
	if err != nil || kind != "routes" {
		t.Fatalf("kind = %q, %v", kind, err)
	}
	id := uuid.New()
	if _, err := (Change{Routes: true, MembershipID: &id}).kind(); err == nil {
		t.Error("a route change that also named a peer was accepted")
	}
	if _, err := (Change{Routes: true, Policy: true}).kind(); err == nil {
		t.Error("a change that is both a policy and a route change was accepted")
	}
}
