package store

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/health"
)

// assignmentFor reads back what the control plane recorded about one device's choice.
func assignmentFor(t *testing.T, s seeded, membershipID, groupID uuid.UUID) (advertiser uuid.UUID, reason string, version int64, ok bool) {
	t.Helper()
	var advertiserID *uuid.UUID
	err := s.pool.QueryRow(testContext(t),
		`SELECT advertiser_id, reason, version FROM route_assignments
		 WHERE membership_id = $1 AND route_group_id = $2`,
		membershipID, groupID).Scan(&advertiserID, &reason, &version)
	if err != nil {
		return uuid.Nil, "", 0, false
	}
	if advertiserID != nil {
		advertiser = *advertiserID
	}
	return advertiser, reason, version, true
}

// ADR-0003 splits authority: the server owns authorisation and order, the agent owns
// liveness, and the server records what the agent chose. Only the first half was ever
// built — route_assignments sat in the schema from the first migration with nothing
// writing it, so nothing could answer "which candidate is actually carrying this".
func TestAnAgentsChoiceIsRecorded(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	clk := clock.NewFake()
	membershipID := addDevice()
	group := subnetGroup(t, s, "branch")
	advertiserID := advertiserFor(t, s, "branch", membershipID)

	if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
		NetworkID: s.netID, AdvertiserID: advertiserID,
		MembershipID: membershipID, RouteGroupID: group.ID,
		Reason:   "first choice, reachable",
		Observed: health.SignalOK, Clock: clk,
	}); err != nil {
		t.Fatalf("ObserveAdvertiser: %v", err)
	}

	got, reason, version, ok := assignmentFor(t, s, membershipID, group.ID)
	if !ok {
		t.Fatal("nothing was recorded about what this device chose")
	}
	if got != advertiserID {
		t.Errorf("advertiser = %s, want %s", got, advertiserID)
	}
	// Kept verbatim: it is the only account of the decision that came from the machine
	// that made it, and it is what answers "why did my outbound IP change?" later.
	if reason != "first choice, reachable" {
		t.Errorf("reason = %q, want the agent's own words", reason)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}
}

// Reports arrive from every device on every heartbeat. An update that ran each time would
// write a row per device per group every twenty-five seconds, against a table in the same
// database as desired state — the write rate ADR-0012 exists to keep away from it.
func TestRepeatingTheSameChoiceWritesNothing(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	clk := clock.NewFake()
	membershipID := addDevice()
	group := subnetGroup(t, s, "branch")
	advertiserID := advertiserFor(t, s, "branch", membershipID)

	for range 5 {
		clk.Advance(time.Minute)
		if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
			NetworkID: s.netID, AdvertiserID: advertiserID,
			MembershipID: membershipID, RouteGroupID: group.ID,
			Reason:   "still fine",
			Observed: health.SignalOK, Clock: clk,
		}); err != nil {
			t.Fatalf("ObserveAdvertiser: %v", err)
		}
	}

	_, _, version, ok := assignmentFor(t, s, membershipID, group.ID)
	if !ok {
		t.Fatal("nothing was recorded")
	}
	// The version moves when the choice moves. Five identical reports are one choice.
	if version != 1 {
		t.Errorf("version = %d after five identical reports, want 1", version)
	}
}

// And when a device does move, the record moves with it — including the reason, which is
// the whole point of keeping one.
func TestMovingBetweenCandidatesUpdatesTheRecord(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	clk := clock.NewFake()
	membershipID := addDevice()
	otherID := addDevice()
	group := subnetGroup(t, s, "branch")
	first := advertiserFor(t, s, "branch", membershipID)
	second := advertiserFor(t, s, "branch", otherID)

	for _, step := range []struct {
		advertiser uuid.UUID
		reason     string
	}{
		{first, "first choice, reachable"},
		{second, "first choice stopped answering"},
	} {
		clk.Advance(time.Minute)
		if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
			NetworkID: s.netID, AdvertiserID: step.advertiser,
			MembershipID: membershipID, RouteGroupID: group.ID,
			Reason:   step.reason,
			Observed: health.SignalOK, Clock: clk,
		}); err != nil {
			t.Fatalf("ObserveAdvertiser: %v", err)
		}
	}

	got, reason, version, _ := assignmentFor(t, s, membershipID, group.ID)
	if got != second {
		t.Errorf("advertiser = %s, want the one it moved to (%s)", got, second)
	}
	if reason != "first choice stopped answering" {
		t.Errorf("reason = %q, want the reason for the move", reason)
	}
	if version != 2 {
		t.Errorf("version = %d, want 2 after one move", version)
	}
}

// A caller with only an advertiser to talk about records health and nothing else, rather
// than inventing a membership to attach a choice to.
func TestAReportWithNoGroupRecordsNoChoice(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()
	group := subnetGroup(t, s, "branch")
	advertiserID := advertiserFor(t, s, "branch", membershipID)

	if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
		NetworkID: s.netID, AdvertiserID: advertiserID,
		Observed: health.SignalOK, Clock: clock.NewFake(),
	}); err != nil {
		t.Fatalf("ObserveAdvertiser: %v", err)
	}
	if _, _, _, ok := assignmentFor(t, s, membershipID, group.ID); ok {
		t.Error("a report naming no group recorded a choice anyway")
	}
}

// And the count reaches the overview, which is what makes any of this visible. A record
// nothing reads is the failure this was fixing (ADR-0018).
func TestTheOverviewCountsWhoIsUsingEachCandidate(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()
	group := subnetGroup(t, s, "branch")
	advertiserID := advertiserFor(t, s, "branch", membershipID)

	before, err := s.NetworkOverview(ctx, s.netID, DefaultOverviewDevices)
	if err != nil {
		t.Fatalf("NetworkOverview: %v", err)
	}
	if n := inUseFor(before, advertiserID); n != 0 {
		t.Errorf("in use by %d before anything reported, want 0", n)
	}

	if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
		NetworkID: s.netID, AdvertiserID: advertiserID,
		MembershipID: membershipID, RouteGroupID: group.ID,
		Observed: health.SignalOK, Clock: clock.NewFake(),
	}); err != nil {
		t.Fatalf("ObserveAdvertiser: %v", err)
	}

	after, err := s.NetworkOverview(ctx, s.netID, DefaultOverviewDevices)
	if err != nil {
		t.Fatalf("NetworkOverview: %v", err)
	}
	if n := inUseFor(after, advertiserID); n != 1 {
		t.Errorf("in use by %d after one device reported, want 1", n)
	}
}

func inUseFor(overview NetworkOverview, advertiserID uuid.UUID) int64 {
	for _, g := range overview.Groups {
		for _, a := range g.Advertisers {
			if a.ID == advertiserID {
				return a.InUseBy
			}
		}
	}
	return -1
}
