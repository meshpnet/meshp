package session

import (
	"net/netip"
	"testing"

	"github.com/meshpnet/meshp/internal/store"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func (f *fixture) subnetGroup(slug string, prefixes ...string) store.RouteGroup {
	f.t.Helper()
	var parsed []netip.Prefix
	for _, p := range prefixes {
		parsed = append(parsed, netip.MustParsePrefix(p))
	}
	group, err := f.store.CreateRouteGroup(f.ctx, store.CreateRouteGroupRequest{
		NetworkID: f.netID, Slug: slug, Kind: store.KindSubnet, Prefixes: parsed,
	})
	if err != nil {
		f.t.Fatalf("CreateRouteGroup: %v", err)
	}
	return group
}

func (f *fixture) advertise(slug string, d device, priority int32) {
	f.t.Helper()
	if err := f.store.Advertise(f.ctx, store.AdvertiseRequest{
		NetworkID: f.netID, GroupSlug: slug, MembershipID: d.membershipID, Priority: priority,
	}); err != nil {
		f.t.Fatalf("Advertise: %v", err)
	}
}

func (f *fixture) assignments(d device) []*meshpv1.RouteGroupAssignment {
	f.t.Helper()
	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, d.membershipID)
	if err != nil {
		f.t.Fatal(err)
	}
	return snapshot.GetRouteGroups()
}

// The ordinary case: a device is told which peers can carry a branch office's LAN.
func TestADeviceIsToldWhoCarriesAPrefix(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	got := f.assignments(laptop)
	if len(got) != 1 {
		t.Fatalf("%d assignments, want 1", len(got))
	}
	if len(got[0].GetPrefixes()) != 1 || got[0].GetPrefixes()[0] != "192.168.10.0/24" {
		t.Errorf("prefixes = %v", got[0].GetPrefixes())
	}
	if len(got[0].GetCandidates()) != 1 {
		t.Fatalf("%d candidates, want 1", len(got[0].GetCandidates()))
	}
	if got[0].GetCandidates()[0].GetPeerPublicKey() == "" {
		t.Error("the candidate carries no key, so nothing could be routed to it")
	}
	if got[0].GetMode() != meshpv1.RouteGroupAssignment_MODE_FAILOVER {
		t.Errorf("mode = %v", got[0].GetMode())
	}
}

// An advertiser routing its own LAN into a tunnel that comes back out of the same machine
// is at best a loop and at worst takes the site off the internet.
func TestAnAdvertiserIsNotOfferedItself(t *testing.T) {
	f := newFixture(t)
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	if got := f.assignments(router); len(got) != 0 {
		t.Fatalf("the only advertiser was offered its own group: %+v", got)
	}
}

// Candidates come ordered, best first, and the agent picks among them without asking. An
// agent that had to ask could not fail over during a control-plane outage, which is exactly
// when it is most likely to need to (ADR-0003).
func TestCandidatesAreOrderedByPriority(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	primary := f.enrolDevice("primary")
	backup := f.enrolDevice("backup")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", backup, 10)
	f.advertise("branch-lan", primary, 1)

	got := f.assignments(laptop)
	if len(got) != 1 || len(got[0].GetCandidates()) != 2 {
		t.Fatalf("assignments = %+v", got)
	}
	if got[0].GetCandidates()[0].GetPriority() != 1 {
		t.Errorf("the preferred candidate is priority %d, want 1",
			got[0].GetCandidates()[0].GetPriority())
	}
}

// A group nobody can carry is withdrawn rather than sent with an empty candidate list:
// installing a route to nowhere blackholes the prefix instead of leaving it alone.
func TestAGroupWithNoAdvertiserIsWithdrawnRatherThanEmpty(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	group := f.subnetGroup("branch-lan", "192.168.10.0/24")

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, laptop.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.GetRouteGroups()) != 0 {
		t.Errorf("a group with no advertiser was assigned: %+v", snapshot.GetRouteGroups())
	}
	// Proto3 cannot tell an empty repeated field from an absent one, so the withdrawal has
	// to be said out loud or a device that lost its last advertiser would route to it forever.
	found := false
	for _, id := range snapshot.GetRemovedRouteGroupIds() {
		if id == group.ID.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("the unassignable group was not withdrawn: %v", snapshot.GetRemovedRouteGroupIds())
	}
}

// Losing the last advertiser must reach devices as a withdrawal, or they keep routing a
// prefix at a device that no longer carries it.
func TestWithdrawingTheLastAdvertiserWithdrawsTheGroup(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	group := f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	builder := NewStateBuilder(f.store)
	before, err := builder.Snapshot(f.ctx, laptop.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.GetRouteGroups()) != 1 {
		t.Fatalf("expected one assignment to begin with: %+v", before.GetRouteGroups())
	}

	if err := f.store.Withdraw(f.ctx, f.netID, "branch-lan", router.membershipID); err != nil {
		t.Fatal(err)
	}

	delta, err := builder.For(f.ctx, laptop.membershipID, before.GetToVersion())
	if err != nil {
		t.Fatal(err)
	}
	if delta.GetFromVersion() == 0 {
		// A snapshot clears the whole set, which is also correct.
		if len(delta.GetRouteGroups()) != 0 {
			t.Errorf("a snapshot still assigns the group: %+v", delta.GetRouteGroups())
		}
		return
	}
	withdrawn := false
	for _, id := range delta.GetRemovedRouteGroupIds() {
		if id == group.ID.String() {
			withdrawn = true
		}
	}
	if !withdrawn {
		t.Errorf("the group was not withdrawn: %+v", delta)
	}
}

// A revoked advertiser must stop being offered, or traffic is steered at a device that is
// no longer in the network.
func TestARevokedAdvertiserLeavesTheCandidates(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	primary := f.enrolDevice("primary")
	backup := f.enrolDevice("backup")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", primary, 1)
	f.advertise("branch-lan", backup, 2)

	if _, err := f.store.RevokeMembership(f.ctx, store.RevokeRequest{
		NetworkID: f.netID, MembershipID: primary.membershipID,
	}); err != nil {
		t.Fatal(err)
	}

	got := f.assignments(laptop)
	if len(got) != 1 {
		t.Fatalf("assignments = %+v", got)
	}
	if len(got[0].GetCandidates()) != 1 {
		t.Fatalf("%d candidates after a revocation, want 1", len(got[0].GetCandidates()))
	}
	if got[0].GetCandidates()[0].GetPriority() != 2 {
		t.Error("the revoked advertiser is still being offered")
	}
}

// An egress group carries the default route for both families, so an agent claiming one
// claims it for both rather than leaving IPv6 to leak past.
func TestAnEgressGroupCarriesBothDefaultRoutes(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	exit := f.enrolDevice("exit")
	if _, err := f.store.CreateRouteGroup(f.ctx, store.CreateRouteGroupRequest{
		NetworkID: f.netID, Slug: "exit", Kind: store.KindEgress,
	}); err != nil {
		t.Fatal(err)
	}
	f.advertise("exit", exit, 1)

	got := f.assignments(laptop)
	if len(got) != 1 {
		t.Fatalf("assignments = %+v", got)
	}
	prefixes := got[0].GetPrefixes()
	if len(prefixes) != 2 || prefixes[0] != "0.0.0.0/0" || prefixes[1] != "::/0" {
		t.Errorf("prefixes = %v, want both default routes", prefixes)
	}
}

// A route change reaches agents as a delta, and an unrelated change does not resend the
// assignments — an agent diffing them would reinstall routes it already has.
func TestAssignmentsAreSentOnlyWhenRoutesChange(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")

	builder := NewStateBuilder(f.store)
	before, err := builder.Snapshot(f.ctx, laptop.membershipID)
	if err != nil {
		t.Fatal(err)
	}

	f.advertise("branch-lan", router, 1)
	delta, err := builder.For(f.ctx, laptop.membershipID, before.GetToVersion())
	if err != nil {
		t.Fatal(err)
	}
	if delta.GetFromVersion() != 0 && len(delta.GetRouteGroups()) == 0 {
		t.Fatalf("a route change produced a delta with no assignments: %+v", delta)
	}

	// Now something unrelated.
	at := delta.GetToVersion()
	f.enrolDevice("someone-else")
	next, err := builder.For(f.ctx, laptop.membershipID, at)
	if err != nil {
		t.Fatal(err)
	}
	if next.GetFromVersion() == 0 {
		t.Skip("the builder chose a snapshot, which always carries assignments")
	}
	if len(next.GetRouteGroups()) != 0 {
		t.Errorf("an unrelated peer change resent the assignments: %+v", next.GetRouteGroups())
	}
}

// Nothing branches on it, but two computations of the same state must render identically or
// every recomputation looks like a change.
func TestAssignmentsAreDeterministic(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	for i, name := range []string{"a", "b", "c"} {
		f.advertise("branch-lan", f.enrolDevice(name), int32(i%2))
	}

	first := f.assignments(laptop)
	for range 10 {
		got := f.assignments(laptop)
		if len(got) != len(first) {
			t.Fatalf("assignment count changed: %d then %d", len(first), len(got))
		}
		for i := range got {
			a, b := got[i].GetCandidates(), first[i].GetCandidates()
			if len(a) != len(b) {
				t.Fatalf("candidate count changed")
			}
			for j := range a {
				if a[j].GetAdvertiserId() != b[j].GetAdvertiserId() {
					t.Fatalf("candidate order changed at %d: %s then %s",
						j, b[j].GetAdvertiserId(), a[j].GetAdvertiserId())
				}
			}
		}
	}
}

// The advertiser's own half. It is excluded from its group's assignments — it would be
// routing its own LAN into a tunnel that comes back out of the same machine — so this is
// the only thing that tells it to forward.
func TestAnAdvertiserIsToldWhatItCarries(t *testing.T) {
	f := newFixture(t)
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, router.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	advertised := snapshot.GetAdvertised()
	if advertised == nil {
		t.Fatal("the advertiser was told nothing about what it carries")
	}
	if len(advertised.GetGroups()) != 1 {
		t.Fatalf("%d carried groups, want 1", len(advertised.GetGroups()))
	}
	got := advertised.GetGroups()[0]
	if len(got.GetPrefixes()) != 1 || got.GetPrefixes()[0] != "192.168.10.0/24" {
		t.Errorf("prefixes = %v", got.GetPrefixes())
	}
	// And it is still not assigned its own group, which would be the loop.
	if len(snapshot.GetRouteGroups()) != 0 {
		t.Errorf("the advertiser was also assigned its own group: %+v", snapshot.GetRouteGroups())
	}
}

// A device that carries nothing is told so, rather than told nothing. An empty list inside
// a present message says "you carry nothing now", which a device that used to carry
// something has to hear — proto3 cannot say that with a repeated field.
func TestADeviceThatCarriesNothingIsToldSo(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, laptop.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.GetAdvertised() == nil {
		t.Fatal("a device in a network with route groups was told nothing about advertising")
	}
	if len(snapshot.GetAdvertised().GetGroups()) != 0 {
		t.Errorf("a non-advertiser was told to carry %+v", snapshot.GetAdvertised().GetGroups())
	}
}

// A network with no route groups has never asked anyone to forward, which is not the same
// as having asked and stopped.
func TestANetworkWithNoGroupsSaysNothingAboutAdvertising(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, laptop.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.GetAdvertised() != nil {
		t.Errorf("a network with no route groups sent %+v", snapshot.GetAdvertised())
	}
}

// Stopping has to reach the advertiser too. Leaving it forwarding while nobody is steered
// at it is a path that works by accident.
func TestWithdrawingStopsTheAdvertiserForwarding(t *testing.T) {
	f := newFixture(t)
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	builder := NewStateBuilder(f.store)
	before, err := builder.Snapshot(f.ctx, router.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.GetAdvertised().GetGroups()) != 1 {
		t.Fatalf("expected it to be carrying one group to begin with")
	}

	if err := f.store.Withdraw(f.ctx, f.netID, "branch-lan", router.membershipID); err != nil {
		t.Fatal(err)
	}

	after, err := builder.For(f.ctx, router.membershipID, before.GetToVersion())
	if err != nil {
		t.Fatal(err)
	}
	if after.GetAdvertised() == nil {
		t.Fatal("withdrawing did not reach the advertiser")
	}
	if len(after.GetAdvertised().GetGroups()) != 0 {
		t.Errorf("it is still being told to carry %+v", after.GetAdvertised().GetGroups())
	}
}

// Disabled means stop. Draining does not: it keeps the devices already using this
// advertiser and refuses new ones, so an advertiser that stopped forwarding while draining
// would drop every session draining exists to let finish.
func TestDisabledStopsForwardingAndDrainingDoesNot(t *testing.T) {
	for _, tc := range []struct {
		state string
		want  int
	}{
		{"draining", 1},
		{"disabled", 0},
	} {
		t.Run(tc.state, func(t *testing.T) {
			f := newFixture(t)
			router := f.enrolDevice("branch-router")
			f.subnetGroup("branch-lan", "192.168.10.0/24")
			if err := f.store.Advertise(f.ctx, store.AdvertiseRequest{
				NetworkID: f.netID, GroupSlug: "branch-lan",
				MembershipID: router.membershipID, AdminState: tc.state,
			}); err != nil {
				t.Fatal(err)
			}

			snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, router.membershipID)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(snapshot.GetAdvertised().GetGroups()); got != tc.want {
				t.Errorf("admin state %q carries %d groups, want %d", tc.state, got, tc.want)
			}
		})
	}
}

// An egress advertiser forwards both default routes, so being somebody's way out does not
// quietly mean IPv4 only.
func TestAnEgressAdvertiserCarriesBothDefaultRoutes(t *testing.T) {
	f := newFixture(t)
	exit := f.enrolDevice("exit")
	if _, err := f.store.CreateRouteGroup(f.ctx, store.CreateRouteGroupRequest{
		NetworkID: f.netID, Slug: "exit", Kind: store.KindEgress,
	}); err != nil {
		t.Fatal(err)
	}
	f.advertise("exit", exit, 1)

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, exit.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	groups := snapshot.GetAdvertised().GetGroups()
	if len(groups) != 1 {
		t.Fatalf("%d carried groups, want 1", len(groups))
	}
	if p := groups[0].GetPrefixes(); len(p) != 2 || p[0] != "0.0.0.0/0" || p[1] != "::/0" {
		t.Errorf("prefixes = %v, want both default routes", p)
	}
}
