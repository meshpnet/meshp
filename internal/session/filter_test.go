package session

import (
	"testing"

	"github.com/meshpnet/meshp/internal/acl"
	"github.com/meshpnet/meshp/internal/store"
)

// publish puts a policy in force for the fixture's network.
func (f *fixture) publish(rules ...acl.Rule) {
	f.t.Helper()
	if _, err := f.store.PublishPolicy(f.ctx, store.PublishPolicyRequest{
		NetworkID: f.netID,
		Document:  acl.Document{Version: acl.Version, Rules: rules},
		Actor:     store.BootstrapActor(),
	}); err != nil {
		f.t.Fatalf("publishing a policy: %v", err)
	}
}

// tagMembership sets a membership's tags, which is what selectors match on.
func (f *fixture) tagMembership(d device, tags ...string) {
	f.t.Helper()
	if _, err := f.store.Pool().Exec(f.ctx,
		`UPDATE device_network_memberships SET tags = $2 WHERE id = $1`, d.membershipID, tags); err != nil {
		f.t.Fatal(err)
	}
}

// The property everything else rests on: a network nobody has written a policy for keeps
// working exactly as it did. An absent policy compiled into an empty filter would reach
// every agent as "deny everything" and take down every deployment that upgraded.
func TestANetworkWithNoPolicySendsNoFilter(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.GetFilter() != nil {
		t.Fatalf("a network with no policy was sent a filter: %+v", snapshot.GetFilter())
	}
	if len(snapshot.GetUpsertPeers()) == 0 {
		t.Error("the peers went missing too")
	}
}

// A snapshot describes the whole world, so it carries the filter whether or not the policy
// just changed. An agent reconnecting would otherwise have nothing to enforce until the
// next policy edit.
func TestASnapshotAlwaysCarriesTheFilter(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")
	f.tagMembership(alice, "server")
	f.tagMembership(bob, "laptop")
	f.publish(acl.Rule{
		Src: []acl.Selector{"tag:laptop"}, Dst: []acl.Selector{"tag:server"},
		Protocol: "tcp", Ports: []string{"22"},
	})

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	filter := snapshot.GetFilter()
	if filter == nil {
		t.Fatal("a snapshot carried no filter while a policy was in force")
	}
	if !filter.GetDefaultDeny() {
		t.Error("the filter does not default to deny")
	}
	if len(filter.GetInbound()) != 1 {
		t.Fatalf("%d inbound rules, want 1: %+v", len(filter.GetInbound()), filter.GetInbound())
	}
	if got := filter.GetInbound()[0].GetPorts(); len(got) != 1 || got[0] != "22" {
		t.Errorf("ports = %v", got)
	}
}

// A policy edit reaches agents as a delta carrying a fresh filter. Without the state change
// the policy would sit in the database until something unrelated bumped the version.
func TestAPolicyChangeArrivesAsADelta(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")
	f.tagMembership(alice, "server")
	f.tagMembership(bob, "laptop")

	builder := NewStateBuilder(f.store)
	before, err := builder.Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}

	f.publish(acl.Rule{Src: []acl.Selector{"tag:laptop"}, Dst: []acl.Selector{"tag:server"}})

	delta, err := builder.For(f.ctx, alice.membershipID, before.GetToVersion())
	if err != nil {
		t.Fatal(err)
	}
	if delta.GetFromVersion() == 0 {
		t.Fatal("a policy change produced a snapshot; the delta path was not used")
	}
	if delta.GetFilter() == nil {
		t.Fatal("a policy change produced a delta with no filter")
	}
	if len(delta.GetUpsertPeers()) != 0 || len(delta.GetRemovePeerKeys()) != 0 {
		t.Errorf("a policy change touched the peer list: +%d -%d",
			len(delta.GetUpsertPeers()), len(delta.GetRemovePeerKeys()))
	}
}

// StateDelta.filter is documented as present only when it changed. Sending it on every
// delta would make each unrelated peer change rewrite every device's firewall.
func TestADeltaWithNoPolicyChangeCarriesNoFilter(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.tagMembership(alice, "server")
	f.publish(acl.Rule{Src: []acl.Selector{"*"}, Dst: []acl.Selector{"tag:server"}})

	builder := NewStateBuilder(f.store)
	before, err := builder.Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}

	// A peer change, not a policy change.
	f.enrolDevice("carol")

	delta, err := builder.For(f.ctx, alice.membershipID, before.GetToVersion())
	if err != nil {
		t.Fatal(err)
	}
	if delta.GetFromVersion() == 0 {
		t.Skip("the builder chose a snapshot, which always carries a filter")
	}
	if delta.GetFilter() != nil {
		t.Errorf("an unrelated peer change resent the filter: %+v", delta.GetFilter())
	}
}

// A device the policy does not mention gets a filter that permits nothing, which is the
// point of default deny — and must not be confused with the absent filter a network with
// no policy sends.
func TestAnUnmentionedDeviceGetsAClosedFilterNotAnAbsentOne(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")
	f.tagMembership(bob, "laptop")
	f.publish(acl.Rule{Src: []acl.Selector{"tag:laptop"}, Dst: []acl.Selector{"tag:laptop"}})

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	filter := snapshot.GetFilter()
	if filter == nil {
		t.Fatal("an unmentioned device was sent no filter, so it would enforce nothing")
	}
	if !filter.GetDefaultDeny() {
		t.Error("the filter does not default to deny")
	}
	if len(filter.GetInbound()) != 0 || len(filter.GetOutbound()) != 0 {
		t.Errorf("an unmentioned device got rules: %+v", filter)
	}
}

// A revoked device must not appear in anyone's filter: its address would grant access to a
// device that is no longer in the network.
func TestARevokedDeviceLeavesEveryFilter(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")
	f.tagMembership(alice, "server")
	f.tagMembership(bob, "laptop")
	f.publish(acl.Rule{Src: []acl.Selector{"tag:laptop"}, Dst: []acl.Selector{"tag:server"}})

	builder := NewStateBuilder(f.store)
	before, err := builder.Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.GetFilter().GetInbound()) != 1 {
		t.Fatalf("bob was not in alice's filter to begin with: %+v", before.GetFilter())
	}

	if _, err := f.store.RevokeMembership(f.ctx, store.RevokeRequest{
		NetworkID: f.netID, MembershipID: bob.membershipID, Actor: store.BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	after, err := builder.Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range after.GetFilter().GetInbound() {
		if len(rule.GetSrcPrefixes()) > 0 {
			t.Errorf("a revoked device is still a permitted source: %v", rule.GetSrcPrefixes())
		}
	}
}

// The builder has two ways to produce a snapshot — the explicit one, and the shortcut For
// takes when a delta would be larger than the snapshot it replaces. Both must carry the
// filter. Attaching it to only one meant a network whose peer count dropped below its
// change count silently sent a policy-free snapshot, and nothing else noticed.
func TestBothSnapshotPathsCarryTheFilter(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.tagMembership(alice, "server")
	f.publish(acl.Rule{Src: []acl.Selector{"*"}, Dst: []acl.Selector{"tag:server"}})

	builder := NewStateBuilder(f.store)

	explicit, err := builder.Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if explicit.GetFilter() == nil {
		t.Error("Snapshot carried no filter")
	}

	// Now make For take its shortcut: more changes than peers. Alice is the only member,
	// so she has no peers at all, and any change at all outnumbers them.
	f.publish(acl.Rule{Src: []acl.Selector{"*"}, Dst: []acl.Selector{"*"}})

	shortcut, err := builder.For(f.ctx, alice.membershipID, explicit.GetToVersion())
	if err != nil {
		t.Fatal(err)
	}
	if shortcut.GetFromVersion() != 0 {
		t.Skip("For chose a delta; this test is about the snapshot shortcut")
	}
	if shortcut.GetFilter() == nil {
		t.Fatal("the snapshot For produced as a shortcut carried no filter")
	}
}
