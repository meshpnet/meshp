package session

import (
	"testing"

	"github.com/meshpnet/meshp/internal/store"
)

// Draining a relay stops agents being told about it, without a restart.
//
// The whole of #128. Before this, the relay list was parsed from MESHP_RELAYS once at
// startup and handed to every agent for the life of the process, so taking one relay out of
// service meant editing an environment variable and restarting the control plane — dropping
// every session on every relay to retire one.
func TestDrainingARelayStopsItBeingHandedOut(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")

	relays, err := ParseRelays("relay1=relay1.example:3478;relay2=relay2.example:3478")
	if err != nil {
		t.Fatal(err)
	}
	f.srv.builder = f.srv.builder.WithRelays(relays)
	f.registerRelays(t, relays)

	before, err := f.srv.builder.For(f.ctx, alice.membershipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(before.GetRelays().GetRelays()); got != 2 {
		t.Fatalf("a deployment with two relays offers %d", got)
	}

	// No restart, no configuration change.
	if _, err := f.store.SetRelayState(f.ctx, store.SetRelayStateRequest{
		Slug: "relay1", State: store.RelayDraining, Actor: store.BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	after, err := f.srv.builder.For(f.ctx, alice.membershipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	offered := after.GetRelays().GetRelays()
	if len(offered) != 1 {
		t.Fatalf("after draining one of two relays, %d are offered", len(offered))
	}
	if offered[0].GetId() != "relay2" {
		t.Errorf("the relay still offered is %q, want relay2", offered[0].GetId())
	}

	// And putting it back works, which is what makes draining a reversible operator action
	// rather than a one-way door.
	if _, err := f.store.SetRelayState(f.ctx, store.SetRelayStateRequest{
		Slug: "relay1", State: store.RelayActive, Actor: store.BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}
	restored, err := f.srv.builder.For(f.ctx, alice.membershipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(restored.GetRelays().GetRelays()); got != 2 {
		t.Errorf("after putting a relay back, %d are offered", got)
	}
}

// Draining every relay tells agents to let go, rather than saying nothing.
//
// The agent treats a nil relay list as "nothing changed" and a present one as "replace what
// you have". So an operator who drains their last relay must produce an empty list and not
// an absent one — otherwise every agent keeps using the relay it was told to stop using,
// and the drain is recorded and never delivered.
func TestDrainingEveryRelayTellsAgentsToLetGo(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")

	relays, err := ParseRelays("relay1=relay1.example:3478")
	if err != nil {
		t.Fatal(err)
	}
	f.srv.builder = f.srv.builder.WithRelays(relays)
	f.registerRelays(t, relays)

	if _, err := f.store.SetRelayState(f.ctx, store.SetRelayStateRequest{
		Slug: "relay1", State: store.RelayDraining, Actor: store.BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	state, err := f.srv.builder.For(f.ctx, alice.membershipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if state.GetRelays() == nil {
		t.Fatal("a deployment that drained its last relay said nothing, so every agent " +
			"keeps using the relay it was told to stop using")
	}
	if got := len(state.GetRelays().GetRelays()); got != 0 {
		t.Errorf("%d relays offered after draining them all", got)
	}
}

// An agent that is already up to date is still told the current relay list.
//
// Draining does not bump any network's state version — it is a decision about the
// deployment rather than about a network's contents — so an agent at head would otherwise
// receive an empty delta and never learn. This is what makes a nudge enough.
func TestAnAgentAtHeadStillLearnsTheRelayList(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")

	relays, err := ParseRelays("relay1=relay1.example:3478;relay2=relay2.example:3478")
	if err != nil {
		t.Fatal(err)
	}
	f.srv.builder = f.srv.builder.WithRelays(relays)
	f.registerRelays(t, relays)

	// What the agent has applied: everything.
	head, err := f.srv.builder.For(f.ctx, alice.membershipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	at := head.GetToVersion()

	if _, err := f.store.SetRelayState(f.ctx, store.SetRelayStateRequest{
		Slug: "relay1", State: store.RelayDraining, Actor: store.BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	// Asked again at the version it already has, which is what a nudge produces.
	delta, err := f.srv.builder.For(f.ctx, alice.membershipID, at)
	if err != nil {
		t.Fatal(err)
	}
	offered := delta.GetRelays().GetRelays()
	if len(offered) != 1 || offered[0].GetId() != "relay2" {
		t.Errorf("an agent at head was told about %d relays; the drain never reached it",
			len(offered))
	}
}

// Configuration remains the source of truth for which relays exist, and a restart must not
// undo a drain. Both halves matter: the first is why an operator can still name relays in
// one place, the second is the failure this whole change removes.
func TestARestartRefreshesEndpointsAndLeavesStateAlone(t *testing.T) {
	f := newFixture(t)

	relays, err := ParseRelays("relay1=relay1.example:3478")
	if err != nil {
		t.Fatal(err)
	}
	f.registerRelays(t, relays)

	if _, err := f.store.SetRelayState(f.ctx, store.SetRelayStateRequest{
		Slug: "relay1", State: store.RelayDraining, Actor: store.BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	// A restart: the same configuration, with an endpoint changed.
	moved, err := ParseRelays("relay1=relay1.example:443")
	if err != nil {
		t.Fatal(err)
	}
	f.registerRelays(t, moved)

	all, err := f.store.ListRelays(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("%d relays after a restart, want 1", len(all))
	}
	if all[0].State != store.RelayDraining {
		t.Errorf("state after a restart is %q; a restart undid the drain", all[0].State)
	}
	if len(all[0].Endpoints) != 1 || all[0].Endpoints[0] != "relay1.example:443" {
		t.Errorf("endpoints after a restart are %v; configuration did not win", all[0].Endpoints)
	}
}

// A relay dropped from configuration goes away, rather than lingering as a row somebody
// could put back into service pointing at nothing.
func TestARelayRemovedFromConfigurationIsForgotten(t *testing.T) {
	f := newFixture(t)

	two, err := ParseRelays("relay1=relay1.example:3478;relay2=relay2.example:3478")
	if err != nil {
		t.Fatal(err)
	}
	f.registerRelays(t, two)

	one, err := ParseRelays("relay2=relay2.example:3478")
	if err != nil {
		t.Fatal(err)
	}
	f.registerRelays(t, one)

	all, err := f.store.ListRelays(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Slug != "relay2" {
		t.Errorf("relays after removing one from configuration = %v, want just relay2", all)
	}
}
