package session

import (
	"testing"

	"github.com/meshpnet/meshp/internal/store"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// setFailover records a policy for one of the fixture's groups.
func (f *fixture) setFailover(slug string, policy store.FailoverPolicy) {
	f.t.Helper()
	if _, err := f.store.SetRouteGroupFailover(f.ctx, f.netID, slug, policy); err != nil {
		f.t.Fatalf("SetRouteGroupFailover(%s): %v", slug, err)
	}
}

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

// The policy an administrator writes has to arrive. Every field on LocalFailoverPolicy has
// been in the proto and in the database since the beginning and none of them were ever sent,
// so every agent ran on the routeprobe package's own defaults and the column meant nothing.
func TestTheFailoverPolicyReachesTheAgent(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	f.setFailover("branch-lan", store.FailoverPolicy{
		Enabled: yes(), FailThreshold: 2, RecoverThreshold: 20, MinHoldSeconds: 300,
	})

	got := f.assignments(laptop)
	if len(got) != 1 {
		t.Fatalf("%d assignments, want 1", len(got))
	}
	policy := got[0].GetLocalFailover()
	if policy == nil {
		t.Fatal("the assignment carries no failover policy, so the agent runs on its own defaults")
	}
	if !policy.GetEnabled() {
		t.Error("enabled did not arrive")
	}
	if policy.GetFailThreshold() != 2 {
		t.Errorf("fail_threshold = %d, want 2", policy.GetFailThreshold())
	}
	if policy.GetRecoverThreshold() != 20 {
		t.Errorf("recover_threshold = %d, want 20", policy.GetRecoverThreshold())
	}
	if policy.GetMinHoldSeconds() != 300 {
		t.Errorf("min_hold_seconds = %d, want 300", policy.GetMinHoldSeconds())
	}
}

// A group nobody has configured still sends a policy, and it says the device may move.
//
// Proto3 cannot tell an absent bool from false, so an assignment that left `enabled` out
// would reach the agent as "you may not move yourself" — the opposite of the column's
// default, and a fleet that sits on dead advertisers waiting for a control plane that may
// be the thing that failed.
func TestAGroupNobodyConfiguredStillSaysTheDeviceMayMove(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	policy := f.assignments(laptop)[0].GetLocalFailover()
	if policy == nil {
		t.Fatal("no policy at all")
	}
	if !policy.GetEnabled() {
		t.Error("a group nobody configured tells devices they may not move themselves")
	}
	// And nothing else is claimed. Zero means the agent's default, which keeps one set of
	// numbers rather than two that drift apart.
	if policy.GetFailThreshold() != 0 || policy.GetRecoverThreshold() != 0 || policy.GetMinHoldSeconds() != 0 {
		t.Errorf("an unconfigured group states thresholds: %+v", policy)
	}
}

// The opt-out arrives as an opt-out.
func TestOptingOutOfLocalFailoverReachesTheAgent(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	f.setFailover("branch-lan", store.FailoverPolicy{Enabled: no()})

	if f.assignments(laptop)[0].GetLocalFailover().GetEnabled() {
		t.Error("a group that switched local failover off still tells devices they may move")
	}
}

// Probe targets are deliberately not sent yet: nothing in the agent reads them, so an
// administrator could write them, see them stored, and watch them do nothing (ADR-0018).
// This is here so that whoever adds them has to delete a test that says why they were not
// there, rather than wondering whether it was an oversight.
func TestProbeTargetsAreNotSentYet(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	policy := f.assignments(laptop)[0].GetLocalFailover()
	if len(policy.GetProbeTargets()) != 0 || policy.GetProbeQuorum() != 0 || policy.GetProbeIntervalMs() != 0 {
		t.Errorf("probe settings are on the wire before anything reads them: %+v", policy)
	}
}

// Two groups, two policies. A network is not one failover policy: an exit pool that must not
// flap and a branch LAN that must recover quickly are different decisions.
func TestEachGroupCarriesItsOwnPolicy(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.subnetGroup("dc-lan", "10.10.0.0/16")
	f.advertise("branch-lan", router, 1)
	f.advertise("dc-lan", router, 1)

	f.setFailover("branch-lan", store.FailoverPolicy{Enabled: yes(), FailThreshold: 2})
	f.setFailover("dc-lan", store.FailoverPolicy{Enabled: no()})

	byName := map[string]*meshpv1.LocalFailoverPolicy{}
	for _, a := range f.assignments(laptop) {
		byName[a.GetName()] = a.GetLocalFailover()
	}
	if got := byName["branch-lan"]; got.GetFailThreshold() != 2 || !got.GetEnabled() {
		t.Errorf("branch-lan = %+v", got)
	}
	if got := byName["dc-lan"]; got.GetEnabled() {
		t.Error("one group's policy leaked into another's")
	}
}
