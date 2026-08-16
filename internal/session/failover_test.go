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

// The targets an administrator named have to arrive, or the agent has nothing to dial and
// falls back to the handshake — which is the whole thing this was supposed to replace.
func TestProbeTargetsReachTheAgent(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	f.setFailover("branch-lan", store.FailoverPolicy{
		Enabled:      yes(),
		ProbeTargets: []string{"192.168.10.1:22", "192.168.10.2:443"},
		ProbeQuorum:  2, ProbeIntervalMS: 600_000,
	})

	policy := f.assignments(laptop)[0].GetLocalFailover()
	if len(policy.GetProbeTargets()) != 2 {
		t.Fatalf("probe_targets = %v", policy.GetProbeTargets())
	}
	if policy.GetProbeTargets()[0] != "192.168.10.1:22" {
		t.Errorf("probe_targets = %v", policy.GetProbeTargets())
	}
	if policy.GetProbeQuorum() != 2 {
		t.Errorf("probe_quorum = %d, want 2", policy.GetProbeQuorum())
	}
	if policy.GetProbeIntervalMs() != 600_000 {
		t.Errorf("probe_interval_ms = %d, want 600000", policy.GetProbeIntervalMs())
	}
}

// A group nobody has given targets sends none, which the agent reads as "fall back to the
// handshake". There is deliberately no default: only an administrator knows what a working
// path looks like for their network, and picking public addresses on their behalf would have
// every device they own dialling a third party nobody asked it to.
func TestAGroupWithNoTargetsSendsNone(t *testing.T) {
	f := newFixture(t)
	laptop := f.enrolDevice("laptop")
	router := f.enrolDevice("branch-router")
	f.subnetGroup("branch-lan", "192.168.10.0/24")
	f.advertise("branch-lan", router, 1)

	policy := f.assignments(laptop)[0].GetLocalFailover()
	if len(policy.GetProbeTargets()) != 0 {
		t.Errorf("a group nobody configured invented targets: %v", policy.GetProbeTargets())
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

// The DNS suffix a device is told to use, which is what makes any of its names resolvable.
//
// DnsConfig has been on the wire since the beginning and nothing ever set it — the fourth
// instance of that pattern in this repository. The agent read exactly one field from it,
// prevent_leaks, and every other one was dead.
func TestTheDNSSuffixReachesTheAgent(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	got := f.stateFor(alice.membershipID, 0).GetDns()
	if got == nil {
		t.Fatal("no DNS configuration at all, so nothing this device holds is nameable")
	}
	if len(got.GetSearchDomains()) != 1 || got.GetSearchDomains()[0] != "hq.internal" {
		t.Errorf("search_domains = %v, want the network's slug under .internal", got.GetSearchDomains())
	}
}

// Split DNS, stated rather than implied. A resolver that captured every query would break
// split-horizon corporate DNS on the first laptop that joined.
func TestOnlyTheMeshSuffixIsRoutedToTheResolver(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	routes := f.stateFor(alice.membershipID, 0).GetDns().GetRoutes()
	if len(routes) != 1 || routes[0].GetDomain() != "hq.internal" {
		t.Errorf("routes = %v, want just the mesh suffix", routes)
	}
}

// Two networks, two suffixes — which is what makes a bare name ambiguous on a device in
// both, and what ADR-0021's refusal rule is about.
func TestEachNetworkHasItsOwnSuffix(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	other := f.otherNetwork("globex")
	stranger := f.enrolDeviceIn(other, "stranger")

	if got := f.stateFor(alice.membershipID, 0).GetDns().GetSearchDomains(); got[0] != "hq.internal" {
		t.Errorf("hq got %v", got)
	}
	if got := f.stateFor(stranger.membershipID, 0).GetDns().GetSearchDomains(); got[0] != "globex.internal" {
		t.Errorf("globex got %v", got)
	}
}

// It rides on every delta, not only snapshots, for the reason the tunnel configuration
// does: an agent that missed the snapshot carrying it would have peers it cannot name.
func TestTheSuffixRidesOnEveryDelta(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	before := f.headVersion()
	f.enrolDevice("bob")

	got := f.stateFor(alice.membershipID, before)
	if isSnapshot(got) {
		t.Fatal("wanted a delta")
	}
	if len(got.GetDns().GetSearchDomains()) == 0 {
		t.Error("a delta carried no DNS configuration")
	}
}
