package session

import (
	"testing"

	"github.com/google/uuid"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// otherNetwork stands up a second network in the same organization, with its own pools so
// devices enrolled into it get addresses.
func (f *fixture) otherNetwork(slug string) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.store.Pool().QueryRow(f.ctx,
		`INSERT INTO networks (organization_id,slug,name) VALUES ($1,$2,$2) RETURNING id`,
		f.orgID, slug).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.store.Pool().Exec(f.ctx,
		`INSERT INTO address_pools (network_id,prefix,family,purpose)
		 VALUES ($1,'100.91.0.0/24'::cidr,4,'device'), ($1,'fd7d::/120'::cidr,6,'device')`,
		id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// setFailClosed records an administrator's answer for the fixture's network.
func (f *fixture) setFailClosed(enforced bool) {
	f.t.Helper()
	if _, err := f.store.SetEgressFailClosed(f.ctx, f.netID, enforced); err != nil {
		f.t.Fatalf("SetEgressFailClosed(%v): %v", enforced, err)
	}
}

// A network nobody has said anything about sends no opinion, and the agent reads that as
// closed. Sending ENFORCED instead would report a decision an administrator never made.
func TestANetworkWithNoOpinionSendsNone(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	got := f.stateFor(alice.membershipID, 0).GetTunnel().GetFailClosedPolicy()
	if got != meshpv1.TunnelConfig_FAIL_CLOSED_UNSPECIFIED {
		t.Errorf("fail_closed_policy = %v, want UNSPECIFIED for a network nobody has configured", got)
	}
}

// And the opt-out is stated, because unset would be read as closed and the device would go
// on refusing egress its administrator has said it need not refuse.
func TestOptingOutReachesTheAgent(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.setFailClosed(false)

	got := f.stateFor(alice.membershipID, 0).GetTunnel().GetFailClosedPolicy()
	if got != meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED {
		t.Errorf("fail_closed_policy = %v, want DISABLED after an administrator opted out", got)
	}
}

// Turning it back on returns the network to saying nothing, which is the same thing the
// agent enforces. The value that matters is what the device does, and it must go back to
// refusing egress outside the tunnel.
func TestTurningItBackOnStopsSayingDisabled(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.setFailClosed(false)
	f.setFailClosed(true)

	got := f.stateFor(alice.membershipID, 0).GetTunnel().GetFailClosedPolicy()
	if got == meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED {
		t.Error("the network still tells devices to fail open after being told to enforce")
	}
}

// The hazard this whole design is arranged around.
//
// TunnelConfig rides on every delta, while route group assignments are only recomputed when
// routes changed. A fail-closed answer derived from the assignments would be right on the
// deltas that mention routes and wrong on the ones that do not — and wrong here means an
// unrelated device joining the network tells a machine that is still carrying a default
// route to stop refusing egress outside it.
//
// So: opt out, then move the version with something that has nothing to do with routes, and
// require the delta to still carry the answer.
func TestAnUnrelatedPeerChangeCarriesTheSameAnswer(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.setFailClosed(false)
	before := f.headVersion()

	// A peer change and nothing else.
	f.enrolDevice("bob")

	got := f.stateFor(alice.membershipID, before)
	if isSnapshot(got) {
		t.Fatal("wanted a delta; a snapshot would not exercise the path this is about")
	}
	if len(got.GetRouteGroups()) != 0 {
		t.Fatal("this delta recomputed route groups, so it is not the path this is about")
	}
	if policy := got.GetTunnel().GetFailClosedPolicy(); policy != meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED {
		t.Errorf("fail_closed_policy = %v on a delta that only added a peer, want DISABLED; "+
			"a device carrying a default route would have been told to stop failing open", policy)
	}
}

// The change has to reach agents by itself, not wait for something else to move the version.
//
// A version bumped with nothing logged produces a delta carrying a number and no contents:
// the builder short-circuits on "nothing in this window changed", every agent acknowledges
// the new version, and every one of them goes on enforcing the old answer while the
// convergence metric calls them current.
func TestOptingOutIsADeltaOnItsOwn(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	before := f.headVersion()

	f.setFailClosed(false)

	if after := f.headVersion(); after == before {
		t.Fatal("opting out did not move the state version, so no agent will ever be told")
	}
	got := f.stateFor(alice.membershipID, before)
	if got.GetTunnel() == nil {
		t.Fatal("the delta announcing the change carries no tunnel configuration")
	}
	if policy := got.GetTunnel().GetFailClosedPolicy(); policy != meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED {
		t.Errorf("fail_closed_policy = %v, want DISABLED", policy)
	}
}

// Writing the value a network already holds tells nobody. Every agent would otherwise be
// handed a delta for a reconfiguration that did not happen, which in a log is
// indistinguishable from one that did.
func TestWritingTheSameAnswerChangesNothing(t *testing.T) {
	f := newFixture(t)
	f.enrolDevice("alice")

	f.setFailClosed(false)
	before := f.headVersion()

	changed, err := f.store.SetEgressFailClosed(f.ctx, f.netID, false)
	if err != nil {
		f.t.Fatal(err)
	}
	if changed {
		t.Error("writing the same answer reported a change")
	}
	if after := f.headVersion(); after != before {
		t.Errorf("state version moved from %d to %d for a write that changed nothing", before, after)
	}
}

// A device reconnecting is sent a snapshot, which must carry the answer as well. An agent
// that reconnected after an opt-out and got a snapshot with no opinion in it would go back
// to enforcing, and the administrator's decision would last until the next restart.
func TestASnapshotCarriesTheAnswer(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.setFailClosed(false)

	snapshot, err := NewStateBuilder(f.store).Snapshot(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	if policy := snapshot.GetTunnel().GetFailClosedPolicy(); policy != meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED {
		t.Errorf("fail_closed_policy = %v in a snapshot, want DISABLED", policy)
	}
}

// Two networks, two answers. A control plane serving several tenants must not let one
// administrator's opt-out reach anybody else's devices.
func TestTheAnswerIsPerNetwork(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.setFailClosed(false)

	other := f.otherNetwork("second")
	stranger := f.enrolDeviceIn(other, "stranger")

	if policy := f.stateFor(alice.membershipID, 0).GetTunnel().GetFailClosedPolicy(); policy != meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED {
		t.Errorf("the network that opted out sends %v", policy)
	}
	if policy := f.stateFor(stranger.membershipID, 0).GetTunnel().GetFailClosedPolicy(); policy == meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED {
		t.Error("one network's opt-out told another network's devices to fail open")
	}
}
