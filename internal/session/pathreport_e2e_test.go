package session

import (
	"context"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/sessionclient"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// fakePaths stands in for the tunnel reconciler, and remembers being asked.
type fakePaths struct {
	report *meshpv1.PathReport
	asked  chan struct{}
}

func (f *fakePaths) Paths() *meshpv1.PathReport {
	select {
	case f.asked <- struct{}{}:
	default:
	}
	return f.report
}

// A path report crosses the wire and comes back out of presence.
//
// The mechanism existed before any of this: PathReport has been in the protocol since the
// first commit, generated into Go, with nothing sending it and nothing handling it. That is
// the ADR-0018 failure, and unit tests either side of the gap would not have found it —
// both ends can be perfectly correct while nothing joins them. So this drives a real agent
// against a real control plane and asks the thing an operator would ask: does the control
// plane know what this device's tunnel looks like.
func TestAPathReportReachesPresence(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")

	paths := &fakePaths{
		asked: make(chan struct{}, 1),
		report: &meshpv1.PathReport{Paths: []*meshpv1.PathReport_PeerPath{
			{
				PeerPublicKey:     "bob-key",
				Kind:              meshpv1.PathReport_PeerPath_KIND_RELAY,
				LastHandshakeUnix: time.Now().Add(-20 * time.Second).Unix(),
			},
			{PeerPublicKey: "carol-key", Kind: meshpv1.PathReport_PeerPath_KIND_DIRECT},
		}},
	}

	applier := newCapturingApplier()
	client := sessionclient.New(sessionclient.Options{
		ControlURL:   f.http.URL,
		Identity:     alice.identity,
		MembershipID: alice.membershipID,
		AgentVersion: "test",
		Paths:        paths,
	})
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go func() { _ = client.RunOnce(ctx, applier) }()

	// Sent as soon as state is applied rather than only on the heartbeat, so this does not
	// wait twenty-five seconds for the first tick.
	waitFor(t, "the agent to be asked for its paths", func() bool {
		select {
		case <-paths.asked:
			return true
		default:
			return false
		}
	})

	var got TunnelState
	waitFor(t, "the report to reach presence", func() bool {
		for _, c := range f.hub.NetworkPresence(f.netID) {
			if c.MembershipID == alice.membershipID && !c.Tunnel.ReportedAt.IsZero() {
				got = c.Tunnel
				return true
			}
		}
		return false
	})

	if got.Peers != 2 {
		t.Errorf("Peers = %d, want 2", got.Peers)
	}
	if got.Handshaked != 1 {
		t.Errorf("Handshaked = %d, want 1", got.Handshaked)
	}
	if got.Talking != 1 {
		t.Errorf("Talking = %d, want 1", got.Talking)
	}
	if got.Relayed != 1 {
		t.Errorf("Relayed = %d, want 1", got.Relayed)
	}
}

// A device with nothing to say says nothing, and presence can tell that apart from a device
// reporting an empty data plane.
func TestAnAgentWithNoDataPlaneSendsNoReport(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	applier := newCapturingApplier()
	client := sessionclient.New(sessionclient.Options{
		ControlURL:   f.http.URL,
		Identity:     alice.identity,
		MembershipID: alice.membershipID,
		AgentVersion: "test",
		Paths:        &fakePaths{asked: make(chan struct{}, 1)}, // returns nil
	})
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go func() { _ = client.RunOnce(ctx, applier) }()

	waitFor(t, "the session to register", func() bool { return f.hub.Count() == 1 })
	select {
	case <-applier.applied:
	case <-time.After(15 * time.Second):
		t.Fatal("no state was delivered")
	}

	for _, c := range f.hub.NetworkPresence(f.netID) {
		if c.MembershipID == alice.membershipID && !c.Tunnel.ReportedAt.IsZero() {
			t.Errorf("presence holds a tunnel state for a device that reported none: %+v", c.Tunnel)
		}
	}
}
