package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/sessionclient"
)

// recorder is an Applier that remembers the states it was given.
//
// It takes the whole set rather than the delta because that is what an Applier receives:
// a target, not an instruction. What the test wants to know is what the agent ended up
// believing, which is exactly that.
type recorder struct {
	mu      sync.Mutex
	applied []*peerset.Set
	changed chan struct{}
}

func newRecorder() *recorder {
	return &recorder{changed: make(chan struct{}, 32)}
}

func (r *recorder) Apply(_ context.Context, state *peerset.Set) ([]string, error) {
	r.mu.Lock()
	r.applied = append(r.applied, state)
	r.mu.Unlock()
	select {
	case r.changed <- struct{}{}:
	default:
	}
	return nil, nil
}

// waitForPeers blocks until the agent believes it has n peers, or gives up.
func (r *recorder) waitForPeers(t *testing.T, n int, within time.Duration) *peerset.Set {
	t.Helper()
	deadline := time.After(within)
	for {
		r.mu.Lock()
		var last *peerset.Set
		if len(r.applied) > 0 {
			last = r.applied[len(r.applied)-1]
		}
		r.mu.Unlock()
		if last != nil && last.Len() == n {
			return last
		}
		select {
		case <-r.changed:
		case <-deadline:
			got := 0
			if last != nil {
				got = last.Len()
			}
			t.Fatalf("the agent has %d peers after %s, want %d", got, within, n)
			return nil
		}
	}
}

// A device joining must reach the agents already in the network promptly, without
// waiting for a heartbeat.
//
// The heartbeat carries the current version and so would eventually deliver this on its
// own (ADR-0012 requires that, and it is what makes a lost notification survivable). The
// interval is 25 seconds, so a test that allows more than a few seconds cannot tell a
// working push from a missing one — which is how the push came to be absent from every
// mutation path while its own unit tests passed.
func TestEnrolmentPushesToAgentsAlreadyInTheNetwork(t *testing.T) {
	h := newHarness(t)

	firstID, firstWG := newDevice(t)
	first, err := enrollclient.New(h.server.URL, nil).Join(h.ctx, enrollclient.JoinRequest{
		Token: h.mintToken(1, time.Hour), Identity: firstID, WireGuard: firstWG,
		Name: "first", OS: "linux", AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("the first device could not join: %v", err)
	}

	// A real agent, so this covers the shipping handshake, the shipping delta handling
	// and the wiring between them rather than a stand-in for any of it.
	rec := newRecorder()
	agentCtx, stopAgent := context.WithCancel(h.ctx)
	defer stopAgent()

	client := sessionclient.New(sessionclient.Options{
		ControlURL:   h.server.URL,
		Identity:     firstID,
		MembershipID: first.MembershipID,
		AgentVersion: "test",
	})
	done := make(chan error, 1)
	go func() { done <- client.Run(agentCtx, rec) }()

	// It starts by being told about a network it is alone in.
	rec.waitForPeers(t, 0, 10*time.Second)

	secondID, secondWG := newDevice(t)
	second, err := enrollclient.New(h.server.URL, nil).Join(h.ctx, enrollclient.JoinRequest{
		Token: h.mintToken(1, time.Hour), Identity: secondID, WireGuard: secondWG,
		Name: "second", OS: "linux", AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("the second device could not join: %v", err)
	}

	// Well inside a heartbeat interval: this can only pass if the enrolment pushed.
	state := rec.waitForPeers(t, 1, 5*time.Second)

	peers := state.Peers()
	if got := peers[0].GetPublicKey(); got != secondWG.Public.String() {
		t.Errorf("the agent was told about %q, want the second device's key %q",
			got, secondWG.Public.String())
	}
	if got := peers[0].GetDeviceName(); got != "second" {
		t.Errorf("peer name = %q, want second", got)
	}
	if state.Version() != uint64(second.StateVersion) {
		t.Errorf("the agent is at version %d, want %d", state.Version(), second.StateVersion)
	}

	// What the applier was handed the first time must still say what it said then. A
	// reconciler keeps the last state it applied so it can diff the next one against it;
	// if the client hands out its own live set, that reference changes underneath and the
	// diff is empty no matter what happened — the peer is never configured, and nothing
	// reports a problem because both sides agree.
	rec.mu.Lock()
	firstApplied := rec.applied[0]
	rec.mu.Unlock()
	if n := firstApplied.Len(); n != 0 {
		t.Errorf("the state applied before the second device joined now has %d peers: "+
			"the applier was handed the client's live set, not a copy of it", n)
	}

	stopAgent()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("the agent did not stop when its context was cancelled")
	}
}

// The push is a courtesy; the state an agent is given must be complete whether or not it
// arrived. A device that enrols while nobody is connected is still there afterwards.
func TestAnAgentConnectingLaterSeesWhatItMissed(t *testing.T) {
	h := newHarness(t)

	firstID, firstWG := newDevice(t)
	first, err := enrollclient.New(h.server.URL, nil).Join(h.ctx, enrollclient.JoinRequest{
		Token: h.mintToken(1, time.Hour), Identity: firstID, WireGuard: firstWG,
		Name: "first", OS: "linux", AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("the first device could not join: %v", err)
	}

	// Nobody is connected, so the nudge for this reaches nothing at all.
	secondID, secondWG := newDevice(t)
	if _, err := enrollclient.New(h.server.URL, nil).Join(h.ctx, enrollclient.JoinRequest{
		Token: h.mintToken(1, time.Hour), Identity: secondID, WireGuard: secondWG,
		Name: "second", OS: "linux", AgentVersion: "test",
	}); err != nil {
		t.Fatalf("the second device could not join: %v", err)
	}

	rec := newRecorder()
	agentCtx, stopAgent := context.WithCancel(h.ctx)
	defer stopAgent()
	client := sessionclient.New(sessionclient.Options{
		ControlURL:   h.server.URL,
		Identity:     firstID,
		MembershipID: first.MembershipID,
		AgentVersion: "test",
	})
	go func() { _ = client.Run(agentCtx, rec) }()

	state := rec.waitForPeers(t, 1, 10*time.Second)
	if got := state.Peers()[0].GetDeviceName(); got != "second" {
		t.Errorf("the agent was told about %q, want second", got)
	}
}
