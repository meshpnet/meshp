package sessionclient

import (
	"sync"
	"testing"
	"time"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// fakeReports stands in for the chooser: it hands out verdicts and remembers what came back.
type fakeReports struct {
	mu       sync.Mutex
	pending  []*meshpv1.ReachabilityReport
	requeued []*meshpv1.ReachabilityReport
}

func (f *fakeReports) Pending() []*meshpv1.ReachabilityReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.pending
	f.pending = nil
	return out
}

func (f *fakeReports) Requeue(reports []*meshpv1.ReachabilityReport) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requeued = append(f.requeued, reports...)
}

func (f *fakeReports) handedBack() []*meshpv1.ReachabilityReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*meshpv1.ReachabilityReport(nil), f.requeued...)
}

func aReport(group, advertiser string) *meshpv1.ReachabilityReport {
	return &meshpv1.ReachabilityReport{
		RouteGroupId:             group,
		AdvertiserId:             advertiser,
		Reachable:                false,
		ConsecutiveFailures:      3,
		SwitchedFromAdvertiserId: "primary",
		SwitchReason:             "the advertiser in use stopped answering probes",
	}
}

// awaitReachabilityReport waits for one to arrive, and returns it.
func (fc *fakeControl) awaitReachabilityReport(within time.Duration) *meshpv1.ReachabilityReport {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		fc.mu.Lock()
		for _, msg := range fc.received {
			if payload, ok := msg.Payload.(*meshpv1.ClientMessage_ReachabilityReport); ok {
				fc.mu.Unlock()
				return payload.ReachabilityReport
			}
		}
		fc.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

func (fc *fakeControl) reachabilityReports() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	n := 0
	for _, msg := range fc.received {
		if _, ok := msg.Payload.(*meshpv1.ClientMessage_ReachabilityReport); ok {
			n++
		}
	}
	return n
}

// The last link in the failover loop. A device that decided locally and never said so keeps
// the next device being sent to the same dead gateway.
func TestAVerdictReachesTheControlPlaneWhenStateIsApplied(t *testing.T) {
	fc := newFakeControl(t)
	reports := &fakeReports{pending: []*meshpv1.ReachabilityReport{aReport("group-1", "backup")}}
	_, conn := startSession(t, fc, Options{Reachability: reports}, noopApplier{})

	// Applying state is what runs a reconcile, so it is the earliest moment there is
	// anything to send.
	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{FromVersion: 0, ToVersion: 1},
	}})

	got := fc.awaitReachabilityReport(5 * time.Second)
	if got == nil {
		t.Fatal("the agent never reported what it had observed")
	}
	if got.GetRouteGroupId() != "group-1" || got.GetAdvertiserId() != "backup" {
		t.Errorf("report = %+v, want the one that was queued", got)
	}
	if got.GetSwitchedFromAdvertiserId() != "primary" || got.GetSwitchReason() == "" {
		t.Errorf("the move was not carried onto the wire: %+v", got)
	}
	if got.GetConsecutiveFailures() != 3 {
		t.Errorf("consecutive failures = %d, want 3", got.GetConsecutiveFailures())
	}
}

// A quiet network sends no state deltas, and a device that has just failed over on one is
// exactly the device worth hearing from. Without the heartbeat carrying reports, it would
// hold that news until something else happened to arrive.
func TestAVerdictIsSentOnTheHeartbeatWithNoStateAtAll(t *testing.T) {
	original := heartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	t.Cleanup(func() { heartbeatInterval = original })

	fc := newFakeControl(t)
	reports := &fakeReports{pending: []*meshpv1.ReachabilityReport{aReport("group-1", "backup")}}
	startSession(t, fc, Options{Reachability: reports}, noopApplier{})

	if got := fc.awaitReachabilityReport(5 * time.Second); got == nil {
		t.Fatal("nothing was reported on a session with no state deltas")
	}
}

// A build with no data plane observes nothing and so has nothing to say.
func TestNothingIsReportedWithoutAReporter(t *testing.T) {
	original := heartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	t.Cleanup(func() { heartbeatInterval = original })

	fc := newFakeControl(t)
	_, conn := startSession(t, fc, Options{}, noopApplier{})
	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{FromVersion: 0, ToVersion: 1},
	}})

	if got := fc.awaitReachabilityReport(300 * time.Millisecond); got != nil {
		t.Fatalf("an agent with nothing to observe reported %+v", got)
	}
}

// Every queued verdict goes, not just the first: a device in several route groups has
// something to say about each of them.
func TestEveryQueuedVerdictIsSent(t *testing.T) {
	original := heartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	t.Cleanup(func() { heartbeatInterval = original })

	fc := newFakeControl(t)
	reports := &fakeReports{pending: []*meshpv1.ReachabilityReport{
		aReport("group-1", "backup"), aReport("group-2", "third"), aReport("group-3", "fourth"),
	}}
	startSession(t, fc, Options{Reachability: reports}, noopApplier{})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fc.reachabilityReports() >= 3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("only %d of 3 verdicts were sent", fc.reachabilityReports())
}

// What will not fit is handed back rather than dropped. Reports are produced when something
// is already wrong, so losing them costs exactly when it matters — and the writer being
// behind is no reason to forget what was observed.
func TestVerdictsThatDoNotFitAreHandedBack(t *testing.T) {
	reports := &fakeReports{pending: []*meshpv1.ReachabilityReport{
		aReport("group-1", "backup"), aReport("group-2", "third"), aReport("group-3", "fourth"),
	}}
	c := New(Options{Reachability: reports})

	// One slot, three reports: the writer is as far behind as it can be.
	outbound := make(chan *meshpv1.ClientMessage, 1)
	c.sendReachabilityReports(outbound)

	if len(outbound) != 1 {
		t.Fatalf("queued %d messages into one slot", len(outbound))
	}
	handedBack := reports.handedBack()
	if len(handedBack) != 2 {
		t.Fatalf("handed back %d reports, want the 2 that did not fit", len(handedBack))
	}
	for i, want := range []string{"group-2", "group-3"} {
		if handedBack[i].GetRouteGroupId() != want {
			t.Errorf("handed back %q at %d, want %q", handedBack[i].GetRouteGroupId(), i, want)
		}
	}
}

// Nothing observed means nothing on the wire. An agent that sent an empty report every tick
// would fold into the server's health monitor as a real observation.
func TestAnEmptyQueueSendsNothing(t *testing.T) {
	reports := &fakeReports{}
	c := New(Options{Reachability: reports})

	outbound := make(chan *meshpv1.ClientMessage, 4)
	c.sendReachabilityReports(outbound)

	if len(outbound) != 0 {
		t.Errorf("sent %d messages with nothing to report", len(outbound))
	}
}
