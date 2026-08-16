package routeprobe

import (
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// A group whose policy says not to move does not move, in either direction.
//
// This branch was unreachable until the server started sending the policy at all: every
// assignment arrived with no LocalFailoverPolicy, so `enabled` was never anything. What was
// here before moved away and never came back, which parks a device on a fallback after one
// blip — a state nobody chose, arriving silently, since the group still reports itself as
// honoured.
func TestAPolicyThatSaysNotToMoveDoesNotMove(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	a.LocalFailover = &meshpv1.LocalFailoverPolicy{Enabled: false, FailThreshold: 2}
	c.Current(a)

	if d := fail(t, c, a, 20); d.Current != "primary" || d.Switched != "" {
		t.Fatalf("a device moved under a policy that says not to: %+v", d)
	}
	if got := c.Current(a).GetAdvertiserId(); got != "primary" {
		t.Errorf("the chooser now points at %q", got)
	}
}

// And it will not come back either, because coming back is a move too — and a device that
// obeyed the policy on the way out and ignored it on the way in would still be choosing for
// itself, just more slowly.
func TestAPolicyThatSaysNotToMoveDoesNotReturn(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)

	// Move it first, under a policy that allows moving.
	a := assignment("primary", "backup")
	a.LocalFailover = &meshpv1.LocalFailoverPolicy{Enabled: true, FailThreshold: 1, RecoverThreshold: 1, MinHoldSeconds: 1}
	c.Current(a)
	if d := fail(t, c, a, 1); d.Current != "backup" {
		t.Fatalf("setup: the device did not move: %+v", d)
	}

	// Now switch local failover off. It should stay on the fallback.
	a.LocalFailover = &meshpv1.LocalFailoverPolicy{Enabled: false, FailThreshold: 1, RecoverThreshold: 1, MinHoldSeconds: 1}
	clk.Advance(time.Hour)
	if d := succeed(t, c, a, 20); d.Current != "backup" || d.Switched != "" {
		t.Fatalf("a device returned under a policy that says not to move: %+v", d)
	}
}

// The counters and the reports keep running, which is the point of not simply returning
// early. The control plane cannot see a path this device cannot use, so a device told not
// to act on a dead advertiser must still be the thing that says it is dead.
func TestADeviceThatMayNotMoveStillSaysWhatItSees(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	a.LocalFailover = &meshpv1.LocalFailoverPolicy{Enabled: false, FailThreshold: 3}
	c.Current(a)

	d := fail(t, c, a, 3)
	if d.ConsecutiveFailures != 3 {
		t.Errorf("consecutive_failures = %d after three failures, want 3", d.ConsecutiveFailures)
	}
	if !d.Report {
		t.Error("the pass that would have moved was not reported, so nobody is told the prefix is unreachable")
	}
	if d.Reason == "" {
		t.Error("nothing explains why a failing advertiser is still in use")
	}

	// Once, not on every pass: a device behaving exactly as configured must not fill the log.
	if next := c.Observe(a, Result{Reachable: false}); next.Report {
		t.Error("every failing pass is reported, which buries the one that mattered")
	}
}

// An assignment with no policy at all means the device may move.
//
// The case that has to be right is a control plane too old to send one: a device that could
// not leave a dead advertiser without being told to could not leave one during the
// control-plane outage most likely to have caused the problem (ADR-0003).
func TestNoPolicyMeansTheDeviceMayMove(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	a.LocalFailover = nil
	c.Current(a)

	if d := fail(t, c, a, DefaultFailThreshold); d.Current != "backup" {
		t.Fatalf("a device with no policy would not leave a dead advertiser: %+v", d)
	}
}
