package routeprobe

import (
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func assignment(ids ...string) *meshpv1.RouteGroupAssignment {
	a := &meshpv1.RouteGroupAssignment{RouteGroupId: "g", Name: "branch"}
	for i, id := range ids {
		a.Candidates = append(a.Candidates, &meshpv1.RouteCandidate{
			AdvertiserId: id, Priority: uint32(i + 1),
		})
	}
	a.LocalFailover = &meshpv1.LocalFailoverPolicy{Enabled: true}
	return a
}

func fail(t *testing.T, c *Chooser, a *meshpv1.RouteGroupAssignment, n int) Decision {
	t.Helper()
	var last Decision
	for range n {
		last = c.Observe(a, Result{Reachable: false})
	}
	return last
}

func succeed(t *testing.T, c *Chooser, a *meshpv1.RouteGroupAssignment, n int) Decision {
	t.Helper()
	var last Decision
	for range n {
		last = c.Observe(a, Result{Reachable: true})
	}
	return last
}

// An agent that has not probed knows nothing the server does not, so it starts where the
// server put it.
func TestItStartsAtTheServersFirstPreference(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")

	if got := c.Current(a); got.GetAdvertiserId() != "primary" {
		t.Fatalf("started at %q, want primary", got.GetAdvertiserId())
	}
}

// The point of the whole package: an advertiser that stops answering is left behind.
func TestItFallsBackAfterEnoughFailures(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)
	a := assignment("primary", "backup")
	c.Current(a)

	// Below the threshold, nothing moves. One failed probe is a packet loss, not an outage.
	if d := fail(t, c, a, DefaultFailThreshold-1); d.Switched != "" {
		t.Fatalf("moved after %d failures: %+v", DefaultFailThreshold-1, d)
	}
	if got := c.Current(a); got.GetAdvertiserId() != "primary" {
		t.Fatalf("moved early to %q", got.GetAdvertiserId())
	}

	d := c.Observe(a, Result{Reachable: false})
	if d.Switched != "primary" || d.Current != "backup" {
		t.Fatalf("decision = %+v, want a move from primary to backup", d)
	}
	if !d.Report {
		t.Error("a switch was not reported; the control plane would never learn of it")
	}
	if d.Reason == "" {
		t.Error("no reason was given for the move")
	}
	if got := c.Current(a); got.GetAdvertiserId() != "backup" {
		t.Errorf("Current is %q after the move", got.GetAdvertiserId())
	}
}

// Falling back is cheap and coming back is not. A hold on the escape would keep a device
// sitting on something that has already failed the threshold.
func TestThereIsNoHoldOnTheWayOut(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)
	a := assignment("primary", "backup", "third")
	a.LocalFailover.MinHoldSeconds = 3600
	c.Current(a)

	if d := fail(t, c, a, DefaultFailThreshold); d.Current != "backup" {
		t.Fatalf("did not leave a failing advertiser under a long hold: %+v", d)
	}
	// And on again, immediately, without waiting out the hold.
	if d := fail(t, c, a, DefaultFailThreshold); d.Current != "third" {
		t.Fatalf("did not move on from the second failing advertiser: %+v", d)
	}
}

// Returning to a flapping advertiser costs every connection each time. So recovery needs
// more evidence than failure, and it waits.
func TestComingBackNeedsMoreEvidenceAndTime(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)
	a := assignment("primary", "backup")
	a.LocalFailover.MinHoldSeconds = 60
	c.Current(a)
	fail(t, c, a, DefaultFailThreshold)

	// Enough successes, but too soon.
	if d := succeed(t, c, a, DefaultRecoverThreshold); d.Switched != "" {
		t.Fatalf("returned before the hold elapsed: %+v", d)
	}
	if got := c.Current(a); got.GetAdvertiserId() != "backup" {
		t.Fatalf("Current is %q, want backup", got.GetAdvertiserId())
	}

	clk.Advance(2 * time.Minute)
	d := succeed(t, c, a, 1)
	if d.Switched != "backup" || d.Current != "primary" {
		t.Fatalf("did not return once the hold elapsed: %+v", d)
	}
	if !d.Report {
		t.Error("the return was not reported")
	}
}

// Too few successes must not be enough, however long has passed.
func TestTimeAloneDoesNotBringItBack(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)
	a := assignment("primary", "backup")
	c.Current(a)
	fail(t, c, a, DefaultFailThreshold)

	clk.Advance(time.Hour)
	if d := succeed(t, c, a, DefaultRecoverThreshold-1); d.Switched != "" {
		t.Fatalf("returned on %d successes: %+v", DefaultRecoverThreshold-1, d)
	}
}

// A run of successes broken by a failure starts again, or an advertiser that works nine
// times out of ten would be treated as recovered.
func TestAFailureResetsTheRecoveryCount(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)
	a := assignment("primary", "backup")
	c.Current(a)
	fail(t, c, a, DefaultFailThreshold)
	clk.Advance(time.Hour)

	succeed(t, c, a, DefaultRecoverThreshold-1)
	c.Observe(a, Result{Reachable: false})
	if d := succeed(t, c, a, DefaultRecoverThreshold-1); d.Switched != "" {
		t.Fatalf("a broken run still counted as recovery: %+v", d)
	}
	if d := succeed(t, c, a, 1); d.Switched != "backup" {
		t.Fatalf("did not recover once the run was long enough: %+v", d)
	}
}

// The last candidate failing has nowhere to go. Wrapping to the front would move a device
// continuously while nothing improved.
func TestTheLastCandidateIsNotWrappedPast(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("only")
	c.Current(a)

	if d := fail(t, c, a, DefaultFailThreshold*3); d.Switched != "" {
		t.Fatalf("moved away from the only candidate: %+v", d)
	}
	if got := c.Current(a); got.GetAdvertiserId() != "only" {
		t.Errorf("Current is %q", got.GetAdvertiserId())
	}
}

// Pinned means never move, whatever is observed. It exists for groups whose egress address
// is allowlisted somewhere: a broken path is a better outcome than a working path from an
// address a bank will refuse.
func TestPinnedNeverMoves(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	a.Mode = meshpv1.RouteGroupAssignment_MODE_PINNED
	c.Current(a)

	if d := fail(t, c, a, DefaultFailThreshold*3); d.Switched != "" {
		t.Fatalf("a pinned group moved: %+v", d)
	}
	if got := c.Current(a); got.GetAdvertiserId() != "primary" {
		t.Errorf("Current is %q, want primary", got.GetAdvertiserId())
	}
}

// The server withdrawing a candidate is an instruction, not a failure, so there is nothing
// to be hysteretic about.
func TestACandidateThatDisappearsIsAbandonedAtOnce(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)
	a := assignment("primary", "backup")
	c.Current(a)
	fail(t, c, a, DefaultFailThreshold)
	if got := c.Current(a); got.GetAdvertiserId() != "backup" {
		t.Fatalf("expected to be on backup, got %q", got.GetAdvertiserId())
	}

	// The server drops backup from the list entirely.
	narrowed := assignment("primary")
	narrowed.RouteGroupId = "g"
	if got := c.Current(narrowed); got.GetAdvertiserId() != "primary" {
		t.Fatalf("kept using a withdrawn candidate: %q", got.GetAdvertiserId())
	}
}

// The first result is reported even when nothing changed. A device that only spoke up on
// change would leave a working advertiser at "unknown" for as long as it kept working —
// which is exactly when the server most wants to hear that it does.
func TestTheFirstResultIsAlwaysReported(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)

	if d := c.Observe(a, Result{Reachable: true}); !d.Report {
		t.Fatal("the first result was not reported")
	}
	if d := c.Observe(a, Result{Reachable: true}); d.Report {
		t.Error("a routine repeat was reported; a healthy network would be noisier than a broken one")
	}
}

// Observing a group nothing has been chosen for is not a crash and not a decision.
func TestObservingAnUnknownGroupDoesNothing(t *testing.T) {
	c := New(clock.NewFake())
	if d := c.Observe(assignment("primary"), Result{Reachable: false}); d.Report || d.Switched != "" {
		t.Errorf("decision = %+v, want nothing", d)
	}
}

func TestAnAssignmentWithNoCandidatesHasNoCurrent(t *testing.T) {
	c := New(clock.NewFake())
	if got := c.Current(&meshpv1.RouteGroupAssignment{RouteGroupId: "g"}); got != nil {
		t.Errorf("Current = %+v, want nothing", got)
	}
}

// A device that carried a prefix for a while must not remember its choice forever.
func TestForgetDropsGroupsNoLongerAssigned(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	fail(t, c, a, DefaultFailThreshold)

	c.Forget(nil)
	// Back to the server's first preference, because nothing is remembered.
	if got := c.Current(a); got.GetAdvertiserId() != "primary" {
		t.Errorf("Current is %q after forgetting", got.GetAdvertiserId())
	}
}

// A policy that names its own thresholds is honoured; one that names none gets defaults
// that do not flap.
func TestPolicyThresholdsAreHonoured(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)
	a := assignment("primary", "backup")
	a.LocalFailover = &meshpv1.LocalFailoverPolicy{
		Enabled: true, FailThreshold: 1, RecoverThreshold: 1, MinHoldSeconds: 1,
	}
	c.Current(a)

	if d := c.Observe(a, Result{Reachable: false}); d.Current != "backup" {
		t.Fatalf("a fail threshold of one did not move on the first failure: %+v", d)
	}
	clk.Advance(2 * time.Second)
	if d := c.Observe(a, Result{Reachable: true}); d.Current != "primary" {
		t.Fatalf("a recover threshold of one did not return: %+v", d)
	}
}
