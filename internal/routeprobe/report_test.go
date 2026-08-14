package routeprobe

import (
	"sync"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// named is an assignment for a particular group, so a test can hold two at once.
func named(groupID string, ids ...string) *meshpv1.RouteGroupAssignment {
	a := assignment(ids...)
	a.RouteGroupId = groupID
	return a
}

func only(t *testing.T, reports []*meshpv1.ReachabilityReport) *meshpv1.ReachabilityReport {
	t.Helper()
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want exactly one", len(reports))
	}
	return reports[0]
}

// The report that matters most: a device moved itself, and the control plane has to learn
// both ends of the move and why.
func TestASwitchIsReportedWithBothEndsAndAReason(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	fail(t, c, a, DefaultFailThreshold)

	report := only(t, c.Pending())
	if report.GetRouteGroupId() != "g" {
		t.Errorf("route group is %q", report.GetRouteGroupId())
	}
	if report.GetAdvertiserId() != "backup" {
		t.Errorf("reported advertiser is %q, want the one now in use", report.GetAdvertiserId())
	}
	if report.GetSwitchedFromAdvertiserId() != "primary" {
		t.Errorf("switched-from is %q, want primary", report.GetSwitchedFromAdvertiserId())
	}
	if report.GetSwitchReason() == "" {
		t.Error("no reason was carried; an operator reading an audit log learns nothing")
	}
	if report.GetReachable() {
		t.Error("reported as reachable after failing its way off the advertiser")
	}
	// The count that caused the move, not the zero it was reset to.
	if report.GetConsecutiveFailures() != uint32(DefaultFailThreshold) {
		t.Errorf("consecutive failures = %d, want %d",
			report.GetConsecutiveFailures(), DefaultFailThreshold)
	}
}

// A working advertiser has to be reported too, or an advertiser that is fine stays at
// "unknown" for exactly as long as it keeps being fine.
func TestAFirstHealthyVerdictIsQueued(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	c.Observe(a, Result{Reachable: true})

	report := only(t, c.Pending())
	if !report.GetReachable() || report.GetAdvertiserId() != "primary" {
		t.Errorf("report = %+v, want primary reachable", report)
	}
	if report.GetSwitchedFromAdvertiserId() != "" {
		t.Errorf("a switch was reported where nothing moved: %q", report.GetSwitchedFromAdvertiserId())
	}
}

// Nothing routine is sent. The server folds each report as one observation of an advertiser,
// so a device that spoke on every pass would supply evidence in proportion to its uptime.
func TestRoutineRepeatsAreNotQueued(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	succeed(t, c, a, 5)

	if got := c.Pending(); len(got) != 1 {
		t.Fatalf("got %d reports from five identical results, want one", len(got))
	}
	succeed(t, c, a, 5)
	if got := c.Pending(); len(got) != 0 {
		t.Errorf("got %d reports with nothing new to say", len(got))
	}
}

// Draining hands them over. A second drain finding the same reports would send each one
// twice, and the server counts what it receives.
func TestDrainingEmptiesTheQueue(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	c.Observe(a, Result{Reachable: true})

	if len(c.Pending()) != 1 {
		t.Fatal("nothing was queued")
	}
	if got := c.Pending(); got != nil {
		t.Errorf("draining twice produced %d reports the second time", len(got))
	}
}

// A newer verdict replaces an unsent older one rather than queueing behind it. A backlog
// draining after a reconnection is a device supplying ten observations for one opinion.
func TestANewerVerdictSupersedesAnUnsentOne(t *testing.T) {
	clk := clock.NewFake()
	c := New(clk)
	a := assignment("primary", "backup")
	a.LocalFailover.MinHoldSeconds = 1
	c.Current(a)

	c.Observe(a, Result{Reachable: true})
	fail(t, c, a, DefaultFailThreshold)

	report := only(t, c.Pending())
	if report.GetAdvertiserId() != "backup" {
		t.Errorf("kept the stale verdict: %+v", report)
	}
}

// The one thing a supersede must not lose. The switch is the line an operator goes looking
// for later, and the verdict that replaces it is about the same advertiser — so saying "on
// backup, having moved from primary" stays true.
func TestAnUnsentSwitchSurvivesBeingSuperseded(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	fail(t, c, a, DefaultFailThreshold)

	// Now on backup, which answers. Reported because the move reset the counters.
	c.Observe(a, Result{Reachable: true})

	report := only(t, c.Pending())
	if !report.GetReachable() || report.GetAdvertiserId() != "backup" {
		t.Fatalf("report = %+v, want the newer verdict about backup", report)
	}
	if report.GetSwitchedFromAdvertiserId() != "primary" {
		t.Errorf("the move was lost: switched-from is %q", report.GetSwitchedFromAdvertiserId())
	}
	if report.GetSwitchReason() == "" {
		t.Error("the reason was lost with it")
	}
}

// Carrying it forward onto a different advertiser would invent a move that never happened.
func TestASwitchIsNotCarriedOntoADifferentAdvertiser(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	fail(t, c, a, DefaultFailThreshold)

	// The server withdraws both and offers a third, which this device is moved onto with no
	// failure involved.
	replaced := named("g", "third")
	if got := c.Current(replaced); got.GetAdvertiserId() != "third" {
		t.Fatalf("expected to be moved to third, got %q", got.GetAdvertiserId())
	}
	c.Observe(replaced, Result{Reachable: true})

	report := only(t, c.Pending())
	if report.GetAdvertiserId() != "third" {
		t.Fatalf("report = %+v, want one about third", report)
	}
	if report.GetSwitchedFromAdvertiserId() != "" {
		t.Errorf("invented a move to third from %q", report.GetSwitchedFromAdvertiserId())
	}
}

// What could not be sent is kept. These are produced when something is already wrong, which
// is when the control plane most needs them.
func TestRequeuedReportsComeBack(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	c.Observe(a, Result{Reachable: true})

	undelivered := c.Pending()
	c.Requeue(undelivered)

	if got := c.Pending(); len(got) != 1 || got[0].GetAdvertiserId() != "primary" {
		t.Errorf("got %+v after requeueing, want the report back", got)
	}
}

// A stale report handed back must not overwrite what has happened since, or a stuck writer
// ends up telling the control plane that a gateway which has since failed is fine.
func TestARequeuedReportDoesNotBeatANewerOne(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	c.Observe(a, Result{Reachable: true})
	stale := c.Pending()

	fail(t, c, a, DefaultFailThreshold)
	c.Requeue(stale)

	report := only(t, c.Pending())
	if report.GetAdvertiserId() != "backup" || report.GetReachable() {
		t.Errorf("report = %+v, want the newer verdict to have won", report)
	}
}

// A verdict about a group this device has been taken out of would be folded into that
// advertiser's health on behalf of a device no longer behind it.
func TestForgettingAGroupDropsItsUnsentReport(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	c.Observe(a, Result{Reachable: true})

	c.Forget(nil)
	if got := c.Pending(); len(got) != 0 {
		t.Errorf("got %d reports about a group this device has left", len(got))
	}
}

// The same, for a report handed back after its group was forgotten. It has no group state to
// be found by, so a sweep that only walked the groups would leave it queued for the life of
// the process.
func TestARequeuedReportForAForgottenGroupIsSweptToo(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)
	c.Observe(a, Result{Reachable: true})
	undelivered := c.Pending()

	c.Forget(nil)
	c.Requeue(undelivered)
	c.Forget(nil)

	if got := c.Pending(); len(got) != 0 {
		t.Errorf("got %d reports about a forgotten group", len(got))
	}
}

// Repeated because map iteration is randomised rather than arbitrary: one drain coming out
// sorted proves nothing, and a single round of this passed against an unsorted
// implementation.
func TestReportsComeOutInAStableOrder(t *testing.T) {
	want := []string{"g1", "g2", "g3", "g4", "g5"}

	for range 20 {
		c := New(clock.NewFake())
		for _, id := range []string{"g3", "g5", "g1", "g4", "g2"} {
			a := named(id, "primary")
			c.Current(a)
			c.Observe(a, Result{Reachable: true})
		}

		got := c.Pending()
		if len(got) != len(want) {
			t.Fatalf("got %d reports, want one per group", len(got))
		}
		for i, id := range want {
			if got[i].GetRouteGroupId() != id {
				t.Fatalf("report %d is for %q, want %q", i, got[i].GetRouteGroupId(), id)
			}
		}
	}
}

// A direct test of what recordLocked promises, rather than of a state the Chooser can reach.
//
// It cannot reach this one: a report that records a switch always names the advertiser just
// moved to, which is never the one an unsent report is about. The clause is still worth
// having and worth covering — the correctness it protects is "newer switch wins", and that
// must not quietly depend on an argument about advertiser identity holding forever.
func TestANewerSwitchIsNotOverwrittenByAnOlderOne(t *testing.T) {
	c := New(clock.NewFake())
	c.pending["g"] = &meshpv1.ReachabilityReport{
		RouteGroupId:             "g",
		AdvertiserId:             "backup",
		SwitchedFromAdvertiserId: "primary",
		SwitchReason:             "the older move",
	}

	c.recordLocked("g", Decision{
		Current:  "backup",
		Switched: "third",
		Reason:   "the newer move",
	}, Result{Reachable: true})

	report := only(t, c.Pending())
	if report.GetSwitchedFromAdvertiserId() != "third" {
		t.Errorf("switched-from is %q, want the newer move's", report.GetSwitchedFromAdvertiserId())
	}
	if report.GetSwitchReason() != "the newer move" {
		t.Errorf("reason is %q", report.GetSwitchReason())
	}
}

func TestRoundTripTimesAreClampedToWhatTheFieldHolds(t *testing.T) {
	for _, tc := range []struct {
		name string
		rtt  time.Duration
		want uint32
	}{
		{"unmeasured", 0, 0},
		{"ordinary", 42 * time.Millisecond, 42},
		{"nonsense", -1 * time.Second, 0},
		{"absurd", 1 << 60, ^uint32(0)},
	} {
		if got := millis(Result{RTT: tc.rtt}); got != tc.want {
			t.Errorf("%s: millis(%v) = %d, want %d", tc.name, tc.rtt, got, tc.want)
		}
	}
}

// The reconciler folds results in on its own timer while the session drains them out, and the
// reconciler is entered both from that timer and from an arriving state delta. Meaningless
// without -race, which is why the suite runs with it.
func TestObservingAndDrainingAreSafeTogether(t *testing.T) {
	c := New(clock.NewFake())
	a := assignment("primary", "backup")
	c.Current(a)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range 200 {
				c.Observe(a, Result{Reachable: i%2 == 0})
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				c.Requeue(c.Pending())
			}
		}()
	}
	wg.Wait()
}
