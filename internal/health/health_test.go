package health

import (
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
)

var (
	allOK   = Report{SelfReport: SignalOK, ControlProbe: SignalOK, ClientObserved: SignalOK}
	allFail = Report{SelfReport: SignalFail, ControlProbe: SignalFail, ClientObserved: SignalFail}
	silent  = Report{}
)

// testPolicy uses small thresholds and no cooldown so a test that is not about
// hysteresis does not have to spell it out.
func testPolicy() Policy {
	return Policy{FailThreshold: 3, RecoverThreshold: 3, DegradeThreshold: 2, Cooldown: -1, OfflineAfter: 90 * time.Second}
}

func observeN(m *Monitor, r Report, n int) {
	for range n {
		m.Observe(r)
	}
}

func TestVerdictFusion(t *testing.T) {
	// The point of fusing three sources is that the one measuring what users
	// experience wins. An advertiser insisting it is fine while every device
	// behind it cannot get out is the exact failure a self-check cannot see.
	tests := []struct {
		name string
		r    Report
		want verdict
	}{
		{"all ok", allOK, verdictOK},
		{"all fail", allFail, verdictFail},
		{"nothing measured", silent, verdictNone},
		{"only self reports, and it is happy", Report{SelfReport: SignalOK}, verdictOK},
		{
			"clients say fail, node says fine",
			Report{SelfReport: SignalOK, ControlProbe: SignalOK, ClientObserved: SignalFail},
			verdictFail,
		},
		{
			"probe fails, clients fine",
			Report{SelfReport: SignalOK, ControlProbe: SignalFail, ClientObserved: SignalOK},
			verdictPartial,
		},
		{
			"node says broken, clients getting through",
			Report{SelfReport: SignalFail, ClientObserved: SignalOK},
			verdictPartial,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.verdict(); got != tt.want {
				t.Errorf("verdict = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStartsUnknownAndNeedsEvidence(t *testing.T) {
	m := NewMonitor(testPolicy(), clock.NewFake())
	if got := m.State(); got != StateUnknown {
		t.Fatalf("initial state = %v, want %v", got, StateUnknown)
	}
	// One good check is not enough to declare an advertiser fit for traffic.
	m.Observe(allOK)
	if got := m.State(); got != StateUnknown {
		t.Errorf("after 1 of 3 successes: state = %v, want %v", got, StateUnknown)
	}
	observeN(m, allOK, 2)
	if got := m.State(); got != StateHealthy {
		t.Errorf("after 3 successes: state = %v, want %v", got, StateHealthy)
	}
}

func TestThresholds(t *testing.T) {
	m := NewMonitor(testPolicy(), clock.NewFake())
	observeN(m, allOK, 3)

	observeN(m, allFail, 2)
	if got := m.State(); got != StateHealthy {
		t.Errorf("after 2 of 3 failures: state = %v, want still %v", got, StateHealthy)
	}
	tr := m.Observe(allFail)
	if !tr.Changed || tr.To != StateUnhealthy {
		t.Errorf("third failure: %+v, want a change to %v", tr, StateUnhealthy)
	}
	if tr.Reason == "" {
		t.Error("transition has no reason; the audit log and the dashboard both need one")
	}
}

func TestDisagreementDegrades(t *testing.T) {
	m := NewMonitor(testPolicy(), clock.NewFake())
	observeN(m, allOK, 3)

	mixed := Report{SelfReport: SignalOK, ControlProbe: SignalFail, ClientObserved: SignalOK}
	observeN(m, mixed, 2)
	if got := m.State(); got != StateDegraded {
		t.Fatalf("state = %v, want %v", got, StateDegraded)
	}
	// Degraded is usable. It means something is odd, not that the advertiser is
	// broken, and taking capacity out of service on a whim is its own outage.
	if !StateDegraded.Usable() {
		t.Error("StateDegraded.Usable() = false, want true")
	}
}

func TestSilenceGoesOffline(t *testing.T) {
	clk := clock.NewFake()
	m := NewMonitor(testPolicy(), clk)
	observeN(m, allOK, 3)

	clk.Advance(89 * time.Second)
	if tr := m.Tick(); tr.Changed {
		t.Errorf("at 89s: %+v, want no change", tr)
	}
	clk.Advance(2 * time.Second)
	tr := m.Tick()
	if !tr.Changed || tr.To != StateOffline {
		t.Fatalf("at 91s: %+v, want a change to %v", tr, StateOffline)
	}
	if StateOffline.Usable() {
		t.Error("StateOffline.Usable() = true, want false")
	}
}

// Going offline must discard progress toward recovery. Otherwise an advertiser
// that banks nine successes, vanishes, and returns with one more is promoted on
// the strength of evidence gathered before it disappeared.
func TestOfflineResetsRecoveryProgress(t *testing.T) {
	clk := clock.NewFake()
	p := testPolicy()
	p.RecoverThreshold = 3
	m := NewMonitor(p, clk)

	observeN(m, allOK, 2) // two of the three needed
	clk.Advance(2 * time.Minute)
	if tr := m.Tick(); tr.To != StateOffline {
		t.Fatalf("state = %v, want %v", tr.To, StateOffline)
	}

	m.Observe(allOK)
	if got := m.State(); got == StateHealthy {
		t.Error("one success after going offline promoted straight to healthy")
	}
	observeN(m, allOK, 2)
	if got := m.State(); got != StateHealthy {
		t.Errorf("after a fresh run of 3: state = %v, want %v", got, StateHealthy)
	}
}

func TestImprovementIsRateLimitedButDegradationIsNot(t *testing.T) {
	clk := clock.NewFake()
	p := testPolicy()
	p.Cooldown = 5 * time.Minute
	m := NewMonitor(p, clk)

	observeN(m, allOK, 3)
	if got := m.State(); got != StateHealthy {
		t.Fatalf("state = %v, want %v", got, StateHealthy)
	}

	// Degradation is immediate. Cooldown must never delay taking a broken
	// advertiser out of service.
	observeN(m, allFail, 3)
	if got := m.State(); got != StateUnhealthy {
		t.Fatalf("degradation was delayed: state = %v, want %v", got, StateUnhealthy)
	}

	// Recovery is not immediate, even with the evidence in hand.
	observeN(m, allOK, 3)
	if got := m.State(); got != StateUnhealthy {
		t.Errorf("recovered inside the cooldown: state = %v, want still %v", got, StateUnhealthy)
	}
	// The operator can tell "still broken" from "waiting out the cooldown".
	tr := m.Observe(allOK)
	if !tr.Suppressed {
		t.Error("Suppressed = false; an operator cannot distinguish waiting from failing")
	}

	clk.Advance(5 * time.Minute)
	tr = m.Observe(allOK)
	if !tr.Changed || tr.To != StateHealthy {
		t.Errorf("after the cooldown: %+v, want a change to %v", tr, StateHealthy)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	clk := clock.NewFake()
	p := testPolicy()
	p.Cooldown = 5 * time.Minute
	m := NewMonitor(p, clk)
	observeN(m, allOK, 3)
	observeN(m, allFail, 3)

	// A control-plane restart must not reset every advertiser to unknown and
	// re-run every cooldown, which would make a deploy look like a fleet-wide
	// health incident.
	restored := NewMonitor(p, clk)
	restored.Restore(m.Snapshot())

	if got, want := restored.State(), m.State(); got != want {
		t.Errorf("restored state = %v, want %v", got, want)
	}
	observeN(restored, allOK, 3)
	if got := restored.State(); got != StateUnhealthy {
		t.Errorf("restored monitor ignored the inherited cooldown: state = %v", got)
	}
}

func TestZeroPolicyGetsDefaults(t *testing.T) {
	m := NewMonitor(Policy{}, clock.NewFake())
	if got, want := m.policy, DefaultPolicy(); got != want {
		t.Errorf("policy = %+v, want %+v", got, want)
	}
	// The defaults are the thresholds the architecture specifies: three strikes
	// to stop trusting an advertiser, ten to start again.
	if got := DefaultPolicy(); got.FailThreshold != 3 || got.RecoverThreshold != 10 {
		t.Errorf("DefaultPolicy thresholds = %d/%d, want 3/10", got.FailThreshold, got.RecoverThreshold)
	}
}
