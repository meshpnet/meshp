package health

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
)

// event records a committed transition and when it happened.
type event struct {
	at        time.Time
	from, to  State
	improving bool
}

// drive runs a monitor through an operation sequence encoded as bytes and
// returns every committed transition. Each byte chooses a report and an amount
// of time to advance, so a sequence explores both the evidence and the timing.
func drive(p Policy, ops []byte) ([]event, State) {
	clk := clock.NewFake()
	m := NewMonitor(p, clk)

	var events []event
	for _, op := range ops {
		var r Report
		switch op % 5 {
		case 0:
			r = allOK
		case 1:
			r = allFail
		case 2:
			r = Report{SelfReport: SignalOK, ControlProbe: SignalFail, ClientObserved: SignalOK}
		case 3:
			// The nasty one: the advertiser insists it is fine, its users say
			// otherwise.
			r = Report{SelfReport: SignalOK, ControlProbe: SignalOK, ClientObserved: SignalFail}
		case 4:
			r = silent
		}

		var tr Transition
		if op%5 == 4 {
			tr = m.Tick()
		} else {
			tr = m.Observe(r)
		}
		if tr.Changed {
			events = append(events, event{
				at:        clk.Now(),
				from:      tr.From,
				to:        tr.To,
				improving: rank(tr.From) >= 0 && rank(tr.To) > rank(tr.From),
			})
		}

		// Advance by a spread of intervals, some shorter than the cooldown and
		// some longer, so both sides of every boundary get exercised.
		clk.Advance(time.Duration(op%17) * 20 * time.Second)
	}
	return events, m.State()
}

// This is Invariant 10 stated as something a machine can check: no matter what
// the evidence does, an advertiser's state may not improve twice inside one
// cooldown. Degradations are deliberately unrestricted, so they are not counted.
func TestPropertyImprovementsRespectCooldown(t *testing.T) {
	p := DefaultPolicy()
	p.Cooldown = 5 * time.Minute

	rng := rand.New(rand.NewPCG(0x6865616c, 0x7468))
	for round := range 300 {
		ops := make([]byte, 120)
		for i := range ops {
			ops[i] = byte(rng.UintN(256))
		}

		events, _ := drive(p, ops)

		var lastImproving time.Time
		for i, e := range events {
			if !e.improving {
				continue
			}
			if !lastImproving.IsZero() {
				if gap := e.at.Sub(lastImproving); gap < p.Cooldown {
					t.Fatalf("round %d: improvement %d (%v -> %v) came %v after the previous one, cooldown is %v\nops: %v",
						round, i, e.from, e.to, gap, p.Cooldown, ops)
				}
			}
			lastImproving = e.at
		}
	}
}

// A stronger statement of the same thing: over a simulated span, the number of
// improvements cannot exceed what the cooldown allows. This catches a cooldown
// that is honoured pairwise but resets on some path.
func TestPropertyImprovementsAreBoundedOverTime(t *testing.T) {
	p := DefaultPolicy()
	p.Cooldown = 5 * time.Minute

	rng := rand.New(rand.NewPCG(7, 11))
	for round := range 100 {
		ops := make([]byte, 200)
		for i := range ops {
			ops[i] = byte(rng.UintN(256))
		}

		events, _ := drive(p, ops)
		if len(events) == 0 {
			continue
		}

		span := events[len(events)-1].at.Sub(events[0].at)
		improvements := 0
		for _, e := range events {
			if e.improving {
				improvements++
			}
		}
		// One improvement may land at each end of the span, hence the +1.
		if max := int(span/p.Cooldown) + 1; improvements > max {
			t.Fatalf("round %d: %d improvements across %v allows at most %d", round, improvements, span, max)
		}
	}
}

// The adversarial case the invariant exists for: an advertiser whose internet
// works and breaks as fast as it can be observed. Without hysteresis this drags
// every device assigned to it back and forth, breaking their connections each
// time.
func TestFlappingAdvertiserDoesNotDragStateWithIt(t *testing.T) {
	clk := clock.NewFake()
	p := Policy{FailThreshold: 3, RecoverThreshold: 10, DegradeThreshold: 3, Cooldown: 5 * time.Minute, OfflineAfter: time.Hour}
	m := NewMonitor(p, clk)

	changes := 0
	// One simulated hour of checks every five seconds, alternating in blocks
	// long enough to cross both thresholds.
	for i := range 720 {
		r := allOK
		if (i/12)%2 == 1 {
			r = allFail
		}
		if m.Observe(r).Changed {
			changes++
		}
		clk.Advance(5 * time.Second)
	}

	// An hour with a five minute cooldown permits at most 12 improvements, and
	// no more degradations than improvements plus one.
	if changes > 25 {
		t.Errorf("state changed %d times in a simulated hour; hysteresis is not holding", changes)
	}
	if changes == 0 {
		t.Error("state never changed across an hour of alternating health; the monitor is inert")
	}
	t.Logf("state changed %d times across 720 checks in a simulated hour", changes)
}

// Degradation must never be delayed. A cooldown that accidentally applies in
// both directions would keep sending traffic to an advertiser already known to
// be broken, which is the expensive direction of this trade-off.
func TestPropertyDegradationIsNeverSuppressed(t *testing.T) {
	p := DefaultPolicy()
	p.Cooldown = time.Hour // an absurd cooldown must still not delay failure

	rng := rand.New(rand.NewPCG(99, 100))
	for round := range 200 {
		ops := make([]byte, 100)
		for i := range ops {
			ops[i] = byte(rng.UintN(256))
		}

		clk := clock.NewFake()
		m := NewMonitor(p, clk)
		for _, op := range ops {
			var tr Transition
			if op%5 == 4 {
				tr = m.Tick()
			} else {
				tr = m.Observe(reportFor(op))
			}
			if tr.Suppressed && rank(tr.To) > rank(tr.From) {
				t.Fatalf("round %d: a suppressed transition reported an improvement: %+v", round, tr)
			}
			clk.Advance(time.Duration(op%17) * 20 * time.Second)
		}

		// Whatever happened, a sustained run of failures must land unhealthy.
		observeN(m, allFail, p.FailThreshold)
		if got := m.State(); got != StateUnhealthy && got != StateOffline {
			t.Fatalf("round %d: after %d sustained failures state is %v", round, p.FailThreshold, got)
		}
	}
}

func reportFor(op byte) Report {
	switch op % 5 {
	case 0:
		return allOK
	case 1:
		return allFail
	case 2:
		return Report{SelfReport: SignalOK, ControlProbe: SignalFail, ClientObserved: SignalOK}
	case 3:
		return Report{SelfReport: SignalOK, ControlProbe: SignalOK, ClientObserved: SignalFail}
	default:
		return silent
	}
}

func FuzzMonitor(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 1, 1})
	f.Add([]byte{4, 4, 4, 4})                // nothing but silence
	f.Add([]byte{3, 3, 3, 0, 0, 0})          // clients disagree with the node
	f.Add([]byte{0, 1, 0, 1, 0, 1, 0, 1})    // maximal flapping
	f.Add([]byte{2, 2, 2, 2, 1, 1, 1, 0, 0}) // disagreement then failure then recovery

	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 4096 {
			ops = ops[:4096]
		}
		p := DefaultPolicy()
		p.Cooldown = 5 * time.Minute

		events, final := drive(p, ops)

		// The state is always one of the declared ones — no zero value leaking
		// out of a path that forgot to assign.
		switch final {
		case StateUnknown, StateOffline, StateUnhealthy, StateDegraded, StateHealthy:
		default:
			t.Fatalf("monitor reached undeclared state %q", final)
		}

		var lastImproving time.Time
		for _, e := range events {
			if e.from == e.to {
				t.Fatalf("committed a transition that changed nothing: %v -> %v", e.from, e.to)
			}
			if !e.improving {
				continue
			}
			if !lastImproving.IsZero() && e.at.Sub(lastImproving) < p.Cooldown {
				t.Fatalf("improvement inside the cooldown: %v -> %v at %v", e.from, e.to, e.at)
			}
			lastImproving = e.at
		}
	})
}
