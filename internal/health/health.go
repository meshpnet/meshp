// Package health decides whether a route advertiser is fit to carry traffic.
//
// Two things make this more than a boolean.
//
// First, an advertiser can pass every check it runs on itself while being
// useless to its users: the host has a default route and working DNS, but its
// forwarding or NAT rules are broken, so packets from devices go in and never
// come out. No self-check can see that. Health is therefore fused from three
// sources, and the one that measures what users actually experience — reports
// from the devices routing through it — is given the final word.
//
// Second, moving traffic is not free. Every reassignment breaks live connections
// (Invariant 11), so a monitor that changes its mind readily is worse than one
// that is slightly slow. The hysteresis here is deliberately asymmetric, and the
// asymmetry runs along which signal is speaking rather than along the direction
// of the change.
//
// A client's verdict is authoritative on arrival, because the agent has already
// applied its own hysteresis before sending one (internal/routeprobe counts
// failures and successes and holds a minimum time before moving). So a client
// report improves the state on its own evidence, bounded in time by the cooldown
// rather than by a second sample count. Counting samples again would apply the
// same filter twice, and since agents report on change rather than on a timer,
// the second count is over events and never reaches a threshold sized for
// polling.
//
// Degradation keeps its sample count, which is not symmetry but a different
// concern: nothing here aggregates across clients yet, so that counter is the
// only thing between one device's broken Wi-Fi and an advertiser marked
// unhealthy for the whole network. Being slow to distrust a broken advertiser
// costs users their traffic, and distrusting a working one on one device's word
// costs everyone else theirs.
package health

import (
	"fmt"
	"sync"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
)

// State is an advertiser's observed health. Administrative states — draining and
// disabled — are deliberately not in this enum; they are a separate axis, and
// combining them here is what lets an operator action and a health observation
// overwrite each other.
type State string

const (
	// StateUnknown is the state before any observation has arrived.
	StateUnknown State = "unknown"
	// StateOffline means nothing has been heard for longer than the policy allows.
	StateOffline State = "offline"
	// StateUnhealthy means the advertiser is observably failing.
	StateUnhealthy State = "unhealthy"
	// StateDegraded means signals disagree: usable, but not to be preferred.
	StateDegraded State = "degraded"
	// StateHealthy means every available signal agrees it is working.
	StateHealthy State = "healthy"
)

// rank orders states from worst to best so the monitor can tell an improvement
// from a degradation. StateUnknown has no rank: it is the absence of
// information, not a position on the scale, and leaving it is always permitted.
func rank(s State) int {
	switch s {
	case StateOffline:
		return 0
	case StateUnhealthy:
		return 1
	case StateDegraded:
		return 2
	case StateHealthy:
		return 3
	default:
		return -1
	}
}

// Usable reports whether traffic may be routed through an advertiser in this
// state. Degraded is usable — it means "something is odd", not "broken" — but
// selection ranks it below healthy.
func (s State) Usable() bool { return s == StateHealthy || s == StateDegraded }

// Signal is one source's verdict.
type Signal int

const (
	// SignalNone means this source has nothing to say. It is not a failure.
	SignalNone Signal = iota
	// SignalOK means this source observed the advertiser working.
	SignalOK
	// SignalFail means this source observed the advertiser failing.
	SignalFail
)

// Report is one round of observation.
type Report struct {
	// SelfReport is what the advertiser says about itself: interface up, default
	// route present, upstream reachable.
	SelfReport Signal

	// ControlProbe is what the control plane observed, ideally by sending
	// traffic through the advertiser rather than merely reaching its host.
	ControlProbe Signal

	// ClientObserved is the aggregated verdict of the devices currently routing
	// through this advertiser. Aggregation — requiring a quorum of clients, so
	// one device's broken Wi-Fi is not mistaken for a broken exit — happens
	// before this point. By the time it arrives here it is authoritative.
	ClientObserved Signal
}

// verdict collapses a report into ok, fail or partial.
type verdict int

const (
	verdictNone verdict = iota
	verdictOK
	verdictFail
	verdictPartial
)

func (r Report) verdict() verdict {
	// Clients see what users see. An advertiser whose own checks pass while the
	// devices behind it cannot get out is precisely the broken-forwarding case
	// that a self-check cannot detect, so this overrides everything.
	if r.ClientObserved == SignalFail {
		return verdictFail
	}

	var ok, fail int
	for _, s := range [...]Signal{r.SelfReport, r.ControlProbe, r.ClientObserved} {
		switch s {
		case SignalOK:
			ok++
		case SignalFail:
			fail++
		case SignalNone:
		}
	}
	switch {
	case ok == 0 && fail == 0:
		return verdictNone
	case fail == 0:
		return verdictOK
	case ok == 0:
		return verdictFail
	default:
		return verdictPartial
	}
}

// Policy tunes the state machine. The zero value is not useful; use
// DefaultPolicy and adjust.
type Policy struct {
	// FailThreshold is how many consecutive failing observations mark an
	// advertiser unhealthy.
	FailThreshold int

	// RecoverThreshold is how many consecutive healthy observations are needed
	// to improve. Deliberately much larger than FailThreshold.
	RecoverThreshold int

	// DegradeThreshold is how many consecutive disagreeing observations mark an
	// advertiser degraded.
	DegradeThreshold int

	// Cooldown is the minimum interval between improvements. This is the
	// mechanism behind Invariant 10: without it, an advertiser that alternates
	// between working and broken drags devices back and forth with it.
	Cooldown time.Duration

	// OfflineAfter is how long silence lasts before an advertiser is offline.
	OfflineAfter time.Duration
}

// DefaultPolicy implements the thresholds the architecture calls for: three
// strikes to stop trusting an advertiser, ten to start again.
func DefaultPolicy() Policy {
	return Policy{
		FailThreshold:    3,
		RecoverThreshold: 10,
		DegradeThreshold: 3,
		Cooldown:         5 * time.Minute,
		OfflineAfter:     90 * time.Second,
	}
}

func (p Policy) withDefaults() Policy {
	d := DefaultPolicy()
	if p.FailThreshold <= 0 {
		p.FailThreshold = d.FailThreshold
	}
	if p.RecoverThreshold <= 0 {
		p.RecoverThreshold = d.RecoverThreshold
	}
	if p.DegradeThreshold <= 0 {
		p.DegradeThreshold = d.DegradeThreshold
	}
	if p.Cooldown < 0 {
		p.Cooldown = 0
	} else if p.Cooldown == 0 {
		p.Cooldown = d.Cooldown
	}
	if p.OfflineAfter <= 0 {
		p.OfflineAfter = d.OfflineAfter
	}
	return p
}

// Transition describes the result of an observation.
type Transition struct {
	From    State
	To      State
	Changed bool

	// Reason is written for a human reading an audit log six weeks later,
	// wanting to know why their outbound address changed. It is stored verbatim
	// and shown in the dashboard.
	Reason string

	// Suppressed is set when the monitor wanted to improve the state but the
	// cooldown forbade it. Surfacing this is how an operator tells "still
	// broken" apart from "recovered, waiting out the cooldown".
	Suppressed bool
}

// Monitor tracks one advertiser. It is safe for concurrent use.
type Monitor struct {
	policy Policy
	clk    clock.Clock

	mu                 sync.Mutex
	state              State
	consecutiveOK      int
	consecutiveFail    int
	consecutivePartial int
	lastImproved       time.Time
	lastReport         time.Time
}

// NewMonitor returns a Monitor in StateUnknown.
func NewMonitor(p Policy, clk clock.Clock) *Monitor {
	if clk == nil {
		clk = clock.System{}
	}
	return &Monitor{policy: p.withDefaults(), clk: clk, state: StateUnknown}
}

// State returns the current state.
func (m *Monitor) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Snapshot describes the monitor's state for storage and for the API.
type Snapshot struct {
	State              State
	ConsecutiveOK      int
	ConsecutiveFail    int
	ConsecutivePartial int
	LastImprovedAt     time.Time
	LastReportAt       time.Time
}

// Snapshot returns the persistable state.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		State:              m.state,
		ConsecutiveOK:      m.consecutiveOK,
		ConsecutiveFail:    m.consecutiveFail,
		ConsecutivePartial: m.consecutivePartial,
		LastImprovedAt:     m.lastImproved,
		LastReportAt:       m.lastReport,
	}
}

// Restore reinstates a stored snapshot, so a control-plane restart does not
// reset every advertiser to unknown and re-run every cooldown.
func (m *Monitor) Restore(s Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.State == "" {
		s.State = StateUnknown
	}
	m.state = s.State
	m.consecutiveOK = s.ConsecutiveOK
	m.consecutiveFail = s.ConsecutiveFail
	m.consecutivePartial = s.ConsecutivePartial
	m.lastImproved = s.LastImprovedAt
	m.lastReport = s.LastReportAt
}

// Observe feeds in one round of observation.
func (m *Monitor) Observe(r Report) Transition {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clk.Now()
	v := r.verdict()
	if v == verdictNone {
		// Nothing was measured. This is not evidence of anything, so counters
		// are left alone — but it is also not contact, so it does not stave off
		// going offline.
		return m.transitionLocked(m.state, "no signal", now)
	}
	m.lastReport = now

	switch v {
	case verdictOK:
		m.consecutiveOK++
		m.consecutiveFail, m.consecutivePartial = 0, 0
	case verdictFail:
		m.consecutiveFail++
		m.consecutiveOK, m.consecutivePartial = 0, 0
	case verdictPartial:
		m.consecutivePartial++
		m.consecutiveOK, m.consecutiveFail = 0, 0
	case verdictNone:
	}

	want, reason := m.desiredLocked(v, r)
	return m.transitionLocked(want, reason, now)
}

// Tick advances time without an observation, so silence can be noticed. A health
// loop calls this when a scheduled check produced nothing at all.
func (m *Monitor) Tick() Transition {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.transitionLocked(m.state, "tick", m.clk.Now())
}

// desiredLocked computes the state the evidence points at, ignoring cooldown.
func (m *Monitor) desiredLocked(v verdict, r Report) (State, string) {
	switch v {
	case verdictFail:
		if m.consecutiveFail >= m.policy.FailThreshold {
			return StateUnhealthy, fmt.Sprintf("%d consecutive failed checks", m.consecutiveFail)
		}
	case verdictPartial:
		if m.consecutivePartial >= m.policy.DegradeThreshold {
			return StateDegraded, fmt.Sprintf("%d consecutive checks with disagreeing signals", m.consecutivePartial)
		}
	case verdictOK:
		// A client's verdict arrives already filtered. The agent counts its own
		// failures and successes and holds a minimum time before it moves at all
		// (internal/routeprobe), so by the time a report is sent the hysteresis
		// has been applied once. Counting samples again here applies it twice —
		// and because agents report on change rather than on a timer, the second
		// count is over events and never reaches a threshold sized for polling.
		// One client would contribute one sample and the advertiser would sit at
		// unknown forever, which is what this used to do.
		//
		// Deliberately not symmetric with the failure path above. That counter is
		// the only thing standing between one device's broken Wi-Fi and an
		// advertiser marked unhealthy for the whole network, because the
		// cross-client aggregation Report describes does not exist yet. Improving
		// too readily costs nothing by comparison: an advertiser wrongly called
		// healthy is one the agents will demote again from their own probes, and
		// the cooldown in transitionLocked still bounds how often it can happen.
		if r.ClientObserved == SignalOK {
			return StateHealthy, "the devices routing through it report reaching it"
		}
		if m.consecutiveOK >= m.policy.RecoverThreshold {
			return StateHealthy, fmt.Sprintf("%d consecutive successful checks", m.consecutiveOK)
		}
	case verdictNone:
	}
	return m.state, "insufficient evidence to change state"
}

// transitionLocked applies the offline rule and the cooldown, then commits.
func (m *Monitor) transitionLocked(want State, reason string, now time.Time) Transition {
	from := m.state

	// Silence outranks everything else the evidence might suggest: an advertiser
	// we cannot hear from cannot be given new traffic, whatever it last said.
	if !m.lastReport.IsZero() && now.Sub(m.lastReport) >= m.policy.OfflineAfter {
		want = StateOffline
		reason = fmt.Sprintf("no report for %s", now.Sub(m.lastReport).Round(time.Second))
	}

	if want == from {
		return Transition{From: from, To: from, Reason: reason}
	}

	improving := rank(from) >= 0 && rank(want) > rank(from)
	if improving && m.policy.Cooldown > 0 && !m.lastImproved.IsZero() {
		if since := now.Sub(m.lastImproved); since < m.policy.Cooldown {
			// Hold the worse state. The evidence is not being discarded — the
			// counters keep climbing — only the promotion is deferred.
			return Transition{
				From:       from,
				To:         from,
				Reason:     fmt.Sprintf("%s, but improvement suppressed for another %s", reason, (m.policy.Cooldown - since).Round(time.Second)),
				Suppressed: true,
			}
		}
	}

	m.state = want
	if improving || rank(from) < 0 {
		m.lastImproved = now
	}
	if want == StateOffline {
		// Losing contact invalidates progress toward recovery. Without this, an
		// advertiser that accumulates nine successes, disappears, and returns
		// with one more would be promoted straight to healthy on the strength of
		// evidence gathered before it vanished.
		m.consecutiveOK, m.consecutiveFail, m.consecutivePartial = 0, 0, 0
	}
	return Transition{From: from, To: want, Changed: true, Reason: reason}
}
