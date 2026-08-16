// Package routeprobe decides which advertiser a device is using, and when to move.
//
// The server orders the candidates and the agent picks among them (ADR-0003). This is the
// picking: given a stream of probe results, it says which candidate is current, when to
// fall back, and when to return. Nothing here probes anything — that is I/O, and keeping it
// out means the interesting decisions are testable against a fake clock rather than against
// a network that has to be broken on cue.
//
// Two ideas shape it.
//
// **Falling back is cheap and coming back is not.** A device that moves to a working
// advertiser has lost nothing; one that returns to a flapping advertiser loses every
// connection each time it moves. So failures are counted low, recoveries are counted high,
// and a minimum hold applies to the return but never to the escape.
//
// **The order is the server's.** This never invents a preference: it walks the list it was
// given, and the only question it answers is how far down to be. An agent that reordered
// candidates locally would make two devices behind the same policy disagree about what the
// policy says.
package routeprobe

import (
	"sync"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// Defaults are used when a policy leaves a field at zero.
//
// A control plane that has not thought about failover should still get behaviour that does
// not flap, so absent means "sensible" rather than "immediate".
const (
	DefaultFailThreshold    = 3
	DefaultRecoverThreshold = 10
	DefaultMinHold          = 60 * time.Second
)

// Chooser tracks which candidate is in use for each route group.
//
// Safe for concurrent use, and it has to be: the reconciler folds results in from its own
// timer while the session drains reports out to the control plane, and the reconciler
// itself is entered both from that timer and from an arriving state delta.
type Chooser struct {
	clk clock.Clock

	mu     sync.Mutex
	groups map[string]*groupState

	// pending holds at most one unsent report per group. Why one and not a queue is in
	// report.go, and it is a correctness argument rather than a tidiness one.
	pending map[string]*meshpv1.ReachabilityReport
}

type groupState struct {
	// currentID is the advertiser in use, empty before anything has been chosen.
	currentID string

	consecutiveFail int
	consecutiveOK   int

	// switchedAt is when the current choice was made, and what min-hold is measured from.
	switchedAt time.Time

	// preferredID is the head of the server's list. Kept so recovery has something to aim
	// at: coming back means returning to the server's first preference, not merely to
	// whatever happens to be one place up.
	preferredID string
}

// New returns a Chooser.
func New(clk clock.Clock) *Chooser {
	if clk == nil {
		clk = clock.System{}
	}
	return &Chooser{
		clk:     clk,
		groups:  make(map[string]*groupState),
		pending: make(map[string]*meshpv1.ReachabilityReport),
	}
}

// Current returns the candidate to use for an assignment.
//
// The server's first preference until something has been observed to fail, which is the
// honest default: an agent that has not probed knows nothing that the server does not.
//
// A candidate that has disappeared from the assignment is abandoned immediately, with no
// hold: the server withdrawing a candidate is not a failure to be hysteretic about, it is
// an instruction.
func (c *Chooser) Current(assignment *meshpv1.RouteGroupAssignment) *meshpv1.RouteCandidate {
	candidates := assignment.GetCandidates()
	if len(candidates) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	id := assignment.GetRouteGroupId()
	state, ok := c.groups[id]
	if !ok {
		state = &groupState{}
		c.groups[id] = state
	}
	state.preferredID = candidates[0].GetAdvertiserId()

	// Pinned means never move, whatever is observed. It exists for groups whose egress
	// address is allowlisted somewhere: moving would change the address, and a broken path
	// is a better outcome than a working path from an address a bank will refuse.
	if assignment.GetMode() == meshpv1.RouteGroupAssignment_MODE_PINNED {
		state.currentID = candidates[0].GetAdvertiserId()
		return candidates[0]
	}

	if state.currentID == "" {
		state.currentID = candidates[0].GetAdvertiserId()
		state.switchedAt = c.clk.Now()
		return candidates[0]
	}
	for _, candidate := range candidates {
		if candidate.GetAdvertiserId() == state.currentID {
			return candidate
		}
	}

	// The current choice is gone from the list.
	state.currentID = candidates[0].GetAdvertiserId()
	state.switchedAt = c.clk.Now()
	state.consecutiveFail, state.consecutiveOK = 0, 0
	return candidates[0]
}

// Result is what a probe of the current candidate found.
type Result struct {
	// Reachable is the quorum verdict across the probe targets, not one target's answer:
	// a single target measures that target's path rather than the advertiser's health.
	Reachable bool

	// RTT is informational and reported onward; nothing here branches on it.
	RTT time.Duration

	// Failed names the targets that did not answer, and is reported onward untouched.
	//
	// Nothing here branches on it either, and that is deliberate: the quorum has already
	// turned these into a verdict, and a second rule that looked at *which* targets failed
	// would be a policy the administrator did not write. It exists so an operator can tell
	// one target being down from the exit being down, which the boolean cannot say.
	Failed []string
}

// Decision is what a probe result led to.
type Decision struct {
	// Report is true when the control plane should be told. Every change is reported, and
	// so is the first result for a group — a device that only spoke up on change would
	// leave an advertiser at "unknown" for as long as it kept working, which is exactly
	// when the server most wants to hear that it does.
	Report bool

	// Switched names the advertiser left behind, empty when nothing moved.
	Switched string

	// Reason is written for whoever reads an audit log later, wanting to know why their
	// traffic moved.
	Reason string

	// Current is the advertiser now in use.
	Current string

	// ConsecutiveFailures is how many failures in a row this result makes, and on a
	// decision that moved, how many it took to move. Reported onward so the control plane
	// can tell an advertiser that failed once from one that failed three times, which is
	// the difference between a lost packet and an outage.
	ConsecutiveFailures int
}

// Observe folds a probe result in and reports what it led to.
func (c *Chooser) Observe(assignment *meshpv1.RouteGroupAssignment, result Result) Decision {
	c.mu.Lock()
	defer c.mu.Unlock()

	decision := c.observeLocked(assignment, result)
	if decision.Report {
		c.recordLocked(assignment.GetRouteGroupId(), decision, result)
	}
	return decision
}

func (c *Chooser) observeLocked(assignment *meshpv1.RouteGroupAssignment, result Result) Decision {
	id := assignment.GetRouteGroupId()
	state, ok := c.groups[id]
	if !ok || state.currentID == "" {
		// Nothing has been chosen, so there is nothing to have probed.
		return Decision{}
	}

	policy := assignment.GetLocalFailover()
	failThreshold := orDefault(int(policy.GetFailThreshold()), DefaultFailThreshold)
	recoverThreshold := orDefault(int(policy.GetRecoverThreshold()), DefaultRecoverThreshold)
	minHold := DefaultMinHold
	if policy.GetMinHoldSeconds() > 0 {
		minHold = time.Duration(policy.GetMinHoldSeconds()) * time.Second
	}

	first := state.consecutiveFail == 0 && state.consecutiveOK == 0
	decision := Decision{Current: state.currentID, Report: first}

	// A policy that says not to move means neither direction, and the counters still run.
	//
	// Both directions, because the field is called `enabled` and an operator who switched
	// local failover off has said the control plane decides where this device points. Moving
	// away but never coming back would park every device on a fallback after one blip, which
	// is a state nobody chose — and it would arrive silently, since the group still reports
	// itself as honoured.
	//
	// The counters and the report keep running, and that is the point of putting this here
	// rather than returning early: the control plane cannot see a path this device cannot
	// use, so a device that stopped saying "this advertiser is dead" the moment it was told
	// not to act on that would take away the one signal that could get somebody to act
	// instead.
	if !mayMove(assignment) {
		if result.Reachable {
			state.consecutiveFail = 0
			state.consecutiveOK++
			return decision
		}
		state.consecutiveOK = 0
		state.consecutiveFail++
		decision.ConsecutiveFailures = state.consecutiveFail
		if state.consecutiveFail == failThreshold {
			// Said once, on the pass that would have moved. Every pass would fill the log of
			// a device that is behaving exactly as configured; never saying it leaves an
			// operator with an unreachable prefix and no explanation.
			decision.Report = true
			decision.Reason = "the advertiser in use stopped answering probes, and this group's policy says not to move"
		}
		return decision
	}

	if !result.Reachable {
		state.consecutiveOK = 0
		state.consecutiveFail++
		// Read before any move. Moving resets the counter, so taking it afterwards would
		// report every switch as having been caused by nothing.
		decision.ConsecutiveFailures = state.consecutiveFail
		if state.consecutiveFail < failThreshold {
			return decision
		}
		// No hold on the way out. A minimum time between switches exists to stop a device
		// oscillating back to something broken, not to keep it sitting on something that
		// has already failed the threshold.
		if next := c.fallback(assignment, state); next != "" {
			decision.Switched = state.currentID
			decision.Reason = "the advertiser in use stopped answering probes"
			c.moveTo(state, next)
			decision.Current = next
			decision.Report = true
		}
		return decision
	}

	state.consecutiveFail = 0
	state.consecutiveOK++

	// Already where the server would put us; nothing to return to.
	if state.currentID == state.preferredID {
		return decision
	}
	if state.consecutiveOK < recoverThreshold {
		return decision
	}
	if c.clk.Now().Sub(state.switchedAt) < minHold {
		// The hold applies here and only here. Returning early to an advertiser that is
		// intermittently healthy is how a device ends up moving every few seconds, and each
		// move costs every connection through it.
		return decision
	}

	decision.Switched = state.currentID
	decision.Reason = "the preferred advertiser is answering again"
	c.moveTo(state, state.preferredID)
	decision.Current = state.preferredID
	decision.Report = true
	return decision
}

// fallback picks the next candidate after the current one, or nothing.
func (c *Chooser) fallback(assignment *meshpv1.RouteGroupAssignment, state *groupState) string {
	candidates := assignment.GetCandidates()
	for i, candidate := range candidates {
		if candidate.GetAdvertiserId() != state.currentID {
			continue
		}
		if i+1 < len(candidates) {
			return candidates[i+1].GetAdvertiserId()
		}
		// The last one failed. Staying put rather than wrapping to the front: the front is
		// where this started, and cycling a list of advertisers that are all failing would
		// move a device continuously while nothing improved.
		return ""
	}
	return ""
}

func (c *Chooser) moveTo(state *groupState, advertiserID string) {
	state.currentID = advertiserID
	state.switchedAt = c.clk.Now()
	state.consecutiveFail, state.consecutiveOK = 0, 0
}

// Forget drops state for groups no longer assigned, so a device that carried a prefix for a
// while does not remember its choice forever.
//
// Unsent reports go with it. A verdict about a group this device has been taken out of is
// not news the control plane can use: it would be folded into that advertiser's health on
// behalf of a device that is no longer behind it.
func (c *Chooser) Forget(assigned []*meshpv1.RouteGroupAssignment) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keep := make(map[string]struct{}, len(assigned))
	for _, a := range assigned {
		keep[a.GetRouteGroupId()] = struct{}{}
	}
	for id := range c.groups {
		if _, ok := keep[id]; !ok {
			delete(c.groups, id)
		}
	}
	// Swept separately rather than alongside the groups: a report handed back by Requeue
	// after its group was forgotten has no group state to be found by, and would otherwise
	// sit in the queue for the life of the process.
	for id := range c.pending {
		if _, ok := keep[id]; !ok {
			delete(c.pending, id)
		}
	}
}

// mayMove reports whether this group's policy lets the device choose for itself.
//
// An absent policy means yes. A control plane that has never heard of local failover is the
// case this has to get right, and a device that cannot leave a dead advertiser without being
// told to cannot leave one during the control-plane outage that is most likely to have
// caused the problem (ADR-0003). The server states `enabled` explicitly for exactly this
// reason — proto3 cannot tell an absent bool from false — so the only way to arrive here
// with no policy is from a server that does not send one at all.
func mayMove(assignment *meshpv1.RouteGroupAssignment) bool {
	policy := assignment.GetLocalFailover()
	if policy == nil {
		return true
	}
	return policy.GetEnabled()
}

func orDefault(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}
