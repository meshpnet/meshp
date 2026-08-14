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
// Safe for concurrent use: the reconciler asks which candidate to configure while a prober
// is folding results in.
type Chooser struct {
	clk    clock.Clock
	groups map[string]*groupState
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
	return &Chooser{clk: clk, groups: make(map[string]*groupState)}
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
}

// Observe folds a probe result in and reports what it led to.
func (c *Chooser) Observe(assignment *meshpv1.RouteGroupAssignment, result Result) Decision {
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

	if !result.Reachable {
		state.consecutiveOK = 0
		state.consecutiveFail++
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
	if !assignment.GetLocalFailover().GetEnabled() && policy != nil {
		// Failover switched off means stay where you are once you have moved, rather than
		// oscillate under a policy that says not to.
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
func (c *Chooser) Forget(assigned []*meshpv1.RouteGroupAssignment) {
	keep := make(map[string]struct{}, len(assigned))
	for _, a := range assigned {
		keep[a.GetRouteGroupId()] = struct{}{}
	}
	for id := range c.groups {
		if _, ok := keep[id]; !ok {
			delete(c.groups, id)
		}
	}
}

func orDefault(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}
