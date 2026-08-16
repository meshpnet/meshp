package tunnel

import (
	"context"
	"net/netip"
	"time"

	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/pathprobe"
	"github.com/meshpnet/meshp/internal/routeprobe"
	"github.com/meshpnet/meshp/internal/wgplan"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// livenessGrace is how stale a handshake may be before the peer counts as unreachable.
//
// WireGuard rekeys well inside two minutes on a peer carrying traffic, and a peer with a
// keepalive answers regardless. Longer than REJECT_AFTER_TIME on purpose: the question is
// whether this advertiser is reachable at all, not whether the current session is fresh, and
// declaring a working advertiser dead because a rekey was a few seconds late would move a
// device for no reason.
const livenessGrace = 3 * time.Minute

// probeFromHandshake reads the observed interface for a verdict on one advertiser.
//
// Half the answer, and the cheap half. It measures whether the advertiser itself is
// reachable, which catches a gateway that is off or unplugged; it says nothing about whether
// anything behind it is, because a branch router whose own uplink has failed handshakes
// perfectly. The other half is probeThroughAdvertiser, which sends real traffic.
//
// This stays in front of that one rather than being replaced by it, and the ordering is the
// design. The two answer different questions and only one of them costs packets:
//
//   - No handshake at all is no verdict. A peer that was configured a moment ago has not had
//     time, and a probe would fail for that reason and move a device before it ever tried.
//   - A stale handshake is already a failure. The advertiser is unreachable, so there is
//     nothing to be learned by dialling through it, and a device with a dead gateway should
//     not also be generating traffic.
//   - A fresh handshake is where this stops being enough, and where the probe takes over.
//
// So the probe only ever tightens a verdict this one has already passed. It cannot rescue an
// advertiser the handshake says is gone, which is correct: the handshake is measuring the
// tunnel the probe would have to travel through.
func probeFromHandshake(observed wgplan.Observed, peerKey string) (routeprobe.Result, bool) {
	for _, peer := range observed.Peers {
		if string(peer.PublicKey) != peerKey {
			continue
		}
		// No handshake yet is not a failure. A peer that has just been configured has not
		// had time, and counting it against the advertiser would fail a device over before
		// it had ever tried.
		//
		// Defensive rather than load-bearing, and said so because a mutation proved it:
		// the kernel reports a zero age alongside no handshake, so falling through would
		// read as reachable and reach the same answer. It stays because the two facts are
		// separate — a future source of observations could report an age without a
		// handshake — and because "no handshake" and "handshake three minutes ago" should
		// not be one branch by accident.
		if !peer.HasHandshake {
			return routeprobe.Result{}, false
		}
		return routeprobe.Result{
			Reachable: peer.HandshakeAge <= livenessGrace,
			RTT:       0, // not measurable from a handshake
		}, true
	}
	// The advertiser is not a peer of this device at all, which is a different problem and
	// already reported as an unhonoured group.
	return routeprobe.Result{}, false
}

// chosenCandidate is the candidate this device should use for an assignment.
//
// The chooser's answer rather than the server's first preference, which is the whole point
// of the previous slice: the server orders the candidates and the agent decides how far
// down the list to be (ADR-0003).
func chosenCandidate(chooser *routeprobe.Chooser, assignment *meshpv1.RouteGroupAssignment) *meshpv1.RouteCandidate {
	if chooser == nil {
		// No chooser: take the server's order verbatim. That is what this did before local
		// failover existed, and it is the right behaviour for a build without one.
		if candidates := assignment.GetCandidates(); len(candidates) > 0 {
			return candidates[0]
		}
		return nil
	}
	return chooser.Current(assignment)
}

// Prober measures whether traffic through an interface reaches somewhere.
//
// An interface so the reconciler can be tested without a network, and so a platform with no
// implementation is a nil rather than a stub that dials out of the wrong interface and
// reports a number about the wrong path.
type Prober interface {
	// Probe dials every target through iface and reports how each went. It does not decide
	// anything: the quorum is the caller's, because the caller is the one holding the policy.
	Probe(ctx context.Context, iface string, targets []netip.AddrPort) []pathprobe.Outcome
}

// probeThroughAdvertiser sends traffic to the group's targets and folds the answers into a
// verdict, or reports that it did not run.
//
// The false is not a failure. A group with no targets, a host with no prober, or targets that
// will not parse all mean "this device cannot answer the question that way", and the caller
// keeps whatever the handshake said. Returning unreachable instead would fail every
// advertiser in a network whose administrator never configured a target, which is every
// network today.
func (r *Reconciler) probeThroughAdvertiser(ctx context.Context, iface string, assignment *meshpv1.RouteGroupAssignment) (routeprobe.Result, []string, bool) {
	if r.prober == nil {
		return routeprobe.Result{}, nil, false
	}
	policy := assignment.GetLocalFailover()
	raw := policy.GetProbeTargets()
	if len(raw) == 0 {
		return routeprobe.Result{}, nil, false
	}

	targets, err := pathprobe.ParseTargets(raw)
	if err != nil {
		// The store refuses these on the way in, so arriving here means a control plane that
		// does not validate, or a policy written before it did. Logged rather than partially
		// honoured: dropping the unparseable ones would quietly lower the number of targets
		// the quorum is measured against, so a policy asking for two of three would become
		// two of two and the group would fail on one target's bad afternoon.
		r.log.Warn("ignoring this group's probe targets and falling back to the handshake",
			"group", logx.Safe(assignment.GetName()), "error", logx.SafeError(err))
		return routeprobe.Result{}, nil, false
	}

	if !r.dueToProbe(assignment.GetRouteGroupId(), policy.GetProbeIntervalMs()) {
		return routeprobe.Result{}, nil, false
	}

	verdict := pathprobe.Verdict(r.prober.Probe(ctx, iface, targets), int(policy.GetProbeQuorum()))
	return routeprobe.Result{Reachable: verdict.Reachable, RTT: verdict.RTT}, verdict.Failed, true
}

// dueToProbe reports whether enough time has passed, and records that it has.
//
// A floor rather than a schedule. The reconciler's own tick decides when this is asked, and
// this only ever says "not yet" — so a group can be quieter than the daemon's reconcile
// interval but never noisier, and a burst of unrelated state deltas cannot turn a probe
// policy into a flood.
//
// An interval of zero means every pass, which is what a group that has not thought about it
// gets: the reconcile interval is already a minute.
func (r *Reconciler) dueToProbe(groupID string, intervalMS uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	if intervalMS == 0 {
		r.lastProbe[groupID] = now
		return true
	}
	last, seen := r.lastProbe[groupID]
	if seen && now.Sub(last) < time.Duration(intervalMS)*time.Millisecond {
		return false
	}
	r.lastProbe[groupID] = now
	return true
}
