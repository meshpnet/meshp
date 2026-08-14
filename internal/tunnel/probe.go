package tunnel

import (
	"time"

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
// An honest first probe rather than the intended one. What the failover policy asks for is
// traffic sent *through* the advertiser to diverse targets, which measures what a user
// experiences; this measures only whether the advertiser itself is reachable. The
// difference matters — a gateway whose own uplink has failed still handshakes — so this
// catches an advertiser that is off or unreachable and not one that is present and useless.
//
// It is worth having anyway because it costs nothing: the reconciler already reads this
// from the kernel on every pass, so a device fails over from a dead gateway without a
// single extra packet. Probing through the advertiser is the next slice, and this is the
// subset that needs no new I/O to be true.
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
