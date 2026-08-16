// Package pathprobe measures whether traffic actually gets through an interface.
//
// It exists because a WireGuard handshake answers the wrong question. A handshake says the
// advertiser is reachable; it says nothing about whether anything behind it is. A branch
// router whose own uplink has failed handshakes perfectly, and every device steered at it
// sits there with no internet while the control plane and the agent both report health.
//
// So this sends real traffic to targets an administrator named, through the tunnel, and
// counts how many answered. The decision of what to do about the answer is not here — that
// is routeprobe, which is deliberately free of I/O so its hysteresis can be tested against
// a fake clock rather than a network that has to be broken on cue. This package is the
// opposite half: the I/O, with the smallest possible amount of judgement attached.
//
// Two properties matter more than anything else here.
//
// **It must go through the tunnel, or it means nothing.** A probe that fell back to the
// physical interface would report the advertiser healthy while measuring the local
// connection — a false positive that keeps a device on a dead gateway, which is the exact
// failure this package was written to remove. The dialer therefore binds to the interface
// rather than trusting the routing table, and a platform that cannot do that has no prober
// at all rather than a hopeful one.
//
// **One target is not a verdict.** A single target measures that target's path. Requiring a
// quorum of diverse targets is what makes the difference between "the exit is down" and
// "one operator is having a bad afternoon", and getting that wrong moves every device in a
// fleet at once.
package pathprobe

import (
	"errors"
	"net/netip"
	"sort"
	"time"
)

// ErrUnsupported means this platform cannot probe through a named interface.
//
// Returned rather than silently probing anyway. A verdict that did not go through the
// tunnel is worse than no verdict: no verdict leaves the handshake in charge, which is
// honest about what it measures, while a wrong one fails a working advertiser or passes a
// dead one.
var ErrUnsupported = errors.New("pathprobe: this platform cannot bind a probe to an interface")

// Outcome is what happened to one target.
type Outcome struct {
	Target netip.AddrPort

	// RTT is how long the connection took to establish. Meaningless when Err is set.
	RTT time.Duration

	// Err is why the target did not answer, or nil.
	Err error
}

// Result is the verdict across every target.
type Result struct {
	// Reachable is whether enough targets answered.
	Reachable bool

	// RTT is the median of the successful dials, or zero when none succeeded.
	//
	// The median rather than the fastest: the fastest is a lower bound on the path and
	// flatters a link where most targets are slow, and this number ends up in front of
	// somebody asking why their connection feels bad.
	RTT time.Duration

	// Failed names the targets that did not answer, in the order they were given.
	//
	// Reported onward so an operator can tell one target being down from the exit being
	// down — which is the same distinction the quorum makes, except that the quorum only
	// decides and this explains.
	Failed []string

	// Answered is how many targets came back, for the log line that says why a device did
	// or did not move.
	Answered int
}

// Quorum is how many targets must answer for a path to count as working.
//
// Zero means a majority, which is the honest default for an odd number of diverse targets
// and rounds in the safe direction for an even one: two of two, two of four. Requiring more
// than half is what stops one operator's outage moving a fleet; requiring all of them would
// mean the least reliable target decides.
//
// A quorum larger than the number of targets can never be met, so it is clamped rather than
// honoured. Refusing it belongs where a person can be told — the store validates it — and
// by the time an assignment reaches a device the only choices left are to clamp or to fail
// every advertiser forever.
func Quorum(want int, targets int) int {
	if targets <= 0 {
		return 0
	}
	if want <= 0 {
		return targets/2 + 1
	}
	if want > targets {
		return targets
	}
	return want
}

// Verdict folds per-target outcomes into an answer.
func Verdict(outcomes []Outcome, wantQuorum int) Result {
	quorum := Quorum(wantQuorum, len(outcomes))

	var rtts []time.Duration
	result := Result{}
	for _, o := range outcomes {
		if o.Err != nil {
			result.Failed = append(result.Failed, o.Target.String())
			continue
		}
		result.Answered++
		rtts = append(rtts, o.RTT)
	}

	// No targets is not a verdict of unreachable. A group with nothing to probe has to fall
	// back to what the handshake says, and returning "unreachable" here would fail every
	// advertiser in a network whose administrator never configured a target.
	if len(outcomes) == 0 {
		return Result{}
	}

	result.Reachable = result.Answered >= quorum
	result.RTT = median(rtts)
	return result
}

// median of the successful dials, or zero.
func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	// The lower of the two middles rather than their mean. Averaging two durations invents
	// a number neither target produced, and this is reported as an observation.
	return sorted[mid-1]
}

// ParseTargets turns configured strings into addresses.
//
// Literal addresses only, never hostnames, and that is a decision rather than a
// simplification. Resolving a name needs DNS, and DNS is one of the things that stops
// working when a gateway fails — so a probe that had to resolve first would blame the
// advertiser for a resolver's outage. Worse, a device that fails closed refuses plaintext
// DNS outside the tunnel (ADR-0011), so the lookup would depend on the very path being
// tested.
func ParseTargets(raw []string) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(raw))
	for _, s := range raw {
		target, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		if target.Port() == 0 {
			return nil, errors.New("pathprobe: a probe target needs a port")
		}
		out = append(out, target)
	}
	return out, nil
}
