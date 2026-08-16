package store

import (
	"encoding/json"
	"fmt"

	"github.com/meshpnet/meshp/internal/pathprobe"
)

// FailoverPolicy is what a route group tells its devices about moving between advertisers.
//
// The agent decides which candidate is alive; the server owns the set and the order
// (ADR-0003). This is the third thing: how patient to be about it. A device that moves on
// the first lost packet takes every connection through it down with each blip, and one that
// waits five minutes has an outage instead.
//
// Stored as jsonb rather than as columns, and handed to agents close to verbatim, because
// ADR-0001 makes failover one mechanism written once — a group is an exit pool, a subnet
// router or a service gateway depending only on what it carries, and adding a column per
// knob would mean this table growing every time the policy learns a new one.
type FailoverPolicy struct {
	// Enabled is whether the device may move itself at all.
	//
	// A pointer, so a row written before this field was read — or by hand — is told from one
	// that says false. The column defaults to '{"enabled": true}', so an absent value means
	// true, which is also the safe direction: a device that can leave a dead advertiser is a
	// better failure than one that cannot.
	Enabled *bool `json:"enabled,omitempty"`

	// FailThreshold is how many consecutive failed probes move the device on. Zero means the
	// agent's default.
	FailThreshold uint32 `json:"fail_threshold,omitempty"`

	// RecoverThreshold is how many consecutive successes bring it back to the server's first
	// preference. Higher than FailThreshold on purpose in every sensible policy: leaving is
	// cheap and returning costs every connection again.
	RecoverThreshold uint32 `json:"recover_threshold,omitempty"`

	// MinHoldSeconds is the floor on time between switches, applied to coming back and never
	// to leaving.
	MinHoldSeconds uint32 `json:"min_hold_seconds,omitempty"`

	// ProbeTargets are addresses the device dials through the advertiser to decide whether
	// the path works. Empty means the device falls back to whether the advertiser's tunnel
	// is up, which catches a gateway that is off and not one whose own uplink has failed.
	//
	// There is deliberately no default. Only an administrator knows what a working path
	// looks like for their network — for a branch LAN it is a host on that LAN, and nothing
	// else will do — and picking public addresses on their behalf would have every device
	// they own dialling a third party nobody asked it to.
	ProbeTargets []string `json:"probe_targets,omitempty"`

	// ProbeQuorum is how many targets must answer. Zero means a majority.
	ProbeQuorum uint32 `json:"probe_quorum,omitempty"`

	// ProbeIntervalMS is the floor on how often a device probes, so a group can be quieter
	// than the daemon's reconcile interval. Zero means probe on every pass.
	ProbeIntervalMS uint32 `json:"probe_interval_ms,omitempty"`
}

// MaxProbeTargets caps how many addresses one group may name.
//
// Every device carrying the group dials all of them on every round, so this is a number an
// administrator multiplies by their fleet without meaning to. Eight is more than enough for
// diversity — three or four is the useful range — and small enough that a policy cannot turn
// a fleet into a load generator.
const MaxProbeTargets = 8

// DefaultFailoverPolicy is what a group gets when nobody says otherwise.
//
// Enabled and nothing else: the thresholds are left at zero so the agent's own defaults
// apply, which keeps one set of numbers rather than two that can drift apart. A control
// plane that stated them here would be answering a question it has not been asked, and the
// agent would stop being able to tell "the administrator chose three" from "nobody chose".
func DefaultFailoverPolicy() FailoverPolicy {
	enabled := true
	return FailoverPolicy{Enabled: &enabled}
}

// MayMove reports whether the device may move itself between advertisers.
func (p FailoverPolicy) MayMove() bool { return p.Enabled == nil || *p.Enabled }

// Validate refuses a policy that cannot behave.
func (p FailoverPolicy) Validate() error {
	// A recover threshold below the fail threshold is a device that leaves slowly and
	// returns quickly, which is backwards: it will oscillate across a flapping advertiser,
	// dropping every connection through it on each pass. Refused rather than corrected,
	// because silently swapping an operator's numbers is worse than telling them.
	if p.FailThreshold > 0 && p.RecoverThreshold > 0 && p.RecoverThreshold < p.FailThreshold {
		return invalid(
			"recover_threshold %d is below fail_threshold %d, so a device would return "+
				"to a failing advertiser faster than it left it", p.RecoverThreshold, p.FailThreshold)
	}
	// Bounded because these are counts of probe rounds, and a threshold in the thousands is
	// a device that never moves — which reads as failover being broken rather than as the
	// policy it is.
	const maxThreshold = 1000
	if p.FailThreshold > maxThreshold || p.RecoverThreshold > maxThreshold {
		return invalid("probe thresholds must be at most %d", maxThreshold)
	}
	// A day. Long enough for any real hysteresis, short enough that a typed-in millisecond
	// value does not park a device on a fallback for a decade.
	const maxHold = 24 * 60 * 60
	if p.MinHoldSeconds > maxHold {
		return invalid("min_hold_seconds must be at most %d", maxHold)
	}

	if len(p.ProbeTargets) > MaxProbeTargets {
		return invalid("at most %d probe targets; every device carrying this group "+
			"dials all of them on every round", MaxProbeTargets)
	}
	// Parsed here rather than trusted, because the agent parses them too and a target it
	// cannot read is one it silently drops — which lowers the number of targets a quorum is
	// measured against without anything saying so.
	if _, err := pathprobe.ParseTargets(p.ProbeTargets); err != nil {
		return invalid("a probe target must be a literal address and port, "+
			"because resolving a name needs the DNS that fails with the gateway: %s", err)
	}
	// A quorum nothing can satisfy fails every advertiser, forever, and a device that has
	// run out of candidates stays on the last one while reporting it dead. The agent clamps
	// rather than obeying, so this is the only place a person can be told.
	if p.ProbeQuorum > uint32(len(p.ProbeTargets)) {
		return invalid("probe_quorum %d cannot be met by %d targets",
			p.ProbeQuorum, len(p.ProbeTargets))
	}
	// An interval below a second is a device dialling every target continuously; a day is
	// long enough that the probe has stopped being one.
	const minInterval, maxInterval = 1000, 24 * 60 * 60 * 1000
	if p.ProbeIntervalMS != 0 && (p.ProbeIntervalMS < minInterval || p.ProbeIntervalMS > maxInterval) {
		return invalid("probe_interval_ms must be between %d and %d, or zero for every pass",
			minInterval, maxInterval)
	}
	return nil
}

// encodeFailover renders a policy for the column.
func encodeFailover(p FailoverPolicy) ([]byte, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("store: encoding the failover policy: %w", err)
	}
	return raw, nil
}

// decodeFailover reads what the column holds.
//
// A row that will not parse is an error rather than a default. The alternative is a device
// quietly running on numbers nobody wrote, which is indistinguishable from the policy
// working — and the whole point of this field is that an operator can predict how their
// fleet behaves.
func decodeFailover(raw []byte) (FailoverPolicy, error) {
	if len(raw) == 0 {
		// NOT NULL with a default, so this should not happen. If it does, the honest answer
		// is the schema default rather than an error: refusing to build the assignment would
		// take the whole route group away over a missing knob.
		return DefaultFailoverPolicy(), nil
	}
	var p FailoverPolicy
	if err := json.Unmarshal(raw, &p); err != nil {
		return FailoverPolicy{}, fmt.Errorf("store: reading the failover policy: %w", err)
	}
	return p, nil
}
