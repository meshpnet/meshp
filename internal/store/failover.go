package store

import (
	"encoding/json"
	"fmt"
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
}

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
		return fmt.Errorf(
			"store: recover_threshold %d is below fail_threshold %d, so a device would return "+
				"to a failing advertiser faster than it left it", p.RecoverThreshold, p.FailThreshold)
	}
	// Bounded because these are counts of probe rounds, and a threshold in the thousands is
	// a device that never moves — which reads as failover being broken rather than as the
	// policy it is.
	const maxThreshold = 1000
	if p.FailThreshold > maxThreshold || p.RecoverThreshold > maxThreshold {
		return fmt.Errorf("store: probe thresholds must be at most %d", maxThreshold)
	}
	// A day. Long enough for any real hysteresis, short enough that a typed-in millisecond
	// value does not park a device on a fallback for a decade.
	const maxHold = 24 * 60 * 60
	if p.MinHoldSeconds > maxHold {
		return fmt.Errorf("store: min_hold_seconds must be at most %d", maxHold)
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
