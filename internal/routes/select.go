// Package routes turns a route group's advertisers into an ordered candidate
// list for one device.
//
// This is the selection half of ADR-0003. The control plane decides which
// advertisers a device is allowed to use and in what order; the agent decides
// which of them are alive. Because the output is an ordered list rather than a
// single choice, ordering decisions here are soft — putting an advertiser second
// rather than first costs nothing if the first one works, and loses nothing if it
// does not.
//
// Two properties matter more than the ranking rules:
//
//   - The output is a pure function of the input. Go randomises map iteration
//     order, and any selector that leaks that order would reshuffle candidates on
//     every recomputation. That is not a cosmetic bug: it is flapping, delivered
//     to every device in the network by a control plane that thinks it is
//     converging.
//   - Removing one advertiser from a group of N moves only the devices assigned
//     to that advertiser. Ordering by weighted rendezvous hash gives this for
//     free; ordering by anything derived from the group as a whole — round robin,
//     least-connections, sorted-by-load — does not, and reshuffles the entire
//     network every time an advertiser's numbers wobble.
package routes

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"

	"github.com/meshpnet/meshp/internal/health"
)

// AdminState is an operator's intent for an advertiser, independent of its
// observed health.
type AdminState string

const (
	// AdminEnabled means the advertiser is available for assignment.
	AdminEnabled AdminState = "enabled"
	// AdminDraining means take no new devices, and let existing ones move away
	// at their own pace.
	AdminDraining AdminState = "draining"
	// AdminDisabled means the advertiser is out of service entirely.
	AdminDisabled AdminState = "disabled"
)

// Mode is a route group's selection strategy.
type Mode string

const (
	// ModeFailover ranks candidates by health, then by the operator's stated
	// priority, then spreads devices across equals. This is the default.
	ModeFailover Mode = "failover"

	// ModePinned keeps a device on the advertiser it already has, and does not
	// move it automatically even when that advertiser is failing.
	//
	// This exists for customers who have allowlisted an outbound address with a
	// bank or a vendor. For them, appearing from a different address is not a
	// recovery: the destination rejects the traffic, and the symptom is far more
	// confusing than being plainly down. Customers who want both a stable
	// address and automatic failover need a route group with a floating egress
	// address, which keeps the address across the move.
	ModePinned Mode = "pinned"
)

// Advertiser is one machine offering to carry a route group's prefixes.
type Advertiser struct {
	ID            string
	PeerPublicKey string

	// Priority is the operator's preference order; lower is preferred. It ranks
	// advertisers of equal health, not advertisers of unequal health.
	Priority int

	// Weight spreads devices across advertisers within the same priority. A
	// weight of 200 attracts roughly twice as many devices as a weight of 100.
	// Zero or negative is treated as 1.
	Weight int

	Admin  AdminState
	Health health.State

	Region      string
	City        string
	DisplayName string
}

// Request describes one selection.
type Request struct {
	// DeviceKey identifies the device stably — in practice the membership ID.
	// The same key always produces the same ordering for the same advertiser
	// set, which is what stops devices wandering between recomputations.
	DeviceKey string

	// Current is the advertiser this device is already using, if any. It matters
	// for draining and for pinned groups.
	Current string

	Mode        Mode
	Advertisers []Advertiser
}

// Candidate is an advertiser offered to a device, in preference order.
type Candidate struct {
	Advertiser
	// Score is the rendezvous score used to order equals. Exposed for debugging
	// and for `meshp doctor`; nothing should branch on it.
	Score float64
}

// healthClass groups advertisers so that a working advertiser always outranks a
// questionable one, whatever the operator's stated priority. Priority expresses
// preference between advertisers that both work; it is not a reason to send
// traffic somewhere known to be worse.
//
// Unknown is selectable, and ranks last. On a fresh deployment or just after a
// control-plane restart, every advertiser is unknown, and refusing to offer any
// of them would mean no egress at all until health checks accumulate. Offering
// them is safe because the agent probes a candidate before using it (ADR-0003),
// so the server proposing an untested advertiser cannot break a device. This is
// not a violation of Invariant 8: unknown is the absence of information, not a
// failing health check.
func healthClass(s health.State) int {
	switch s {
	case health.StateHealthy:
		return 0
	case health.StateDegraded:
		return 1
	case health.StateUnknown:
		return 2
	default:
		return -1 // unhealthy or offline: not selectable
	}
}

// Select returns the ordered candidates a device may use, best first. An empty
// result means the device has no authorised egress through this group, which the
// caller must surface rather than silently leaving the device without a route.
func Select(req Request) []Candidate {
	// Pinned groups do not move. If the device already has an advertiser, that
	// is the answer regardless of health: the agent's own probe decides whether
	// it is usable, and moving would defeat the reason the group is pinned.
	if req.Mode == ModePinned && req.Current != "" {
		for _, a := range req.Advertisers {
			if a.ID == req.Current && a.Admin != AdminDisabled {
				return []Candidate{{Advertiser: a, Score: math.Inf(1)}}
			}
		}
	}

	type ranked struct {
		Candidate
		class    int
		draining bool
	}
	out := make([]ranked, 0, len(req.Advertisers))

	for _, a := range req.Advertisers {
		if a.Admin == AdminDisabled {
			continue
		}

		// Invariant 8: an advertiser that is observably failing receives no new
		// assignments. It is dropped even if it is the current one — that is
		// exactly the case failover exists for.
		class := healthClass(a.Health)
		if class < 0 {
			continue
		}

		// A draining advertiser is offered only to the devices already on it, and
		// ranks last so they move away at their next reconciliation. It keeps
		// carrying their traffic until they do, so nothing is cut off — though
		// moving does break connections through it (Invariant 11), which is why
		// draining is an operator action and not something health triggers.
		draining := a.Admin == AdminDraining
		if draining && a.ID != req.Current {
			continue
		}

		weight := a.Weight
		if weight <= 0 {
			weight = 1
		}
		out = append(out, ranked{
			Candidate: Candidate{Advertiser: a, Score: rendezvousScore(req.DeviceKey, a.ID, weight)},
			class:     class,
			draining:  draining,
		})
	}

	// Every comparison is total and every tie is broken by ID, so the ordering
	// is fully determined by the input. Anything less would let map iteration
	// order reach the wire.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.draining != b.draining {
			return !a.draining
		}
		if a.class != b.class {
			return a.class < b.class
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.ID < b.ID
	})

	candidates := make([]Candidate, len(out))
	for i, r := range out {
		candidates[i] = r.Candidate
	}
	return candidates
}

// rendezvousScore implements weighted rendezvous (highest random weight) hashing.
//
// Each (device, advertiser) pair gets a value drawn deterministically from the
// pair itself, so the ordering is stable per device and independent of every
// other device and advertiser. Removing an advertiser only affects the devices
// for which it scored highest, which is the minimal-disruption property; and
// scores scale with weight, so devices spread across a tier in proportion to it.
//
// Both of those properties depend entirely on the hash being uniform. An earlier
// version used FNV-1a, whose avalanche is weak enough that advertiser IDs sharing
// a prefix and differing in length — exit-00, exit-01, exit-new — produced
// visibly skewed draws: adding a fifth advertiser to four moved half the fleet
// instead of a fifth. SHA-256 is used instead. This runs once per device per
// route group when desired state is recomputed, not per packet, so the cost is
// irrelevant and the uniformity is worth having provably rather than probably.
//
// maphash would be faster still and is wrong here: it is seeded per process, so
// two control-plane replicas would disagree about the same device.
func rendezvousScore(deviceKey, advertiserID string, weight int) float64 {
	h := sha256.New()
	_, _ = h.Write([]byte(deviceKey))
	_, _ = h.Write([]byte{0}) // separator, so "ab"+"c" and "a"+"bc" differ
	_, _ = h.Write([]byte(advertiserID))
	sum := h.Sum(nil)

	// Map to the open interval (0,1). Zero would make the logarithm infinite and
	// one would make it zero, so both ends are excluded by construction.
	u := (float64(binary.BigEndian.Uint64(sum[:8])>>11) + 0.5) / float64(uint64(1)<<53)
	return float64(weight) / -math.Log(u)
}
