package routes

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/meshpnet/meshp/internal/health"
)

func healthyPool(n int) []Advertiser {
	out := make([]Advertiser, n)
	for i := range out {
		out[i] = adv(fmt.Sprintf("exit-%02d", i), 1, health.StateHealthy)
	}
	return out
}

// Shuffling the input must not change the output. This is a stronger claim than
// "the same input gives the same output", and it is the one that catches an
// incomplete comparator: any pair the sort cannot order becomes dependent on
// arrival order, which in turn depends on whatever map or query produced it.
func TestPropertySelectIsIndependentOfInputOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	pool := healthyPool(8)
	// Deliberately include exact ties in weight and priority, since those are the
	// pairs a weak comparator fails to order.
	pool[3].Weight, pool[4].Weight = 100, 100
	pool[5].Priority, pool[6].Priority = 2, 2

	for _, key := range []string{"a", "membership-42", "θ", ""} {
		want := ids(Select(Request{DeviceKey: key, Mode: ModeFailover, Advertisers: pool}))

		for attempt := range 200 {
			shuffled := append([]Advertiser(nil), pool...)
			rng.Shuffle(len(shuffled), func(i, j int) {
				shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
			})

			got := ids(Select(Request{DeviceKey: key, Mode: ModeFailover, Advertisers: shuffled}))
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("key %q attempt %d: input order changed the result\n got: %v\nwant: %v", key, attempt, got, want)
			}
		}
	}
}

// Removing one advertiser from a group must move only the devices that were
// using it. A selector that reshuffles everyone on a membership change turns one
// machine going down into a network-wide reassignment, breaking connections for
// devices that had nothing to do with the failure.
func TestPropertyMinimalDisruptionOnRemoval(t *testing.T) {
	const devices = 10_000
	pool := healthyPool(5)

	before := make(map[string]string, devices)
	for i := range devices {
		key := fmt.Sprintf("membership-%05d", i)
		before[key] = top(Select(Request{DeviceKey: key, Mode: ModeFailover, Advertisers: pool}))
	}

	// Take out the third advertiser.
	reduced := append(append([]Advertiser(nil), pool[:2]...), pool[3:]...)
	removed := pool[2].ID

	moved, stayed := 0, 0
	for key, was := range before {
		now := top(Select(Request{DeviceKey: key, Current: was, Mode: ModeFailover, Advertisers: reduced}))
		switch was {
		case removed:
			moved++
			if now == removed {
				t.Fatalf("%s is still assigned to the removed %s", key, removed)
			}
		default:
			stayed++
			if now != was {
				t.Fatalf("%s moved from %s to %s although %s was the one removed", key, was, now, removed)
			}
		}
	}

	// Exactly the devices that were on the removed advertiser move, and with a
	// uniform hash that is one fifth of them. The tolerance here is tight on
	// purpose: a loose bound passes happily on a badly distributed hash, which is
	// how a version of this selector that moved half the fleet on every capacity
	// change went unnoticed.
	assertNear(t, "devices moved after removing 1 of 5", moved, devices/5, 0.10)
	t.Logf("removing 1 of 5 advertisers moved %d devices and left %d untouched", moved, stayed)
}

// Adding capacity must be equally undisruptive: only the devices that the new
// advertiser wins may move, and nobody else.
func TestPropertyMinimalDisruptionOnAddition(t *testing.T) {
	const devices = 10_000
	pool := healthyPool(4)

	before := make(map[string]string, devices)
	for i := range devices {
		key := fmt.Sprintf("membership-%05d", i)
		before[key] = top(Select(Request{DeviceKey: key, Mode: ModeFailover, Advertisers: pool}))
	}

	grown := append(append([]Advertiser(nil), pool...), adv("exit-new", 1, health.StateHealthy))

	moved := 0
	for key, was := range before {
		now := top(Select(Request{DeviceKey: key, Current: was, Mode: ModeFailover, Advertisers: grown}))
		if now == was {
			continue
		}
		moved++
		if now != "exit-new" {
			t.Fatalf("%s moved from %s to %s, but only the new advertiser should attract devices", key, was, now)
		}
	}
	// A new advertiser in a group of five should attract one fifth of the fleet
	// and disturb nobody else.
	assertNear(t, "devices moved after adding a 5th advertiser", moved, devices/5, 0.10)
	t.Logf("adding a 5th advertiser moved %d of %d devices", moved, devices)
}

// Everything else in this file rests on the rendezvous hash being uniform. If it
// is not, weights lie, capacity changes move far more devices than they should,
// and some advertisers quietly carry several times their share — none of which
// shows up as a failure anywhere else. So it is asserted directly, over advertiser
// IDs that share a prefix and differ in length, which is the shape that broke the
// first implementation.
func TestPropertyDistributionIsUniform(t *testing.T) {
	const devices = 20_000

	for _, n := range []int{2, 3, 5, 8} {
		t.Run(fmt.Sprintf("%d-advertisers", n), func(t *testing.T) {
			pool := healthyPool(n)
			counts := map[string]int{}
			for i := range devices {
				key := fmt.Sprintf("membership-%05d", i)
				counts[top(Select(Request{DeviceKey: key, Mode: ModeFailover, Advertisers: pool}))]++
			}
			for _, a := range pool {
				assertNear(t, "share for "+a.ID, counts[a.ID], devices/n, 0.10)
			}
		})
	}

	// The awkward case specifically: IDs of differing length sharing a prefix.
	pool := append(healthyPool(4), adv("exit-new", 1, health.StateHealthy))
	counts := map[string]int{}
	for i := range devices {
		key := fmt.Sprintf("membership-%05d", i)
		counts[top(Select(Request{DeviceKey: key, Mode: ModeFailover, Advertisers: pool}))]++
	}
	for _, a := range pool {
		assertNear(t, "share for "+a.ID+" among mixed-length ids", counts[a.ID], devices/5, 0.10)
	}
}

// assertNear fails when got is more than tolerance (as a fraction) away from want.
func assertNear(t *testing.T, what string, got, want int, tolerance float64) {
	t.Helper()
	lo := int(float64(want) * (1 - tolerance))
	hi := int(float64(want) * (1 + tolerance))
	if got < lo || got > hi {
		t.Errorf("%s = %d, want %d ± %.0f%% (%d..%d)", what, got, want, tolerance*100, lo, hi)
	}
}

// Weight has to actually mean something, in proportion.
func TestPropertyWeightDistributesProportionally(t *testing.T) {
	const devices = 20_000
	pool := []Advertiser{
		{ID: "big", Priority: 1, Weight: 300, Admin: AdminEnabled, Health: health.StateHealthy},
		{ID: "small", Priority: 1, Weight: 100, Admin: AdminEnabled, Health: health.StateHealthy},
	}

	counts := map[string]int{}
	for i := range devices {
		key := fmt.Sprintf("membership-%05d", i)
		counts[top(Select(Request{DeviceKey: key, Mode: ModeFailover, Advertisers: pool}))]++
	}

	share := float64(counts["big"]) / float64(devices)
	if share < 0.70 || share > 0.80 {
		t.Errorf("advertiser with 3x the weight took %.1f%% of devices, want about 75%%", share*100)
	}
	t.Logf("weights 300:100 split %d:%d (%.1f%% / %.1f%%)",
		counts["big"], counts["small"], share*100, (1-share)*100)
}

// Invariant 8 as a property: over arbitrary combinations of health and
// administrative state, nothing failing or disabled is ever offered, and a
// draining advertiser reaches only the device already on it.
func TestPropertyNeverOffersSomethingUnusable(t *testing.T) {
	states := []health.State{
		health.StateUnknown, health.StateOffline, health.StateUnhealthy,
		health.StateDegraded, health.StateHealthy,
	}
	admins := []AdminState{AdminEnabled, AdminDraining, AdminDisabled}

	rng := rand.New(rand.NewPCG(0x726f, 0x757465))
	for round := range 3000 {
		n := 1 + rng.IntN(6)
		pool := make([]Advertiser, n)
		for i := range pool {
			pool[i] = Advertiser{
				ID:       fmt.Sprintf("a%d", i),
				Priority: rng.IntN(3),
				Weight:   rng.IntN(400) - 50, // include invalid weights
				Admin:    admins[rng.IntN(len(admins))],
				Health:   states[rng.IntN(len(states))],
			}
		}

		current := ""
		if rng.IntN(2) == 0 {
			current = pool[rng.IntN(n)].ID
		}
		mode := ModeFailover
		if rng.IntN(4) == 0 {
			mode = ModePinned
		}

		got := Select(Request{DeviceKey: fmt.Sprintf("d%d", round), Current: current, Mode: mode, Advertisers: pool})

		seen := map[string]bool{}
		for _, c := range got {
			if seen[c.ID] {
				t.Fatalf("round %d: %s offered twice", round, c.ID)
			}
			seen[c.ID] = true

			if c.Admin == AdminDisabled {
				t.Fatalf("round %d: offered disabled advertiser %s", round, c.ID)
			}
			if c.Admin == AdminDraining && c.ID != current {
				t.Fatalf("round %d: offered draining advertiser %s to a device on %q", round, c.ID, current)
			}
			// A pinned group is allowed to keep a failing advertiser, because
			// moving would defeat the point of pinning. Everywhere else, failing
			// advertisers must not be offered.
			if mode == ModePinned && c.ID == current {
				continue
			}
			if c.Health == health.StateUnhealthy || c.Health == health.StateOffline {
				t.Fatalf("round %d: offered %s in state %s", round, c.ID, c.Health)
			}
		}

		// Ordering must be non-decreasing in health class, ignoring the drainer
		// that is deliberately parked at the end.
		lastClass := -1
		for _, c := range got {
			if c.Admin == AdminDraining || (mode == ModePinned && c.ID == current) {
				continue
			}
			if class := healthClass(c.Health); class < lastClass {
				t.Fatalf("round %d: health class went backwards at %s: %v", round, c.ID, ids(got))
			} else {
				lastClass = class
			}
		}
	}
}

func FuzzSelect(f *testing.F) {
	f.Add([]byte{0}, "d1")
	f.Add([]byte{1, 2, 3, 4, 5}, "membership-1")
	f.Add([]byte{255, 255, 255}, "")
	f.Add([]byte{0, 0, 0, 0}, "same-weights-and-priorities")

	f.Fuzz(func(t *testing.T, spec []byte, deviceKey string) {
		if len(spec) == 0 || len(spec) > 64 {
			return
		}

		states := []health.State{
			health.StateUnknown, health.StateOffline, health.StateUnhealthy,
			health.StateDegraded, health.StateHealthy,
		}
		admins := []AdminState{AdminEnabled, AdminDraining, AdminDisabled}

		pool := make([]Advertiser, len(spec))
		for i, b := range spec {
			pool[i] = Advertiser{
				ID:       fmt.Sprintf("a%d", i),
				Priority: int(b % 4),
				Weight:   int(b) - 20,
				Admin:    admins[int(b)%len(admins)],
				Health:   states[int(b)%len(states)],
			}
		}

		req := Request{DeviceKey: deviceKey, Mode: ModeFailover, Advertisers: pool}
		first := ids(Select(req))

		// Selection is a pure function; calling it again cannot disagree.
		if again := ids(Select(req)); fmt.Sprint(first) != fmt.Sprint(again) {
			t.Fatalf("Select is not deterministic:\n %v\n %v", first, again)
		}
		for _, c := range Select(req) {
			if c.Score <= 0 || c.Score != c.Score { // non-positive or NaN
				t.Fatalf("advertiser %s scored %v", c.ID, c.Score)
			}
		}
	})
}

// top names the winning candidate, or "" when a device has no authorised egress.
// It exists only for assertions, so production code is not carrying an accessor
// that nothing ships against.
func top(cs []Candidate) string {
	if len(cs) == 0 {
		return ""
	}
	return cs[0].ID
}
