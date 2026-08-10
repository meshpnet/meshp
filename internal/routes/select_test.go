package routes

import (
	"fmt"
	"testing"

	"github.com/meshpnet/meshp/internal/health"
)

func adv(id string, priority int, h health.State) Advertiser {
	return Advertiser{ID: id, Priority: priority, Weight: 100, Admin: AdminEnabled, Health: h}
}

func ids(cs []Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}

func TestSelectDropsUnusableAdvertisers(t *testing.T) {
	// Invariant 8, stated directly: nothing observably failing is ever offered,
	// and neither is anything an operator has disabled.
	got := Select(Request{
		DeviceKey: "device-1",
		Mode:      ModeFailover,
		Advertisers: []Advertiser{
			adv("healthy", 1, health.StateHealthy),
			adv("unhealthy", 1, health.StateUnhealthy),
			adv("offline", 1, health.StateOffline),
			{ID: "disabled", Priority: 1, Weight: 100, Admin: AdminDisabled, Health: health.StateHealthy},
		},
	})

	if len(got) != 1 || got[0].ID != "healthy" {
		t.Errorf("Select = %v, want only [healthy]", ids(got))
	}
}

func TestUnhealthyCurrentAdvertiserIsDropped(t *testing.T) {
	// The whole point of failover: an advertiser being the current assignment is
	// no reason to keep offering it once it is failing.
	got := Select(Request{
		DeviceKey: "device-1",
		Current:   "broken",
		Mode:      ModeFailover,
		Advertisers: []Advertiser{
			adv("broken", 1, health.StateUnhealthy),
			adv("spare", 2, health.StateHealthy),
		},
	})
	if len(got) != 1 || got[0].ID != "spare" {
		t.Errorf("Select = %v, want only [spare]", ids(got))
	}
}

func TestHealthOutranksPriority(t *testing.T) {
	// The operator's priority orders advertisers that both work. It is not a
	// reason to prefer a questionable advertiser over a healthy one — and because
	// the result is a list, the degraded one is still there as a fallback.
	got := Select(Request{
		DeviceKey: "device-1",
		Mode:      ModeFailover,
		Advertisers: []Advertiser{
			adv("tier1-degraded", 1, health.StateDegraded),
			adv("tier2-healthy", 2, health.StateHealthy),
			adv("tier3-unknown", 3, health.StateUnknown),
		},
	})

	want := []string{"tier2-healthy", "tier1-degraded", "tier3-unknown"}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("Select = %v, want %v", ids(got), want)
		}
	}
}

func TestPriorityOrdersEqualHealth(t *testing.T) {
	got := Select(Request{
		DeviceKey: "device-1",
		Mode:      ModeFailover,
		Advertisers: []Advertiser{
			adv("third", 3, health.StateHealthy),
			adv("first", 1, health.StateHealthy),
			adv("second", 2, health.StateHealthy),
		},
	})
	want := []string{"first", "second", "third"}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("Select = %v, want %v", ids(got), want)
		}
	}
}

// Unknown advertisers must be selectable. On a fresh deployment every advertiser
// is unknown, and refusing to offer any of them would mean the network has no
// egress until health checks accumulate.
func TestUnknownIsSelectableButRanksLast(t *testing.T) {
	got := Select(Request{
		DeviceKey:   "device-1",
		Mode:        ModeFailover,
		Advertisers: []Advertiser{adv("fresh", 1, health.StateUnknown)},
	})
	if len(got) != 1 || got[0].ID != "fresh" {
		t.Fatalf("a brand new deployment has no egress: Select = %v", ids(got))
	}
}

func TestDrainingIsOfferedOnlyToItsCurrentHolders(t *testing.T) {
	advertisers := []Advertiser{
		{ID: "draining", Priority: 1, Weight: 100, Admin: AdminDraining, Health: health.StateHealthy},
		adv("spare", 2, health.StateHealthy),
	}

	// A device already on the drainer keeps it as a fallback, ranked last, so it
	// moves to the spare at its next reconciliation rather than being cut off.
	onDrainer := Select(Request{DeviceKey: "d1", Current: "draining", Mode: ModeFailover, Advertisers: advertisers})
	want := []string{"spare", "draining"}
	if len(onDrainer) != 2 || onDrainer[0].ID != want[0] || onDrainer[1].ID != want[1] {
		t.Errorf("device on the drainer: Select = %v, want %v", ids(onDrainer), want)
	}

	// Anyone else never sees it. This is what makes maintenance possible without
	// an outage.
	other := Select(Request{DeviceKey: "d2", Mode: ModeFailover, Advertisers: advertisers})
	if len(other) != 1 || other[0].ID != "spare" {
		t.Errorf("other device: Select = %v, want only [spare]", ids(other))
	}
}

func TestPinnedModeDoesNotMove(t *testing.T) {
	advertisers := []Advertiser{
		adv("pinned", 1, health.StateUnhealthy),
		adv("healthy-alternative", 1, health.StateHealthy),
	}

	// A pinned group deliberately stays put even when its advertiser is failing:
	// the customer allowlisted this outbound address, and arriving from a
	// different one would be rejected by the destination anyway.
	got := Select(Request{DeviceKey: "d1", Current: "pinned", Mode: ModePinned, Advertisers: advertisers})
	if len(got) != 1 || got[0].ID != "pinned" {
		t.Errorf("pinned Select = %v, want only [pinned]", ids(got))
	}

	// With no assignment yet there is nothing to pin to, so a first choice is
	// made normally.
	fresh := Select(Request{DeviceKey: "d1", Mode: ModePinned, Advertisers: advertisers})
	if len(fresh) == 0 || fresh[0].ID != "healthy-alternative" {
		t.Errorf("first pinned assignment = %v, want healthy-alternative first", ids(fresh))
	}
}

func TestPinnedModeStillHonoursDisabled(t *testing.T) {
	// Pinning must not override an operator taking a machine out of service.
	got := Select(Request{
		DeviceKey: "d1",
		Current:   "pinned",
		Mode:      ModePinned,
		Advertisers: []Advertiser{
			{ID: "pinned", Priority: 1, Weight: 100, Admin: AdminDisabled, Health: health.StateHealthy},
			adv("spare", 1, health.StateHealthy),
		},
	})
	if len(got) != 1 || got[0].ID != "spare" {
		t.Errorf("Select = %v, want only [spare]", ids(got))
	}
}

func TestNoUsableAdvertisersReturnsEmpty(t *testing.T) {
	got := Select(Request{
		DeviceKey:   "d1",
		Mode:        ModeFailover,
		Advertisers: []Advertiser{adv("a", 1, health.StateUnhealthy), adv("b", 1, health.StateOffline)},
	})
	if len(got) != 0 {
		t.Errorf("Select = %v, want empty", ids(got))
	}
}

func TestZeroWeightIsTreatedAsOne(t *testing.T) {
	// A misconfigured weight must not remove an advertiser from consideration or
	// produce a NaN score that corrupts the sort.
	got := Select(Request{
		DeviceKey:   "d1",
		Mode:        ModeFailover,
		Advertisers: []Advertiser{{ID: "zero", Weight: 0, Admin: AdminEnabled, Health: health.StateHealthy}},
	})
	if len(got) != 1 {
		t.Fatalf("Select = %v, want one candidate", ids(got))
	}
	if s := got[0].Score; s <= 0 || isNaN(s) {
		t.Errorf("Score = %v, want a positive finite number", s)
	}
}

func isNaN(f float64) bool { return f != f }

func TestSelectDoesNotMutateInput(t *testing.T) {
	advertisers := []Advertiser{
		adv("c", 3, health.StateHealthy),
		adv("a", 1, health.StateHealthy),
		adv("b", 2, health.StateHealthy),
	}
	before := ids(candidatesOf(advertisers))
	Select(Request{DeviceKey: "d1", Mode: ModeFailover, Advertisers: advertisers})
	if after := ids(candidatesOf(advertisers)); fmt.Sprint(before) != fmt.Sprint(after) {
		t.Errorf("Select reordered its input: %v became %v", before, after)
	}
}

func candidatesOf(as []Advertiser) []Candidate {
	out := make([]Candidate, len(as))
	for i, a := range as {
		out[i] = Candidate{Advertiser: a}
	}
	return out
}
