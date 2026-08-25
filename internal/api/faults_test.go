package api

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/session"
	"github.com/meshpnet/meshp/internal/store"
)

func codes(faults []Fault) []string {
	out := make([]string, 0, len(faults))
	for _, f := range faults {
		out = append(out, f.Code)
	}
	return out
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The rules that decide whether somebody is alarmed. They had no tests at all while they
// lived in the page, because there is no JavaScript toolchain to run any (ADR-0023).
func TestWhatCountsAsABrokenDevice(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	ackedAt := now.Add(-time.Minute)

	settled := func(tunnel session.TunnelState) *session.Connected {
		return &session.Connected{ConnectedAt: now.Add(-time.Hour), Tunnel: tunnel}
	}

	for _, tc := range []struct {
		name   string
		device store.OverviewDevice
		live   *session.Connected

		// elsewhere is whether another replica holds this device's session, which is
		// what the database knows and this process does not.
		elsewhere bool
		want      []string
	}{
		{
			name:   "a device with nothing wrong",
			device: store.OverviewDevice{State: "active", LastAckAt: &ackedAt},
			live:   settled(session.TunnelState{Peers: 3, Handshaked: 3, Talking: 3}),
			want:   nil,
		},
		{
			name: "components it could not apply",
			device: store.OverviewDevice{
				State: "active", LastAckAt: &ackedAt, Unapplied: []string{"route-groups", "dns"},
			},
			live: settled(session.TunnelState{Peers: 1, Handshaked: 1}),
			want: []string{faultUnapplied},
		},
		{
			name:   "enrolled and never heard from",
			device: store.OverviewDevice{State: "active"},
			live:   nil,
			want:   []string{faultNeverApplied},
		},
		{
			// A revoked membership is doing what was asked of it. Reporting it as broken
			// would put an operator's own decision in front of them as a fault.
			name:   "a revoked membership is not a device in trouble",
			device: store.OverviewDevice{State: "revoked"},
			live:   nil,
			want:   nil,
		},
		{
			name:   "a tunnel that has never carried anything",
			device: store.OverviewDevice{State: "active", LastAckAt: &ackedAt},
			live:   settled(session.TunnelState{Peers: 4}),
			want:   []string{faultTunnelNeverCarried},
		},
		{
			// WireGuard renews a handshake when traffic flows, so a quiet peer looks stale
			// and is fine. Only "never" is a fault.
			name:   "a quiet tunnel is not a dead one",
			device: store.OverviewDevice{State: "active", LastAckAt: &ackedAt},
			live:   settled(session.TunnelState{Peers: 4, Handshaked: 4}),
			want:   nil,
		},
		{
			// A device reports its data plane the moment it applies state, before there
			// has been time for a handshake. Without the grace every join would report a
			// dead tunnel until it stopped being wrong.
			name:   "a tunnel seconds old has not failed, it has not started",
			device: store.OverviewDevice{State: "active", LastAckAt: &ackedAt},
			live:   &session.Connected{ConnectedAt: now.Add(-5 * time.Second), Tunnel: session.TunnelState{Peers: 4}},
			want:   nil,
		},
		{
			// Connected, so it is applying state; it just has no peers to talk to.
			name:   "a device alone in its network is not broken",
			device: store.OverviewDevice{State: "active", LastAckAt: &ackedAt},
			live:   settled(session.TunnelState{}),
			want:   nil,
		},
		{
			name: "several things at once",
			device: store.OverviewDevice{
				State: "active", LastAckAt: &ackedAt,
				Unapplied: []string{"peers"}, LastError: "nftables: could not carry 192.168.1.0/24",
			},
			live: settled(session.TunnelState{Peers: 2}),
			want: []string{faultUnapplied, faultLastError, faultTunnelNeverCarried},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codes(deviceFaults(tc.device, tc.live, tc.elsewhere, now))
			if len(tc.want) == 0 && len(got) == 0 {
				return
			}
			if !same(got, tc.want) {
				t.Errorf("faults = %v, want %v", got, tc.want)
			}
		})
	}
}

func advertiser(admin, health string) store.OverviewAdvertiser {
	return store.OverviewAdvertiser{MembershipID: uuid.New(), AdminState: admin, Health: health}
}

func TestWhatCountsAsABrokenRouteGroup(t *testing.T) {
	for _, tc := range []struct {
		name        string
		advertisers []store.OverviewAdvertiser
		want        []string
	}{
		{
			name:        "nobody is offering to carry it",
			advertisers: nil,
			want:        []string{faultNoAdvertisers},
		},
		{
			name:        "one healthy candidate is enough",
			advertisers: []store.OverviewAdvertiser{advertiser("enabled", "healthy"), advertiser("disabled", "healthy")},
			want:        nil,
		},
		{
			// Nobody has reported on it, which is not the same as knowing it is down.
			name:        "an unproven candidate still counts as a candidate",
			advertisers: []store.OverviewAdvertiser{advertiser("enabled", "")},
			want:        nil,
		},
		{
			// Degraded is carrying, badly. The group is not out.
			name:        "a degraded candidate still counts",
			advertisers: []store.OverviewAdvertiser{advertiser("enabled", "degraded")},
			want:        nil,
		},
		{
			name: "every candidate is out of action",
			advertisers: []store.OverviewAdvertiser{
				advertiser("enabled", "unhealthy"), advertiser("draining", "healthy"),
				advertiser("disabled", "healthy"), advertiser("enabled", "offline"),
			},
			want: []string{faultNoViableAdvertiser},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codes(groupFaults(store.OverviewGroup{Advertisers: tc.advertisers}))
			if len(tc.want) == 0 && len(got) == 0 {
				return
			}
			if !same(got, tc.want) {
				t.Errorf("faults = %v, want %v", got, tc.want)
			}
		})
	}
}

// An advertiser whose control session has dropped may still be carrying, because an agent
// keeps forwarding from the state it last applied (ADR-0008). Calling the group broken on
// that basis would raise an alarm for a control-plane outage rather than a data-plane one.
func TestADroppedControlSessionDoesNotBreakARouteGroup(t *testing.T) {
	group := store.OverviewGroup{Advertisers: []store.OverviewAdvertiser{advertiser("enabled", "healthy")}}
	if faults := groupFaults(group); len(faults) != 0 {
		t.Errorf("faults = %v, want none: liveness is not part of this rule", codes(faults))
	}
}

// A device connected to another replica is not a device that has never been heard from.
//
// The two look identical to a control plane that only knows its own sessions, which is what
// made this wrong: `live == nil` meant "we have no heartbeat data", and it was being read as
// "nobody does". On a two-replica deployment that turns roughly half the devices into
// reported faults about installations that are working.
func TestADeviceHeldByAnotherReplicaIsNotAFault(t *testing.T) {
	now := time.Now().UTC()
	device := store.OverviewDevice{State: "active"} // no LastAckAt: it has acknowledged nothing yet

	// What this replica sees for a device attached to the one next door: no session of its
	// own, and no acknowledgement in the database yet.
	elsewhere := codes(deviceFaults(device, nil, true, now))
	for _, code := range elsewhere {
		if code == faultNeverApplied {
			t.Error("a device connected to another replica was reported as never having " +
				"applied any configuration")
		}
	}

	// And the fault still fires for a device that genuinely is not talking to anybody,
	// which is the case it exists for.
	if got := codes(deviceFaults(device, nil, false, now)); !same(got, []string{faultNeverApplied}) {
		t.Errorf("a device connected nowhere = %v, want %v", got, []string{faultNeverApplied})
	}
}
