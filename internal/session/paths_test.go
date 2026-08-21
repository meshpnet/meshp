package session

import (
	"testing"
	"time"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func path(kind meshpv1.PathReport_PeerPath_Kind, handshake int64) *meshpv1.PathReport_PeerPath {
	return &meshpv1.PathReport_PeerPath{Kind: kind, LastHandshakeUnix: handshake}
}

// The counts, and the distinctions between them that the page depends on.
func TestSummarisingAPathReport(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-30 * time.Second).Unix()
	stale := now.Add(-2 * time.Hour).Unix()

	for _, tc := range []struct {
		name  string
		paths []*meshpv1.PathReport_PeerPath
		want  TunnelState
	}{
		{
			name:  "a working tunnel",
			paths: []*meshpv1.PathReport_PeerPath{path(directKind, fresh), path(relayKind, fresh)},
			want:  TunnelState{Peers: 2, Handshaked: 2, Talking: 2, Relayed: 1},
		},
		{
			// The case the whole thing exists for: peers configured, nothing ever
			// established. Reported as a fault; every other row here is not.
			name:  "a tunnel that has never carried anything",
			paths: []*meshpv1.PathReport_PeerPath{path(directKind, 0), path(directKind, 0)},
			want:  TunnelState{Peers: 2},
		},
		{
			// Quiet, not broken. WireGuard renews a handshake when traffic flows, so an
			// idle peer with no keepalive looks like this and is fine.
			name:  "a quiet peer still counts as having handshaked",
			paths: []*meshpv1.PathReport_PeerPath{path(directKind, stale)},
			want:  TunnelState{Peers: 1, Handshaked: 1},
		},
		{
			// The agent's clock is its own. Counting a future handshake as "never" would
			// report a working tunnel as one that has never come up, which is the loudest
			// verdict this produces.
			name:  "a handshake from the future is not a handshake that never happened",
			paths: []*meshpv1.PathReport_PeerPath{path(directKind, now.Add(time.Minute).Unix())},
			want:  TunnelState{Peers: 1, Handshaked: 1, Talking: 1},
		},
		{
			name:  "a device with no peers",
			paths: nil,
			want:  TunnelState{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := summarisePaths(&meshpv1.PathReport{Paths: tc.paths}, now)
			if got.ReportedAt != now {
				t.Errorf("ReportedAt = %v, want %v", got.ReportedAt, now)
			}
			got.ReportedAt = time.Time{}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A report that has arrived is distinguishable from one that has not.
//
// The API omits the field entirely when ReportedAt is zero, because "has not said" and "has
// nothing" are different answers and only one of them should render as a device with no
// peers.
func TestAnUnreportedTunnelIsDistinguishableFromAnEmptyOne(t *testing.T) {
	var never TunnelState
	if !never.ReportedAt.IsZero() {
		t.Fatal("a zero TunnelState must have a zero ReportedAt")
	}
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	empty := summarisePaths(&meshpv1.PathReport{}, now)
	if empty.ReportedAt.IsZero() {
		t.Error("a device that reported no peers must still be marked as having reported")
	}
}

const (
	directKind = meshpv1.PathReport_PeerPath_KIND_DIRECT
	relayKind  = meshpv1.PathReport_PeerPath_KIND_RELAY
)
