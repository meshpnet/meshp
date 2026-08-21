package session

import (
	"time"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// pathsFresh is how recent a handshake must be for a peer to count as talking.
//
// WireGuard renews a handshake when traffic flows, and every keepalive interval where one
// is set, so an idle peer with no keepalive goes quiet while being perfectly healthy.
// Nothing here calls a stale handshake a fault for that reason: this bound describes what
// is currently talking, and it is several times the keepalive so one missed renewal does
// not change the answer.
const pathsFresh = 3 * time.Minute

// TunnelState is what a device last said about its own data plane.
//
// A summary rather than the peer list it was computed from. The question this exists to
// answer is "is this device's tunnel carrying anything", and holding every peer of every
// device of every network in memory to answer it would be a per-device cost that grows with
// the square of the network. The detail is in the report; what survives is the count.
//
// In memory only, like every other kind of liveness (ADR-0012). Losing it costs one
// heartbeat's wait, not correctness.
type TunnelState struct {
	// ReportedAt is when this arrived, so a reader can tell a current answer from one left
	// behind by a device that has since gone quiet.
	ReportedAt time.Time

	// Peers is how many peers the interface holds.
	Peers int

	// Handshaked is how many have ever completed a handshake. Zero, with peers configured,
	// is the unambiguous failure: this tunnel has never carried anything. It is the only
	// count here that is treated as a fault.
	Handshaked int

	// Talking is how many handshaked within pathsFresh. Informational, never a fault — a
	// quiet peer is not a broken one.
	Talking int

	// Relayed is how many are reached through a relay rather than directly. Not a fault
	// either: meshp is relay-first and a relayed path is a working path (ADR-0002).
	Relayed int
}

// summarisePaths reduces a report to what presence keeps.
func summarisePaths(report *meshpv1.PathReport, now time.Time) TunnelState {
	state := TunnelState{ReportedAt: now, Peers: len(report.GetPaths())}
	for _, path := range report.GetPaths() {
		if path.GetKind() == meshpv1.PathReport_PeerPath_KIND_RELAY {
			state.Relayed++
		}
		last := path.GetLastHandshakeUnix()
		if last <= 0 {
			continue
		}
		state.Handshaked++
		// Future timestamps count as fresh rather than being discarded. The agent's clock
		// is its own and may be ahead of ours; treating that as "never handshaked" would
		// report a working tunnel as one that has never come up, which is the one verdict
		// here that is loud.
		if now.Sub(time.Unix(last, 0)) < pathsFresh {
			state.Talking++
		}
	}
	return state
}

// handlePathReport records what a device said about its data plane.
//
// Kept in memory and not written to the database. It arrives on every heartbeat from every
// device, which is precisely the write rate ADR-0012 exists to keep off the rows that hold
// desired state, and none of it needs to survive a restart.
func (s *Server) handlePathReport(sess *Session, report *meshpv1.PathReport) {
	sess.setTunnel(summarisePaths(report, s.clk.Now()))
}
