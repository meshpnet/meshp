package api

import (
	"strings"
	"time"

	"github.com/meshpnet/meshp/internal/session"
	"github.com/meshpnet/meshp/internal/store"
)

// Fault is something wrong with a device or a route group (ADR-0023).
//
// A code and a message, for the two readers this endpoint has. The code is a stable
// identifier for a consumer that counts or alerts; the message is the sentence a person
// reads, and it lives beside the rule that produced it rather than in whichever client
// happens to be rendering — this project treats the wording of a failure as part of the
// product (ADR-0011), and a wording maintained in two places is a wording that disagrees
// with itself.
//
// Consumers must handle a code they do not recognise by rendering the message. Rules will
// be added, and a client that failed on an unknown one would make every addition a
// breaking change.
type Fault struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Fault codes. Stable: a consumer may key alerts on these.
const (
	// faultUnapplied is the component list a device said it could not apply.
	faultUnapplied = "unapplied_components"
	// faultLastError is whatever the agent reported alongside it.
	faultLastError = "last_error"
	// faultNeverApplied is an enrolled device that has never acknowledged anything.
	faultNeverApplied = "never_applied"
	// faultTunnelNeverCarried is a data plane with peers and no handshake, ever.
	faultTunnelNeverCarried = "tunnel_never_carried"

	// faultNoAdvertisers is a route group nobody offers to carry.
	faultNoAdvertisers = "no_advertisers"
	// faultNoViableAdvertiser is one where every candidate is out of action.
	faultNoViableAdvertiser = "no_viable_advertiser"
)

// tunnelGrace is how long a control session must have been up before a tunnel with no
// handshakes is called dead rather than new.
//
// A device reports its data plane the moment it applies state, when there has been no time
// for a handshake. Without this every join would report a dead tunnel until it stopped
// being wrong. Applied here, against this server's own clock at both ends, because a client
// comparing our timestamp against its own would be wrong by however wrong its clock is.
const tunnelGrace = 2 * time.Minute

// deviceFaults is what is wrong with one device.
//
// Only an active membership can be in trouble. A revoked or suspended one is doing exactly
// what was asked of it, and reporting it as broken would put an operator's own decision in
// front of them as a fault to investigate.
func deviceFaults(d store.OverviewDevice, live *session.Connected, now time.Time) []Fault {
	faults := make([]Fault, 0, 2)
	if d.State != "active" {
		return faults
	}

	if len(d.Unapplied) > 0 {
		faults = append(faults, Fault{
			Code:    faultUnapplied,
			Message: "could not apply: " + strings.Join(d.Unapplied, ", "),
		})
	}
	if d.LastError != "" {
		// The agent's own words, passed through. Rewriting them here would lose the only
		// account of the failure that came from the machine it happened on.
		faults = append(faults, Fault{Code: faultLastError, Message: d.LastError})
	}
	if live == nil && d.LastAckAt == nil {
		// Enrolled and never heard from. Easy to miss in a list of names, and usually an
		// installation that did not finish rather than a device that has gone away.
		faults = append(faults, Fault{
			Code:    faultNeverApplied,
			Message: "has never applied any configuration",
		})
	}

	// The one thing a path report is allowed to call a fault (#117). A device can apply
	// every version it is sent and pass no traffic at all.
	//
	// "Never handshaked", not "handshaked a while ago". WireGuard renews a handshake when
	// traffic flows, so a quiet peer with no keepalive looks stale while being perfectly
	// healthy — but a peer that has never completed one has never carried a packet.
	if live != nil && live.Tunnel.Peers > 0 && live.Tunnel.Handshaked == 0 &&
		now.Sub(live.ConnectedAt) > tunnelGrace {
		faults = append(faults, Fault{
			Code:    faultTunnelNeverCarried,
			Message: "tunnel has never carried anything: no peer has completed a handshake",
		})
	}
	return faults
}

// groupFaults is what is wrong with one route group.
func groupFaults(g store.OverviewGroup) []Fault {
	faults := make([]Fault, 0, 1)
	if len(g.Advertisers) == 0 {
		return append(faults, Fault{
			Code:    faultNoAdvertisers,
			Message: "nothing is offering to carry this",
		})
	}
	for _, a := range g.Advertisers {
		if viableAdvertiser(a) {
			return faults
		}
	}
	return append(faults, Fault{
		Code:    faultNoViableAdvertiser,
		Message: "no candidate can carry this: every advertiser is disabled, draining or unhealthy",
	})
}

// viableAdvertiser reports whether this candidate could carry anything at all.
//
// Deliberately not a function of whether its control session is up. An agent keeps
// forwarding from the state it last applied when the control plane is unreachable
// (ADR-0008), so an advertiser whose session has dropped may well still be carrying, and
// calling the group broken on that basis would raise an alarm for a control-plane outage
// rather than a data-plane one.
//
// Unknown health is not treated as broken either, for the opposite reason: nobody has
// reported on it yet, which is not the same as knowing it is down.
func viableAdvertiser(a store.OverviewAdvertiser) bool {
	if a.AdminState != "enabled" {
		return false
	}
	return a.Health != "unhealthy" && a.Health != "offline"
}
