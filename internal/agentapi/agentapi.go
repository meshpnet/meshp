// Package agentapi is the local interface between meshp and meshpd.
//
// It exists because of a privilege boundary. meshpd runs as root and owns the
// device's private keys; meshp is a command an ordinary user types. Everything that
// touches a key or the network stack has to happen on the daemon's side of that
// line, so the CLI asks rather than acts.
//
// Until this existed, `meshp join` generated the keys and wrote them itself, which
// made an unprivileged command responsible for material that belongs to a privileged
// process. That is the loose end this closes.
//
// The transport is HTTP over a unix socket. Not because HTTP is elegant here, but
// because it is inspectable: when something is wrong at three in the morning,
// `curl --unix-socket /var/run/meshpd.sock http://local/v1/status` works and a custom
// framing does not.
package agentapi

import (
	"time"

	"github.com/google/uuid"
)

// DefaultSocketPath is where the daemon listens.
const DefaultSocketPath = "/var/run/meshpd.sock"

// Status is what the daemon reports about itself.
type Status struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`

	// Enrolled is false when there is no local state at all, which is a normal
	// condition rather than an error: the agent may be installed before anyone has a
	// token.
	Enrolled bool `json:"enrolled"`

	// IdentityPublicKey is the device's stable name, shared by every membership
	// (ADR-0006). Public, so safe to report.
	IdentityPublicKey string `json:"identity_public_key,omitempty"`

	// Resolver is where this device answers names, or empty when it is not answering.
	//
	// Reported because the port is the kernel's choice — 53 is almost always taken — so
	// this is the only way anybody finds it, whether that is a person running `dig` or
	// the code that will configure the system resolver.
	Resolver string `json:"resolver,omitempty"`

	// ResolverSuffixes are the domains it can answer for, across every network. Worth
	// showing beside the address: a name that will not resolve is usually a name under a
	// suffix that is not in this list.
	ResolverSuffixes []string `json:"resolver_suffixes,omitempty"`

	Memberships []MembershipStatus `json:"memberships"`
}

// MembershipStatus is one network this device belongs to.
type MembershipStatus struct {
	MembershipID uuid.UUID `json:"membership_id"`
	NetworkID    uuid.UUID `json:"network_id"`
	DeviceID     uuid.UUID `json:"device_id"`
	ControlURL   string    `json:"control_url"`

	InterfaceName string `json:"interface_name"`
	AddressV4     string `json:"address_v4,omitempty"`
	AddressV6     string `json:"address_v6,omitempty"`

	// WireGuardPublicKey only. The private half never crosses this socket, or any
	// other (Invariant 1).
	WireGuardPublicKey string `json:"wireguard_public_key"`

	// Connected and AppliedStateVersion come from the live session rather than from
	// disk, which is the reason to ask the daemon instead of reading the state file:
	// the file cannot tell you whether the control plane is reachable right now.
	Connected           bool      `json:"connected"`
	ConnectedSince      time.Time `json:"connected_since,omitzero"`
	AppliedStateVersion int64     `json:"applied_state_version"`
	LastError           string    `json:"last_error,omitempty"`

	JoinedAt time.Time `json:"joined_at"`

	// TunnelUp is whether a WireGuard interface is configured and up for this
	// membership. A membership with an address and no tunnel is a normal state, and
	// status must not imply otherwise.
	TunnelUp bool `json:"tunnel_up"`

	// ListenPort is the UDP port the interface listens on. Zero when there is no tunnel.
	//
	// Reported because an operator opening a firewall or a port forward needs it, and
	// because it is what peers will be told once endpoints are distributed.
	ListenPort int `json:"listen_port,omitempty"`

	// TunnelKind is which WireGuard implementation is behind the interface: "kernel" or
	// "userspace". Empty when there is no tunnel.
	//
	// Reported because the difference is large and otherwise invisible (ADR-0015). An
	// operator asking why one host is a fraction of another's throughput should be able
	// to see the answer instead of inferring it.
	TunnelKind string `json:"tunnel_kind,omitempty"`

	// Relay is how this device reaches peers it has no direct path to, which today is all
	// of them (ADR-0002). Nil where there is no data plane to relay into.
	Relay *RelayStatus `json:"relay,omitempty"`
}

// RelayStatus is what an operator needs when relaying is not working.
//
// Deliberately more than "connected". The ways this fails are different problems with
// different fixes — the control plane declining to issue a credential, a relay that cannot
// be reached, a relay reached but delivering nothing — and a single boolean makes them
// indistinguishable from here.
type RelayStatus struct {
	// RelayID and Endpoints are what desired state asked for. Reported even when nothing is
	// connected: "configured for relay1 and cannot reach it" and "never told about a relay"
	// are different problems.
	RelayID   string   `json:"relay_id,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`

	Connected      bool      `json:"connected"`
	ConnectedSince time.Time `json:"connected_since,omitzero"`

	// Endpoint is the relay address that answered, which may not be the first one offered.
	Endpoint string `json:"endpoint,omitempty"`

	// Reflexive is the address the relay sees this device at — the one thing nothing else
	// can report, and the first evidence of what kind of NAT this device is behind.
	Reflexive string `json:"reflexive,omitempty"`

	// HasToken and TokenExpiresAt separate "not authorised" from "cannot connect".
	HasToken       bool      `json:"has_token"`
	TokenExpiresAt time.Time `json:"token_expires_at,omitzero"`

	// Refusal is why the control plane declined to issue one, if it did.
	Refusal   string `json:"refusal,omitempty"`
	LastError string `json:"last_error,omitempty"`

	// PeersRelayed is how many peers are reached this way.
	PeersRelayed int `json:"peers_relayed"`

	// Counters, because "the tunnel is up and nothing works" needs a direction. Packets
	// leaving and none arriving is a different fault from neither.
	PacketsRelayed   uint64 `json:"packets_relayed"`
	PacketsDelivered uint64 `json:"packets_delivered"`
	Dropped          uint64 `json:"dropped"`
}

// JoinRequest asks the daemon to enrol this device.
type JoinRequest struct {
	Token      string `json:"token"`
	ControlURL string `json:"control_url"`
	// Name defaults to the host's name when empty.
	Name string `json:"name,omitempty"`
}

// JoinResponse is what the daemon assigned.
type JoinResponse struct {
	MembershipID  uuid.UUID `json:"membership_id"`
	NetworkID     uuid.UUID `json:"network_id"`
	DeviceID      uuid.UUID `json:"device_id"`
	InterfaceName string    `json:"interface_name"`
	AddressV4     string    `json:"address_v4,omitempty"`
	AddressV6     string    `json:"address_v6,omitempty"`
}

// Error is how the daemon reports a refusal.
type Error struct {
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}
