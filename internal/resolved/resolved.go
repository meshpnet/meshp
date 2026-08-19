// Package resolved points the host's resolver at meshp for the names meshp owns.
//
// Only the mesh domains, and only for the tunnel's own interface. Everything else keeps
// using whatever the machine was already using, which is not a nicety: a resolver that
// captured every query would break split-horizon corporate DNS on the first laptop that
// joined, and would make meshp answerable for the user's entire name resolution — a much
// larger promise than the one being made (ADR-0021).
//
// # Why only systemd-resolved
//
// Because it is the one mechanism with a real undo. `resolvectl revert` puts a link back
// exactly as it was, so the agent can honour Invariant 20 — remove what we installed —
// without keeping a copy of somebody else's configuration and hoping it is still current
// when the time comes.
//
// The alternatives are shared mutable files that other software also edits.
// /etc/resolv.conf is rewritten by NetworkManager, dhclient, containers and the user;
// putting a line in it means either clobbering theirs or parsing and rewriting a file whose
// format has three dialects. ADR-0021 is explicit that a host which cannot configure its
// resolver must say so and leave the system's DNS alone rather than write a file it does not
// know how to put back, and that is what this package does everywhere but here.
package resolved

import (
	"context"
	"net/netip"
)

// Configurer points a host's resolver at an address for a set of domains.
//
// An interface so the agent can be tested without root and without a resolver daemon, and
// so a platform with no implementation is a nil rather than a stub that reports success
// and configures nothing.
type Configurer interface {
	// Configure sends queries for these domains, on this interface, to this address.
	// Called on every reconcile, so it must be idempotent.
	Configure(ctx context.Context, iface string, server netip.AddrPort, domains []string) error

	// Revert puts the interface back as it was. Called when a device leaves a network, and
	// safe to call for an interface that was never configured.
	Revert(ctx context.Context, iface string) error
}
