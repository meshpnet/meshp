// Package resolved points the host's resolver at meshp for the names meshp owns.
//
// Only the mesh domains, and only for the tunnel's own interface. Everything else keeps
// using whatever the machine was already using, which is not a nicety: a resolver that
// captured every query would break split-horizon corporate DNS on the first laptop that
// joined, and would make meshp answerable for the user's entire name resolution — a much
// larger promise than the one being made (ADR-0021).
//
// # What decides whether a platform gets an implementation
//
// One question: is there a real undo? The agent has to honour Invariant 20 — remove what we
// installed — without keeping a copy of somebody else's configuration and hoping it is still
// current when the time comes. ADR-0021 is explicit that a host which cannot manage that
// must say so and leave the system's DNS alone rather than write a file it does not know how
// to put back.
//
// Two platforms pass, for different reasons.
//
// **Linux, through systemd-resolved.** `resolvectl revert` puts a link back exactly as it
// was. The alternatives on Linux do not qualify: /etc/resolv.conf is rewritten by
// NetworkManager, dhclient, containers and the user, so putting a line in it means either
// clobbering theirs or parsing and rewriting a file whose format has three dialects.
//
// **macOS, through the SystemConfiguration dynamic store.** A stronger answer than Linux's,
// and worth stating as such: there is nothing to put back. The store is keyed per service,
// so meshp creates a key that is entirely its own and removes it to undo. Nobody else's
// entry is read, merged or rewritten at any point — where `resolvectl revert` restores
// previous state, this never disturbs any.
//
// What is left unimplemented is Windows and the mobile platforms. The mechanism exists on
// each; nobody has written it, and until somebody does those hosts report that names will
// not resolve rather than pretending.
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
