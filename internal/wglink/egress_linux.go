//go:build linux

package wglink

import (
	"fmt"
	"net/netip"
)

// Router claims and releases a full tunnel's routing. It satisfies tunnel.Egress.
//
// A type rather than the bare functions so the mark stays an implementation detail: the
// reconciler decides whether this device sends everything through the tunnel, and has no
// business knowing how the tunnel's own packets are told apart from everything else.
type Router struct{}

// NewRouter returns something that can claim a default route, or nothing where the platform
// cannot. Nil rather than a stub, so a device asked for a full tunnel it cannot deliver
// reports the group unhonoured instead of pretending.
func NewRouter() *Router { return &Router{} }

// Claim marks the tunnel's own traffic and sends everything else through it.
//
// The mark first. A rule that exempts marked traffic exempts nothing until something is
// marking it, and in that gap the tunnel's own packets are routed into the tunnel.
//
// The carve-out is ignored here, and that is the whole difference between this and the
// macOS implementation. A mark exempts the tunnel's own packets whatever their destination,
// so Linux does not need to be told which addresses those are — and enumerating them would
// be worse than the mark, because an endpoint that roamed between passes would be routed
// into the tunnel until the next one. The lock still needs them; the routing does not.
func (r *Router) Claim(iface string, _ []netip.AddrPort, _ []netip.Prefix) error {
	if err := SetEgressMark(iface, EgressMark); err != nil {
		return err
	}
	return ClaimDefaultRoute(iface, EgressMark)
}

// Release gives the routing back.
func (r *Router) Release() error { return ReleaseDefaultRoute(EgressMark) }

// EgressHeld reports whether a claim from a previous life is still in place.
func EgressHeld() (bool, error) { return DefaultRouteClaimed(EgressMark) }

// egressUndo removes the rule and the table this platform's claim installs.
func egressUndo() []string {
	return []string{
		fmt.Sprintf("sudo ip rule del fwmark %#x", EgressMark),
		fmt.Sprintf("sudo ip route flush table %d", EgressTable),
	}
}
