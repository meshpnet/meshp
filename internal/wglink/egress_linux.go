//go:build linux

package wglink

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
func (r *Router) Claim(iface string) error {
	if err := SetEgressMark(iface, EgressMark); err != nil {
		return err
	}
	return ClaimDefaultRoute(iface, EgressMark)
}

// Release gives the routing back.
func (r *Router) Release() error { return ReleaseDefaultRoute(EgressMark) }

// EgressHeld reports whether a claim from a previous life is still in place.
func EgressHeld() (bool, error) { return DefaultRouteClaimed(EgressMark) }
