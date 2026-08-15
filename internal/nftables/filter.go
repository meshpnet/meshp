package nftables

import (
	"context"
	"net/netip"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// Filter enforces packet filters through nftables. It satisfies tunnel.Filter.
type Filter struct{}

// New returns a Filter, or nothing when this host cannot enforce one.
//
// Nil rather than an error, and checked once at construction rather than on every apply:
// the answer decides what the agent claims in its capabilities, and a capability that
// flapped between reconciles would be worse than one that is simply false.
func New(ctx context.Context) *Filter {
	if !Available(ctx) {
		return nil
	}
	return &Filter{}
}

// Apply renders and loads a filter, or removes the ruleset when there is none.
func (f *Filter) Apply(ctx context.Context, iface string, filter *meshpv1.PacketFilter) error {
	script, err := Render(iface, filter)
	if err != nil {
		return err
	}
	return Apply(ctx, script)
}

// ApplyLock makes this device refuse egress that does not go through the tunnel, or stops
// it refusing.
//
// An empty interface name removes the lock. That is the only way it comes off from here —
// the rules are system state and outlive this process on purpose (ADR-0011), so nothing
// about the agent exiting takes them away.
func (f *Filter) ApplyLock(ctx context.Context, iface string, endpoints []netip.AddrPort, excluded []netip.Prefix) error {
	script, err := RenderLock(LockSpec{Interface: iface, Endpoints: endpoints, Excluded: excluded})
	if err != nil {
		return err
	}
	return Apply(ctx, script)
}

// ApplyForward makes this host carry what it has been assigned, or stop carrying.
//
// Forwarding is enabled before the rules rather than after: rules that permit forwarding on
// a host whose kernel will not forward are correct and do nothing, and the gap between the
// two would be a window where a gateway looks configured and drops everything.
func (f *Filter) ApplyForward(ctx context.Context, iface string, groups []*meshpv1.AdvertisedRoutes_Group) error {
	if len(groups) > 0 {
		if _, err := EnableForwarding(); err != nil {
			return err
		}
	}
	script, err := RenderForward(iface, groups)
	if err != nil {
		return err
	}
	return Apply(ctx, script)
}
