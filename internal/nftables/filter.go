package nftables

import (
	"context"
	"fmt"
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
func (f *Filter) ApplyLock(ctx context.Context, iface string, endpoints []netip.AddrPort, excluded []netip.Prefix, preventDNSLeaks bool) error {
	script, err := RenderLock(LockSpec{
		Interface: iface, Endpoints: endpoints, Excluded: excluded,
		PreventDNSLeaks: preventDNSLeaks,
	})
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
	if err := Apply(ctx, script); err != nil {
		return err
	}

	// And a way past anything else that refuses forwarded packets (#89). meshp's own
	// accept cannot undo another table's drop, so this puts one where it counts. A host
	// with nothing in the way is untouched: ApplyCarry does nothing when there is no
	// iptables-style filter table, which is exactly the host with no foreign policy.
	carried, err := carriedPrefixList(groups)
	if err != nil {
		return err
	}
	return ApplyCarry(ctx, iface, carried)
}

// carriedPrefixList is what this device forwards into, as prefixes.
//
// A default route is left out. An egress group carries 0.0.0.0/0, and accepting that in the
// host's own FORWARD chain would turn meshp into a blanket exemption from a policy somebody
// wrote on purpose — far past what carrying a customer's LAN needs.
func carriedPrefixList(groups []*meshpv1.AdvertisedRoutes_Group) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, g := range groups {
		for _, raw := range g.GetPrefixes() {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("nftables: a carried prefix will not parse: %q", raw)
			}
			if p.Bits() == 0 {
				continue
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

// ForwardObstacles names anything else on this host that drops forwarded packets.
//
// A thin wrapper on ForwardRefusals so the reconciler can hold one interface rather than
// reaching into this package for the one call that is not an Apply.
func (f *Filter) ForwardObstacles(ctx context.Context) ([]string, error) {
	found, err := ForwardRefusals(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(found))
	for _, r := range found {
		out = append(out, r.String())
	}
	return out, nil
}

// ApplyMap makes this host reach colliding prefixes at the ranges allocated for them.
//
// Rebuilt whole on every call, like the other tables here: the ruleset is one nft transaction
// and replacing it is atomic, so there is no moment where half a device's mappings are in
// force. An empty map removes the table, which is what a device that stopped colliding needs
// (Invariant 20).
func (f *Filter) ApplyMap(ctx context.Context, iface string, mapped map[netip.Prefix]netip.Prefix) error {
	mappings := make([]Mapping, 0, len(mapped))
	for real, to := range mapped {
		mappings = append(mappings, Mapping{Mapped: to, Real: real})
	}
	script, err := RenderMap(iface, mappings)
	if err != nil {
		return err
	}
	return Apply(ctx, script)
}
