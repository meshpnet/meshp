package tunnel

import (
	"context"
	"net/netip"

	"github.com/meshpnet/meshp/internal/egress"
	"github.com/meshpnet/meshp/internal/logx"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// applyEgress claims or releases a full tunnel.
//
// The order is the safety property, and it reverses on the way out.
//
// Claiming: work out what must stay reachable, install the lock, and only then take the
// default route. ADR-0011 requires the lock before the route because the gap between them is
// a device sending the user's traffic in clear over whatever network it happens to be on, at
// the moment it believes it is protected.
//
// Releasing: routing first, then the lock. A lock still in place with the route gone refuses
// everything and the machine has no network; a route still in place with the lock gone leaks
// until the lock goes. Neither is good and the first is worse.
//
// Nothing here is best effort. If the carve-out cannot be computed the group is unhonoured
// and no lock is installed, because a device that locks itself away from its control plane
// is off the network for a reason nobody watching can see.
func (r *Reconciler) applyEgress(ctx context.Context, iface string, want bool, relays, excluded []string) []string {
	if !want {
		r.releaseEgress(ctx)
		return nil
	}
	if r.egress == nil || r.filter == nil {
		r.log.Error("this device is meant to send everything through the tunnel and cannot",
			"hint", "a full tunnel needs policy routing and a packet filter; this host has one or neither")
		return []string{"egress"}
	}

	// Two sources, because neither knows enough alone. The control plane sends the
	// exclusions only it can work out — the exit's own endpoint, prefixes an administrator
	// named — and the device adds the ones only it can see: the network it is attached to,
	// and the link-local world underneath it.
	carve, err := egress.Compute(ctx, egress.Inputs{
		ControlURL:     r.membership.ControlURL,
		RelayEndpoints: relays,
		LocalPrefixes:  egress.LocalNetworks(iface),
		ExtraPrefixes:  excluded,
	}, nil)
	if err != nil {
		// The branch that decides whether a mistake here costs a feature or a machine.
		r.log.Error("not claiming a default route",
			"error", logx.SafeError(err),
			"consequence", "this device would have had no way back to its control plane")
		return []string{"egress"}
	}

	if err := r.filter.ApplyLock(ctx, iface, carve.Endpoints, carve.Prefixes); err != nil {
		r.log.Error("cannot refuse egress outside the tunnel; not claiming a default route",
			"error", logx.SafeError(err))
		return []string{"egress"}
	}
	if err := r.egress.Claim(iface); err != nil {
		// The lock is on and the route is not, which is the safe half of a half-done claim:
		// the device sends nothing rather than sending it the wrong way. Taking the lock off
		// again would restore the leak it was installed to prevent, so it stays, the group is
		// unhonoured, and the next pass tries the claim again.
		r.log.Error("cannot claim the default route; egress stays refused",
			"error", logx.SafeError(err))
		return []string{"egress"}
	}

	if !r.claimed {
		r.log.Info("this device now sends everything through the tunnel",
			"interface", iface,
			"kept_direct", len(carve.Prefixes), "endpoints_kept", len(carve.Endpoints))
	}
	r.claimed = true
	return nil
}

// releaseEgress undoes a claim, if this reconciler made one.
func (r *Reconciler) releaseEgress(ctx context.Context) {
	if !r.claimed {
		return
	}

	var failed error
	if r.egress != nil {
		failed = r.egress.Release()
	}
	// The lock comes off even when the routing did not, and its error is kept only if
	// nothing else failed first. Leaving a lock behind because a route would not release is
	// how a device ends up refusing everything with no explanation.
	if r.filter != nil {
		if err := r.filter.ApplyLock(ctx, "", nil, nil); err != nil && failed == nil {
			failed = err
		}
	}
	if failed != nil {
		r.log.Error("could not stop sending everything through the tunnel",
			"error", logx.SafeError(failed),
			"consequence", "this device may have no egress until meshpd restarts and reclaims")
		return
	}

	r.claimed = false
	r.log.Info("no longer sending everything through the tunnel")
}

// wantsEgress reports whether any assigned group asks for a default route, and what the
// control plane says must stay off it.
func wantsEgress(state routeGroupSource) (bool, []string) {
	want := false
	for _, group := range state.RouteGroups() {
		for _, raw := range group.GetPrefixes() {
			if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Bits() == 0 {
				want = true
			}
		}
	}
	return want, state.Tunnel().GetExcludedPrefixes()
}

// routeGroupSource is the part of desired state a claim reads.
type routeGroupSource interface {
	RouteGroups() []*meshpv1.RouteGroupAssignment
	Tunnel() *meshpv1.TunnelConfig
}

// relayEndpointsOf lists the relay addresses a claim must keep reachable.
func relayEndpointsOf(relays *meshpv1.RelayConfig) []string {
	var out []string
	for _, relay := range relays.GetRelays() {
		out = append(out, relay.GetEndpoints()...)
	}
	return out
}
