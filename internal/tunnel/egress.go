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
func (r *Reconciler) applyEgress(ctx context.Context, iface string, want bool, failClosed, preventDNSLeaks bool, relays, excluded []string) []string {
	if !want {
		r.releaseEgress(ctx)
		return nil
	}
	if r.egress == nil {
		r.log.Error("this device is meant to send everything through the tunnel and cannot",
			"hint", "a full tunnel needs policy routing, which this host does not have")
		return []string{"egress"}
	}
	if failClosed && r.lock == nil {
		// Refused rather than downgraded. An administrator asking for fail-closed is asking
		// for the property that traffic never leaves outside the tunnel, and a device that
		// claimed the route while quietly declining to enforce it would report the property
		// and not have it — which is the dishonesty ADR-0011 is written against.
		r.log.Error("this network asks devices to fail closed and this host cannot",
			"hint", "fail-closed egress needs a way to refuse traffic, and this host has none")
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

	if failClosed {
		if err := r.lock.ApplyLock(ctx, iface, carve.Endpoints, carve.Prefixes, preventDNSLeaks); err != nil {
			r.log.Error("cannot refuse egress outside the tunnel; not claiming a default route",
				"error", logx.SafeError(err))
			return []string{"egress"}
		}
	}
	if err := r.egress.Claim(iface, carve.Endpoints, carve.Prefixes); err != nil {
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
			"interface", iface, "fail_closed", failClosed, "dns_leaks_prevented", preventDNSLeaks,
			"kept_direct", len(carve.Prefixes), "endpoints_kept", len(carve.Endpoints))
		if !failClosed {
			// Said plainly, because it is the difference between the product this claims to
			// be and a route that happens to point somewhere. Whoever turned it off should
			// be able to find out from the log that they did.
			r.log.Warn("egress is not failing closed; traffic will leave in the clear if the tunnel drops",
				"reason", "this network's policy says fail_closed is false")
		}
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
	if r.lock != nil {
		if err := r.lock.ApplyLock(ctx, "", nil, nil, false); err != nil && failed == nil {
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

// failClosedFor reads the network's fail-closed policy.
//
// Unspecified means enforced. ADR-0011 makes closed the default for an egress group, and the
// policy is three-state precisely so this can tell "nobody has chosen" from "somebody chose
// to fail open" — a control plane that has never heard of the field would otherwise be
// asking every device to leak, which is the one direction that must never happen by
// omission.
func failClosedFor(tunnel *meshpv1.TunnelConfig) bool {
	return tunnel.GetFailClosedPolicy() != meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED
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
	DNS() *meshpv1.DnsConfig
}

// relayEndpointsOf lists the relay addresses a claim must keep reachable.
func relayEndpointsOf(relays *meshpv1.RelayConfig) []string {
	var out []string
	for _, relay := range relays.GetRelays() {
		out = append(out, relay.GetEndpoints()...)
	}
	return out
}
