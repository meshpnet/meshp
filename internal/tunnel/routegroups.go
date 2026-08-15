package tunnel

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/routeprobe"
	"github.com/meshpnet/meshp/internal/wgplan"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// applyRouteGroups gives the carried prefixes to the peer that carries them.
//
// Both halves come from one change, which is the point. WireGuard will not accept or send a
// packet for a prefix that is not in a peer's AllowedIPs, and the kernel will not send one
// to the interface without a route — and wgplan derives the routes it installs from exactly
// these AllowedIPs. Adding the prefix in one place therefore produces both, and they cannot
// drift apart.
//
// The best candidate is taken and the rest ignored, for now. The server orders them and the
// agent is meant to choose among them by probing (ADR-0003); until it probes, taking the
// server's first preference is the honest subset of that — it is what the server would have
// chosen, and no worse than having no route at all.
//
// Returns the group names it could not honour, which the caller reports as unapplied rather
// than swallowing: a device quietly not carrying a prefix it was assigned is indistinguishable
// from one that is, right up until somebody tries to use it.
func applyRouteGroups(iface *wgplan.Interface, assignments []*meshpv1.RouteGroupAssignment, chooser *routeprobe.Chooser, log *slog.Logger) []string {
	if len(assignments) == 0 {
		return nil
	}

	byKey := make(map[wgplan.Key]int, len(iface.Peers))
	for i, peer := range iface.Peers {
		byKey[peer.PublicKey] = i
	}

	var unhonoured []string
	for _, assignment := range assignments {
		name := assignment.GetName()

		prefixes, defaultRoute, err := groupPrefixes(assignment)
		if err != nil {
			log.Error("a route group names a prefix this device cannot parse",
				"group", logx.Safe(name), "error", err)
			unhonoured = append(unhonoured, name)
			continue
		}

		if defaultRoute {
			// Both halves, because WireGuard needs one and the routing table must not get
			// the other. A peer carrying a default route needs 0.0.0.0/0 and ::/0 in its
			// allowed IPs or the kernel will not send it anything outside the mesh — but
			// wgplan deliberately derives no system route from a zero-length prefix, since a
			// default route in the main table would capture the outer packets carrying this
			// very tunnel. The system route lives in the egress table instead, installed
			// with the rules that exempt the tunnel's own traffic (ADR-0019).
			prefixes = append(prefixes,
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
		}

		// The chooser's answer, not the server's first preference. The server orders the
		// candidates and the agent decides how far down the list to be (ADR-0003), which is
		// what makes a device fail over without asking the control plane first.
		best := chosenCandidate(chooser, assignment)
		if best == nil {
			// The server withdraws a group nobody can carry rather than sending it empty,
			// so this means the two ends disagree. Reported rather than ignored.
			log.Warn("a route group arrived with no candidates", "group", logx.Safe(name))
			unhonoured = append(unhonoured, name)
			continue
		}
		index, ok := byKey[wgplan.Key(best.GetPeerPublicKey())]
		if !ok {
			// Assigned a carrier that is not in this device's peer list. Nothing can be
			// routed to a peer the interface does not have, and adding one from here would
			// invent a peer the control plane did not send.
			log.Error("the chosen carrier for a route group is not a peer of this device",
				"group", logx.Safe(name), "peer", truncate(best.GetPeerPublicKey()))
			unhonoured = append(unhonoured, name)
			continue
		}

		iface.Peers[index].AllowedIPs = append(iface.Peers[index].AllowedIPs, prefixes...)
		log.Debug("carrying a route group",
			"group", logx.Safe(name), "via", truncate(best.GetPeerPublicKey()),
			"prefixes", len(prefixes))
	}
	return unhonoured
}

// groupPrefixes parses an assignment's prefixes, and reports whether it claims a default
// route.
//
// Parsed here rather than trusted: these reach the kernel's routing table, and a prefix
// this build cannot read must not be approximated into one it can.
func groupPrefixes(assignment *meshpv1.RouteGroupAssignment) (prefixes []netip.Prefix, defaultRoute bool, err error) {
	for _, raw := range assignment.GetPrefixes() {
		prefix, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil {
			return nil, false, fmt.Errorf("prefix %q: %w", logx.Safe(raw), parseErr)
		}
		if prefix.Bits() == 0 {
			return nil, true, nil
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	if len(prefixes) == 0 {
		return nil, false, fmt.Errorf("it carries no prefixes")
	}
	return prefixes, false, nil
}
