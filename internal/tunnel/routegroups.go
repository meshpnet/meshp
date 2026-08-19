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
func applyRouteGroups(iface *wgplan.Interface, assignments []*meshpv1.RouteGroupAssignment, chooser *routeprobe.Chooser, claims *Claims, canTranslate bool, log *slog.Logger) []string {
	// Where colliding prefixes are reached, but only on a host that can actually perform the
	// translation. On one that cannot, the mapping is dropped here and the real prefix is
	// claimed instead — so the two memberships contest it and both are refused, exactly as
	// before ADR-0020. A device that installed a route to a mapped range nothing rewrites
	// would blackhole the customer it was meant to reach, which is worse than saying no.
	iface.Mapped = mappedPrefixes(assignments, canTranslate, log)

	// Declared before the early return, so a membership that has been taken out of every
	// route group stops contesting prefixes it no longer carries. Leaving a stale claim
	// behind would keep another membership refused for a network this one has left.
	//
	// What is claimed is what reaches the routing table, which for a mapped prefix is its
	// range and not the customer's own. That is what makes the collision go away rather than
	// needing to be special-cased: two mapped ranges are different, so nothing contests.
	claims.Declare(iface.Name, declaredPrefixes(assignments, iface.Mapped))

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
		// Another membership on this device carrying the same prefix. Refused rather than
		// picked between: which one a packet reaches would depend on the order the routing
		// table was written, so the technician who types `ssh 192.168.1.5` would sometimes
		// reach one customer and sometimes the other (ADR-0019).
		if contested := contestedPrefixes(claims, iface.Name, routedAs(prefixes, iface.Mapped)); len(contested) > 0 {
			log.Error("not carrying a route group whose prefixes another network also claims",
				"group", logx.Safe(name),
				"prefixes", contested,
				"also_claimed_by", claims.Contested(iface.Name, contested[0]),
				"why", "which network a packet reached would depend on the order the routing table was written")
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

// declaredPrefixes is every prefix these assignments ask this membership to carry.
//
// Unparseable ones are skipped rather than refused: a prefix this build cannot read is
// already reported as an unhonoured group above, and it cannot contest anything because
// nothing can route it either.
func declaredPrefixes(assignments []*meshpv1.RouteGroupAssignment, mapped map[netip.Prefix]netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, assignment := range assignments {
		for _, raw := range assignment.GetPrefixes() {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			out = append(out, routedAs([]netip.Prefix{prefix.Masked()}, mapped)...)
		}
	}
	return out
}

// routedAs is what these prefixes look like in the routing table.
//
// The mapped range where there is one, the prefix itself otherwise. Everything that decides
// whether two memberships collide has to ask this rather than look at the prefix directly,
// because the collision is about the routing table and nothing else.
func routedAs(prefixes []netip.Prefix, mapped map[netip.Prefix]netip.Prefix) []netip.Prefix {
	if len(mapped) == 0 {
		return prefixes
	}
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if to, ok := mapped[p.Masked()]; ok {
			out = append(out, to)
			continue
		}
		out = append(out, p)
	}
	return out
}

// mappedPrefixes reads the ranges the control plane allocated, on a host that can use them.
//
// Refused rather than approximated when a half will not parse or the two are different sizes:
// the host part is carried across unchanged, so a mismatched pair would send a technician to
// an address inside the right customer and the wrong machine.
func mappedPrefixes(assignments []*meshpv1.RouteGroupAssignment, canTranslate bool, log *slog.Logger) map[netip.Prefix]netip.Prefix {
	var out map[netip.Prefix]netip.Prefix
	for _, assignment := range assignments {
		for _, m := range assignment.GetMappedPrefixes() {
			real, realErr := netip.ParsePrefix(m.GetPrefix())
			to, toErr := netip.ParsePrefix(m.GetMapped())
			if realErr != nil || toErr != nil || real.Bits() != to.Bits() ||
				real.Addr().Is4() != to.Addr().Is4() {
				log.Error("a mapped range this device cannot use was sent for a colliding prefix",
					"prefix", logx.Safe(m.GetPrefix()), "mapped", logx.Safe(m.GetMapped()),
					"consequence", "the prefix stays contested and the group is not carried")
				continue
			}
			if !canTranslate {
				// Said once per pass rather than per prefix, further down, because a host
				// with no nftables collides on everything or nothing.
				continue
			}
			if out == nil {
				out = make(map[netip.Prefix]netip.Prefix)
			}
			out[real.Masked()] = to.Masked()
		}
	}
	if !canTranslate && len(out) == 0 {
		for _, assignment := range assignments {
			if len(assignment.GetMappedPrefixes()) > 0 {
				log.Error("this device was given ranges for colliding prefixes and cannot translate",
					"why", "translation needs nftables, which this host does not have",
					"consequence", "the colliding groups stay refused rather than reaching one customer at another's address")
				break
			}
		}
	}
	return out
}

// contestedPrefixes is those of these prefixes that another membership also claims.
func contestedPrefixes(claims *Claims, owner string, prefixes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, prefix := range prefixes {
		// A default route overlaps everything and is resolved by longest match, so it is
		// never the contested one — an egress group alongside a customer LAN is well
		// defined rather than ambiguous.
		if prefix.Bits() == 0 {
			continue
		}
		if len(claims.Contested(owner, prefix)) > 0 {
			out = append(out, prefix)
		}
	}
	return out
}
