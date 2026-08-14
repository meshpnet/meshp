package nftables

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// ForwardTableName is the table an advertiser's forwarding lives in.
//
// Its own table, separate from the policy table, because the two are rebuilt on different
// events: a policy change must not disturb a gateway's forwarding, and a route group
// changing must not reload a filter and reset its counters.
const ForwardTableName = "meshp_fwd"

// RenderForward turns what a device carries into a ruleset that carries it.
//
// Two things have to be true for a packet to cross, and both are here. The forward chain
// has to accept it — a host that routes but does not forward drops it silently between the
// interfaces — and the source address has to be rewritten, because a LAN device replying to
// 100.90.0.2 has no route to it and never will: nothing on that network has heard of the
// mesh, which is the whole point of putting a gateway in front of it.
//
// Empty groups render a script that removes the table. A device that has stopped carrying
// must stop forwarding, and leaving the rules would make it a gateway nobody knows about.
func RenderForward(iface string, groups []*meshpv1.AdvertisedRoutes_Group) (string, error) {
	if !interfaceNamePattern.MatchString(iface) {
		return "", fmt.Errorf("nftables: %q is not a usable interface name", iface)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", ForwardTableName)
	fmt.Fprintf(&b, "delete table inet %s\n", ForwardTableName)
	if len(groups) == 0 {
		return b.String(), nil
	}

	carried, egress, err := carriedPrefixes(groups)
	if err != nil {
		return "", err
	}
	if len(carried.v4) == 0 && len(carried.v6) == 0 && !egress {
		return b.String(), nil
	}

	fmt.Fprintf(&b, "add table inet %s\n", ForwardTableName)

	// policy accept with an explicit drop last, for the same reason the filter chains use
	// it: a chain that somehow ends up empty must not cut this host off from forwarding it
	// was already doing for something else — Docker, a VPN, anything.
	fmt.Fprintf(&b, "add chain inet %s forward { type filter hook forward priority filter; policy accept; }\n",
		ForwardTableName)

	// Return traffic first. A LAN host answering a mesh device is a reply to a connection
	// this gateway already accepted, and without conntrack every forwarded connection would
	// establish and then hang.
	fmt.Fprintf(&b, "add rule inet %s forward ct state established,related accept\n", ForwardTableName)

	for _, side := range []struct {
		family, saddr, daddr string
		prefixes             []string
	}{
		{"ip", "ip saddr", "ip daddr", carried.v4},
		{"ip6", "ip6 saddr", "ip6 daddr", carried.v6},
	} {
		if len(side.prefixes) == 0 {
			continue
		}
		// Out of the tunnel and into what this device carries.
		fmt.Fprintf(&b, "add rule inet %s forward iifname %q %s %s accept\n",
			ForwardTableName, iface, side.daddr, set(side.prefixes))
		// And back, so a mesh device can be answered by something it started talking to.
		fmt.Fprintf(&b, "add rule inet %s forward oifname %q %s %s accept\n",
			ForwardTableName, iface, side.saddr, set(side.prefixes))
	}
	if egress {
		// An egress advertiser forwards anything out of the tunnel: that is what being
		// somebody's way to the internet means.
		fmt.Fprintf(&b, "add rule inet %s forward iifname %q accept\n", ForwardTableName, iface)
	}

	// Source rewriting, in postrouting so it happens after the routing decision has chosen
	// the outgoing interface — which is what tells the kernel which address to masquerade to.
	fmt.Fprintf(&b, "add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }\n",
		ForwardTableName)

	stable := stableEgressOf(groups)
	for _, side := range []struct {
		saddr, daddr string
		prefixes     []string
	}{
		{"ip saddr", "ip daddr", carried.v4},
		{"ip6 saddr", "ip6 daddr", carried.v6},
	} {
		if len(side.prefixes) == 0 {
			continue
		}
		fmt.Fprintf(&b, "add rule inet %s postrouting iifname %q %s %s %s\n",
			ForwardTableName, iface, side.daddr, set(side.prefixes), stable)
	}
	if egress {
		fmt.Fprintf(&b, "add rule inet %s postrouting iifname %q oifname != %q %s\n",
			ForwardTableName, iface, iface, stable)
	}

	return b.String(), nil
}

// stableEgressOf renders the source-rewriting verb.
//
// snat when the group names an address, because a customer who has allowlisted an outbound
// IP with a bank depends on it surviving a failover; masquerade otherwise, which takes
// whatever address the outgoing interface happens to have and is what anyone without that
// requirement wants.
func stableEgressOf(groups []*meshpv1.AdvertisedRoutes_Group) string {
	for _, g := range groups {
		raw := g.GetStableEgressIp()
		if raw == "" {
			continue
		}
		// Parsed and re-rendered, never interpolated: this reaches a script that runs as
		// root, and it arrives from the control plane.
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		return "snat to " + addr.Unmap().String()
	}
	return "masquerade"
}

// carriedPrefixes splits what is carried by family, and reports whether a default route is
// among it.
func carriedPrefixes(groups []*meshpv1.AdvertisedRoutes_Group) (out families, egress bool, err error) {
	seen := make(map[netip.Prefix]struct{})
	for _, group := range groups {
		for _, raw := range group.GetPrefixes() {
			prefix, parseErr := netip.ParsePrefix(raw)
			if parseErr != nil {
				return families{}, false, fmt.Errorf(
					"nftables: carried prefix %q is not a prefix: %w", raw, parseErr)
			}
			if prefix.Bits() == 0 {
				// Handled by the catch-all rules rather than as a prefix match, because a
				// 0.0.0.0/0 daddr match would also catch traffic to this host itself.
				egress = true
				continue
			}
			seen[prefix.Masked()] = struct{}{}
		}
	}

	prefixes := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if a.Addr() != b.Addr() {
			return a.Addr().Less(b.Addr())
		}
		return a.Bits() < b.Bits()
	})
	for _, p := range prefixes {
		if p.Addr().Is4() {
			out.v4 = append(out.v4, p.String())
		} else {
			out.v6 = append(out.v6, p.String())
		}
	}
	return out, egress, nil
}
