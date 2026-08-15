package nftables

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// LockTableName is the table a fail-closed device's egress rules live in.
//
// Its own table for the reason the forwarding rules have one, and for a sharper one besides:
// this is the only table here that can take a machine off the network. Keeping it separate
// means it can be found and removed on its own, by a `meshp down`, by an agent starting up
// and finding what a previous life left behind, or by a person with a console and no idea
// what meshp is.
const LockTableName = "meshp_lock"

// LockSpec is what a device may still reach while it fails closed.
//
// Everything not named here is refused. The fields are therefore not conveniences — each one
// is a way for the device to stay usable and reachable while the tunnel is the only route
// out, and omitting one is how this feature turns into a bricked machine (ADR-0011).
type LockSpec struct {
	// Interface is the tunnel. Traffic leaving through it is the entire point of claiming a
	// default route, so it is always permitted.
	Interface string

	// Endpoints are the outer addresses that make the tunnel possible: the relay this device
	// attaches to, and the control plane that can tell it to stop.
	//
	// Without these the lock deadlocks — no tunnel, because no egress; no egress, because no
	// tunnel — and it deadlocks in the state where the machine cannot be told to unlock.
	Endpoints []netip.AddrPort

	// Excluded are prefixes an administrator has carved out, and the local network.
	//
	// A device that cannot reach its own LAN while tunnelled has lost its printer, its NAS
	// and often its default gateway. What belongs in here is decided elsewhere; this only
	// renders it.
	Excluded []netip.Prefix
}

// RenderLock turns a lock specification into a ruleset that refuses everything else.
//
// An empty Interface renders a script that removes the table, which is how a device stops
// failing closed — the same shape RenderForward uses for a device that has stopped carrying.
//
// Three deliberate differences from the other tables here.
//
// The chain's policy is drop rather than accept. Elsewhere a chain that somehow ends up
// empty must not disturb traffic that has nothing to do with meshp; here an empty chain
// means every rule that was holding the line is gone, and this is the one table whose whole
// job is to fail closed rather than open.
//
// There is no blanket `ct state established,related accept`. The forwarding table needs one
// or connections hang, but a connection established before the lock went up is exactly what
// this exists to stop: the user's real address, still in use, after the tunnel dropped.
//
// The last rule rejects rather than drops. A dropped packet leaves an application hanging
// until it times out, and the user learns nothing; a rejected one fails immediately with an
// error the operating system already knows how to describe. ADR-0011 is explicit that there
// will be users whose network broke because their laptop correctly refused to leak, and that
// the error message is the product.
func RenderLock(spec LockSpec) (string, error) {
	var b strings.Builder

	// add-then-delete so removal is idempotent: deleting a table that is not there is an
	// error, and adding one that is already there is not.
	fmt.Fprintf(&b, "add table inet %s\n", LockTableName)
	fmt.Fprintf(&b, "delete table inet %s\n", LockTableName)
	if spec.Interface == "" {
		return b.String(), nil
	}
	if !interfaceNamePattern.MatchString(spec.Interface) {
		return "", fmt.Errorf("nftables: %q is not a usable interface name", spec.Interface)
	}

	fmt.Fprintf(&b, "add table inet %s\n", LockTableName)
	fmt.Fprintf(&b, "add chain inet %s output { type filter hook output priority filter; policy drop; }\n",
		LockTableName)

	// Loopback first, and unconditionally. The agent's own control socket, a local resolver
	// and everything a desktop does with 127.0.0.1 go through here, and a lock that broke
	// them would break the machine rather than its egress.
	fmt.Fprintf(&b, "add rule inet %s output oif lo accept\n", LockTableName)

	// The tunnel itself: this is what the traffic is supposed to use.
	fmt.Fprintf(&b, "add rule inet %s output oifname %q accept\n", LockTableName, spec.Interface)

	// The outer packets that carry the tunnel, and the control channel that can end it.
	// Rendered from parsed addresses rather than interpolated text — this script runs as
	// root and the endpoints arrive from the control plane.
	for _, ep := range sortedEndpoints(spec.Endpoints) {
		addr := ep.Addr().Unmap()
		family := "ip"
		if addr.Is6() {
			family = "ip6"
		}
		fmt.Fprintf(&b, "add rule inet %s output %s daddr %s udp dport %d accept\n",
			LockTableName, family, addr.String(), ep.Port())
		fmt.Fprintf(&b, "add rule inet %s output %s daddr %s tcp dport %d accept\n",
			LockTableName, family, addr.String(), ep.Port())
	}

	// The local network and anything else carved out.
	excluded := splitPrefixes(spec.Excluded)
	if len(excluded.v4) > 0 {
		fmt.Fprintf(&b, "add rule inet %s output ip daddr %s accept\n", LockTableName, set(excluded.v4))
	}
	if len(excluded.v6) > 0 {
		fmt.Fprintf(&b, "add rule inet %s output ip6 daddr %s accept\n", LockTableName, set(excluded.v6))
	}

	// Keeping the address the machine has. A device that cannot renew a DHCP lease loses its
	// network some minutes later, and a device that cannot do neighbour discovery loses IPv6
	// immediately — both of which look exactly like the bug this feature exists to prevent,
	// and neither of which carries any of the user's traffic.
	fmt.Fprintf(&b, "add rule inet %s output udp dport { 67, 68, 546, 547 } accept\n", LockTableName)
	fmt.Fprintf(&b, "add rule inet %s output meta l4proto ipv6-icmp accept\n", LockTableName)

	// And everything else is refused, audibly.
	fmt.Fprintf(&b, "add rule inet %s output reject\n", LockTableName)

	return b.String(), nil
}

// sortedEndpoints puts the endpoints in a stable order, so the same specification renders
// the same script and an unchanged lock is not reloaded for nothing.
func sortedEndpoints(in []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(in))
	seen := make(map[netip.AddrPort]struct{}, len(in))
	for _, ep := range in {
		if !ep.Addr().IsValid() || ep.Port() == 0 {
			continue
		}
		norm := netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// splitPrefixes sorts prefixes into families, dropping anything unusable rather than
// refusing the whole lock: a malformed exclusion should cost that exclusion, not leave the
// device with no lock at all.
func splitPrefixes(in []netip.Prefix) families {
	var out families
	seen := make(map[netip.Prefix]struct{}, len(in))
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		norm := netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		if norm.Addr().Is4() {
			out.v4 = append(out.v4, norm.String())
		} else {
			out.v6 = append(out.v6, norm.String())
		}
	}
	sort.Strings(out.v4)
	sort.Strings(out.v6)
	return out
}
