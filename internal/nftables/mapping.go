package nftables

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// MapTableName is the prefix of the table that makes two customers on the same prefix
// distinguishable.
//
// Its own table, like the lock and the forwarding rules, and rebuilt on its own trigger: the
// mappings change when a device's memberships change, which is a different event from a
// policy update or a route group moving between advertisers.
//
// One table per interface rather than one for the device, which is the whole reason this is a
// prefix and not the name. Every membership reconciles on its own timer and rebuilds its own
// table whole, so a single shared table would have the second membership to reconcile erase
// the first's rules — and on a device holding two colliding memberships, which is the only
// device that has any of these rules at all, that means exactly one of the two customers is
// ever reachable. An end-to-end run found it doing precisely that.
const MapTableName = "meshp_map"

// MapTable is the table one interface's mappings live in.
//
// The interface name is already validated by the caller against a pattern nft will accept,
// and interface names are unique on a host, so this cannot collide with another membership's.
func MapTable(iface string) string { return MapTableName + "_" + iface }

// Mapping is one colliding prefix and the range this device reaches it by.
//
// Both halves are the same size. A /24 is mapped to a /24 and the host part is carried
// across unchanged, so 100.71.5.5 is 192.168.1.5 at the other end — which is what makes the
// translation stateless, and what makes a packet capture on the advertiser legible to
// somebody who knows the mapping.
type Mapping struct {
	// Mapped is what the routing table holds and what a person types. Allocated by the
	// control plane, which is the only party that can see both memberships (ADR-0020).
	Mapped netip.Prefix

	// Real is what the customer actually uses, and what crosses the tunnel.
	Real netip.Prefix
}

// RenderMap turns a device's mappings into a ruleset that performs them.
//
// Two rewrites per mapping, both stateless, both scoped to one interface.
//
// A raw header rewrite, not a conntrack DNAT, and that is the decision this rests on. DNAT
// re-routes after rewriting, which would send the kernel back to a routing table holding two
// identical prefixes — the ambiguity this exists to resolve. It also keeps per-connection
// state, and ADR-0020 refuses to put any of that on the path: an entry that expires, or a
// daemon that restarts, drops established connections. These rules are pure arithmetic, so a
// packet arriving after any interruption is translated exactly as the one before it was.
//
// Postrouting rather than output, which is the weaker of the two choices and worth saying so.
// For locally-generated traffic the routing decision is already made by the time either hook
// runs, so a raw rewrite in output would behave identically — a mutation moving it there
// passes every test here. Postrouting is kept because it is also traversed by forwarded
// packets, so it stays correct if this device ever carries a mapped range on behalf of
// something behind it, which output would not.
//
// Inbound is the mirror, and it has to exist: the customer's server replies to the source it
// saw, so the reply arrives from 192.168.1.5 to a technician whose socket is connected to
// 100.71.5.5. Rewriting the source back on the way in closes that loop.
//
// The source address is never touched in either direction. ADR-0007 enforces ACLs at the
// destination against the identity of the device reaching it, and a rewritten source would
// hand every server in every customer's network one address for the whole MSP.
//
// No mappings renders a script that removes the table, so a device that stopped colliding
// stops translating (Invariant 20).
func RenderMap(iface string, mappings []Mapping) (string, error) {
	if !interfaceNamePattern.MatchString(iface) {
		return "", fmt.Errorf("nftables: %q is not a usable interface name", iface)
	}

	table := MapTable(iface)

	var b strings.Builder
	// add-then-delete so removal is idempotent, as everywhere else here: deleting a table
	// that is not there is an error, and adding one that is already there is not.
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "delete table inet %s\n", table)
	if len(mappings) == 0 {
		return b.String(), nil
	}

	ordered, err := validMappings(mappings)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(&b, "add table inet %s\n", table)
	// Priority mangle on the way out, and -300 on the way in, so both run before anything
	// that inspects addresses. The filter chain's rules are written in terms of the real
	// mesh addresses on the wire, and the forwarding chain's in terms of carried prefixes;
	// translating outside them keeps every other table reading the address it expects.
	fmt.Fprintf(&b, "add chain inet %s outbound { type filter hook postrouting priority mangle; policy accept; }\n",
		table)
	fmt.Fprintf(&b, "add chain inet %s inbound { type filter hook prerouting priority -300; policy accept; }\n",
		table)

	for _, m := range ordered {
		host := hostWildcard(m.Mapped)
		fmt.Fprintf(&b, "add rule inet %s outbound oifname \"%s\" %s daddr %s %s daddr set %s daddr & %s | %s\n",
			table, iface, family(m.Mapped), m.Mapped,
			family(m.Mapped), family(m.Mapped), host, m.Real.Masked().Addr())
		fmt.Fprintf(&b, "add rule inet %s inbound iifname \"%s\" %s saddr %s %s saddr set %s saddr & %s | %s\n",
			table, iface, family(m.Real), m.Real,
			family(m.Real), family(m.Real), host, m.Mapped.Masked().Addr())
	}
	return b.String(), nil
}

// validMappings checks what cannot be expressed, and sorts what can.
//
// Refusing rather than rendering something approximate: a mapping that is wrong sends a
// technician to the wrong customer's machine, which is the exact failure the refusal in
// PR #70 exists to avoid. Better to carry neither prefix and say so.
func validMappings(mappings []Mapping) ([]Mapping, error) {
	seen := make(map[netip.Prefix]bool, len(mappings))
	out := make([]Mapping, 0, len(mappings))

	for _, m := range mappings {
		if !m.Mapped.IsValid() || !m.Real.IsValid() {
			return nil, fmt.Errorf("nftables: a mapping is missing one of its halves: %v -> %v", m.Mapped, m.Real)
		}
		if m.Mapped.Addr().Is4() != m.Real.Addr().Is4() {
			return nil, fmt.Errorf("nftables: %v and %v are different families", m.Mapped, m.Real)
		}
		if m.Mapped.Bits() != m.Real.Bits() {
			// The host part is carried across unchanged, so the two halves must hold the
			// same number of hosts. Mapping a /24 onto a /25 would silently drop half the
			// customer's network.
			return nil, fmt.Errorf("nftables: %v and %v are different sizes; a mapping carries the host part across",
				m.Mapped, m.Real)
		}
		if m.Mapped.Masked() != m.Mapped || m.Real.Masked() != m.Real {
			// A prefix with host bits set means the caller is describing something other
			// than a network, and the arithmetic below would quietly ignore them.
			return nil, fmt.Errorf("nftables: %v -> %v has bits set below the prefix", m.Mapped, m.Real)
		}
		if seen[m.Mapped] {
			// Two rules matching the same mapped range would fire in file order, so the
			// second is unreachable and the caller believes something that is not true.
			return nil, fmt.Errorf("nftables: %v is mapped twice", m.Mapped)
		}
		seen[m.Mapped] = true
		out = append(out, m)
	}

	// Sorted so the same set of mappings renders the same script every time. An unstable
	// order would reinstall the ruleset on every reconcile and look like churn.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Mapped.Addr() != out[j].Mapped.Addr() {
			return out[i].Mapped.Addr().Less(out[j].Mapped.Addr())
		}
		return out[i].Mapped.Bits() < out[j].Mapped.Bits()
	})
	return out, nil
}

// family is the nftables keyword for the address family, in an inet table where both live.
func family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ip"
	}
	return "ip6"
}

// hostWildcard is the mask that keeps the host part and discards the network.
//
// The complement of the prefix mask: for a /24 it is 0.0.0.255, and for a /25 it is
// 0.0.0.127 — which is why this is computed rather than written per byte. A prefix that does
// not fall on a byte boundary is ordinary in a customer's network and gets the same treatment
// as one that does.
func hostWildcard(p netip.Prefix) netip.Addr {
	// Built at the address's own width, so an IPv4 mask renders as 0.0.0.255 rather than
	// the IPv4-in-IPv6 form nft would not accept.
	octets := make([]byte, p.Addr().BitLen()/8)
	for i := range octets {
		octets[i] = 0xff
	}
	for i := range p.Bits() {
		octets[i/8] &^= 1 << (7 - i%8)
	}
	addr, _ := netip.AddrFromSlice(octets)
	return addr
}
