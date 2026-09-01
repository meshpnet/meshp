//go:build darwin

package wglink

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/route"
)

// interfaceRoutes lists the routes currently pointing at one interface.
//
// Read from the kernel's routing table over PF_ROUTE rather than by parsing netstat(1),
// which prints destinations abbreviated — `100.90` for `100.90.0.0/16` — and would have this
// guessing at prefix lengths from how many octets were printed.
//
// Every route through this interface counts as ours, which is a different rule from Linux
// and lands in the same place. There, routes carry a protocol number and meshp filters on
// its own; here there is no such field, and the reason one is not needed is that the
// interface itself is ours: this process created the utun and nothing else has a reason to
// point anything at it. What that admits is that a route an operator added by hand to a
// meshp interface would be withdrawn on the next reconcile — which is also true on Linux
// for a route added with meshp's protocol number, and is the same bargain: the agent removes
// what it installed, and an interface it owns entirely is all of it.
//
// The routes the kernel installs by itself are excluded. macOS adds them when an address goes
// on the interface — a host route for the address, and for IPv6 the link-local prefix and the
// multicast prefixes — and reporting them would have the planner try to withdraw routes it
// never installed, on every pass, forever.
//
// That "forever" is not hypothetical. It shipped: this function reported fe80::/64, ff00::/8,
// ff01::/32 and ff02::/32 on any interface carrying an IPv6 address, the planner withdrew all
// four, the kernel reinstalled them, and the route socket reported the change — which since
// #184 wakes the reconciler, so the agent spun at two passes a second on a laptop until it was
// killed. Every test passed throughout, because a single reconcile converges correctly and
// nothing asked what a second one did.
func interfaceRoutes(index int) ([]netip.Prefix, error) {
	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("wglink: reading the routing table: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("wglink: parsing the routing table: %w", err)
	}

	// Read once rather than per route: it is a file, and this runs on every reconcile.
	claim := recordedClaim()

	var out []netip.Prefix
	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if !ok || m.Index != index {
			continue
		}
		prefix, ok := prefixOf(m)
		if !ok {
			continue
		}
		// A route the kernel cloned from one of ours is the kernel's, however much it
		// looks like a route to a destination somebody chose.
		if wasCloned(m) {
			continue
		}
		// A host route to one of the interface's own addresses is the kernel's
		// bookkeeping rather than a route meshp asked for.
		if prefix.IsSingleIP() && isLocalRoute(m) {
			continue
		}
		// Neither is anything link-local or multicast. meshp routes the addresses a network
		// hands out, which are neither, so a prefix of either kind was put there by the
		// kernel however it is flagged — and unlike the host route above there is no flag
		// that distinguishes them, which is why this asks what the prefix is rather than
		// what the routing message says about it.
		if kernelOwned(prefix) {
			continue
		}
		// Nor anything the egress router installed. It is meshp's, and it is not this
		// interface's plan to manage — see routeowner.go.
		if egressOwned(claim, prefix) {
			continue
		}
		out = append(out, prefix)
	}
	return out, nil
}

// prefixOf turns a routing message's destination and netmask into a prefix.
func prefixOf(m *route.RouteMessage) (netip.Prefix, bool) {
	// Addrs is indexed by RTAX_*: 0 is the destination, 2 the netmask.
	if len(m.Addrs) == 0 || m.Addrs[0] == nil {
		return netip.Prefix{}, false
	}
	dst := addrOf(m.Addrs[0])
	if !dst.IsValid() {
		return netip.Prefix{}, false
	}

	// A route with no netmask is a host route. macOS omits the mask for those rather than
	// sending an all-ones one.
	bits := dst.BitLen()
	if len(m.Addrs) > 2 && m.Addrs[2] != nil {
		if mask := maskBits(m.Addrs[2], dst.BitLen()); mask >= 0 {
			bits = mask
		}
	}
	prefix, err := dst.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

func addrOf(a route.Addr) netip.Addr {
	switch v := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(v.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(v.IP).Unmap()
	default:
		return netip.Addr{}
	}
}

// maskBits counts the leading ones in a netmask expressed as an address.
//
// Returns -1 for anything that is not a contiguous mask. A non-contiguous netmask is legal
// in the routing socket's encoding and meaningless as a prefix length, so it is skipped
// rather than rounded into something that would then be compared against a plan.
//
// net.IPMask.Size does both jobs and is used rather than counted by hand, which is how this
// was written first and got wrong: the contiguity check rejected every mask whose length was
// not a multiple of eight. A /24 passed and a /1 and a /12 did not, so Observe silently
// dropped those routes and the reconciler could never withdraw one. Size returns a zero
// length for a mask that is not contiguous, which is the same answer this needs and is
// already correct.
func maskBits(a route.Addr, want int) int {
	var raw []byte
	switch v := a.(type) {
	case *route.Inet4Addr:
		raw = v.IP[:]
	case *route.Inet6Addr:
		raw = v.IP[:]
	default:
		return -1
	}
	if len(raw)*8 != want {
		return -1
	}

	ones, bits := net.IPMask(raw).Size()
	if bits == 0 {
		// Not contiguous. Size reports both as zero for those, and a zero length is
		// otherwise a legitimate answer for a mask of all zeroes.
		return -1
	}
	return ones
}

// wasCloned reports whether the kernel generated this route from one of ours.
//
// macOS clones. A route carrying RTF_PRCLONING — which the halves a full tunnel installs do —
// makes the kernel create a host route for every destination actually contacted through it. So
// a laptop browsing the web through a claimed tunnel grows a /32 per site, dozens of them,
// each one a route meshp did not install and the planner would withdraw. The kernel recreates
// them with the next packet.
//
// Measured rather than reasoned about: with a full tunnel claimed and ordinary browsing,
// interfaceRoutes reported 74 routes where `netstat -rn` showed 5. The other 69 were these —
// `netstat -rna` shows them, flagged `UHWIig`, or in words:
//
//	<UP,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL>
//
// This is the third time the same rule has been wrong in the same place. "Every route on a
// meshp interface is meshp's" held until the kernel added link-local and multicast routes
// (#193), then until the egress router wrote to the same interface (#202), and now until
// traffic flowed through it. What is different about this one is that it needs *use*: an
// interface that is up and idle never grows a cloned route, so no test that brings an
// interface up and looks at it can find this.
func wasCloned(m *route.RouteMessage) bool {
	const rtfWasCloned = 0x20000 // RTF_WASCLONED
	return m.Flags&rtfWasCloned != 0
}

// isLocalRoute reports whether a route is the kernel's own entry for an interface address.
func isLocalRoute(m *route.RouteMessage) bool {
	const rtfLocal = 0x200000 // RTF_LOCAL
	return m.Flags&rtfLocal != 0
}

// kernelOwned reports whether a prefix is one the operating system maintains itself, rather
// than one meshp could have installed.
//
// Every route on a meshp interface counts as meshp's here, because macOS offers nothing to
// distinguish them by: a routing message has no field saying who installed it. Linux has a
// protocol number and Windows has an origin; this is the platform that has neither, so the
// question has to be asked about the prefix instead. Adding an IPv6 address installs the
// link-local prefix and the multicast prefixes alongside it, reported as ordinary routes
// through the interface.
//
// Reporting them costs more than a wasted comparison. The planner withdraws them, the kernel
// restores them, and the route socket reports the change — which since #184 wakes the
// reconciler, so the agent runs the same four operations twice a second for as long as it is
// up. That shipped, and was found by running it on a laptop rather than by any test.
//
// Deliberately a question about the prefix rather than about the routing message: the flags
// that distinguish these differ between platforms and, for the multicast entries, do not
// distinguish them at all. What is reliable is that an address meshp hands out comes from the
// network's own range (ADR-0005) and is never link-local or multicast, so nothing excluded
// here could have been ours to install.
func kernelOwned(prefix netip.Prefix) bool {
	addr := prefix.Addr()
	return addr.IsLinkLocalUnicast() || addr.IsMulticast()
}
