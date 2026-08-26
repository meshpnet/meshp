package pf

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// interfaceNamePattern is what a macOS network interface may be called.
//
// Checked before the name reaches a ruleset rather than trusted, because it arrives as
// configuration and ends up in a file loaded by a process running as root. The same guard
// nftables.Render applies, with macOS's shorter name limit.
var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// LockSpec is what a device may still reach while it fails closed.
//
// The same four things nftables.LockSpec names, and that type carries the fuller account of
// why each one exists — each is a way for the machine to stay usable and reachable while the
// tunnel is the only way out, and omitting one is how this feature becomes a bricked laptop.
//
// Its own type rather than a shared one because the two renderings have nothing in common
// beyond their inputs. pf and nftables disagree about evaluation order, about how a rule
// stops evaluation, and about what "reject" is called; a shared spec would be the only thing
// holding two unrelated renderers together, and it would drift the first time one of them
// needed a field the other could not honour.
type LockSpec struct {
	// Interface is the tunnel. Empty means there is no lock — RenderLock produces nothing,
	// and removal is a flush rather than a ruleset.
	Interface string

	// Endpoints are the outer addresses that make the tunnel possible: the relay and the
	// control plane that can tell this device to stop. Without them the lock deadlocks.
	Endpoints []netip.AddrPort

	// Excluded are the prefixes that stay reachable directly — the local network, and
	// whatever an administrator carved out.
	Excluded []netip.Prefix

	// PreventDNSLeaks refuses plaintext DNS that is not going through the tunnel. It exists
	// for the hole the carve-out has to leave: the resolver is on the local network, which
	// the carve-out permits.
	PreventDNSLeaks bool
}

// RenderLock turns a lock specification into a pf ruleset that refuses everything else.
//
// An empty Interface renders nothing. That is not the same shape as RenderLock in nftables,
// which renders a script that deletes its table: there is no ruleset that means "remove
// this" in pf, because an anchor is emptied by flushing it rather than by loading something.
// Removal lives in ApplyLock for that reason, and this returns "" so a caller that renders
// first and loads second cannot accidentally load an empty ruleset over a live lock.
//
// Four deliberate differences from the nftables rendering, three of them forced by pf.
//
// **Every rule is `quick`.** pf is last-match-wins: without `quick` the final block would
// win over every accept above it and the machine would have no network at all. With it, the
// file reads top to bottom the way the nftables chain does, and the order below is the
// policy rather than an accident of how pf resolves ties.
//
// **Every pass rule is `no state`.** pf checks its state table before its rules, so a
// permitted flow would otherwise be waved through on subsequent packets without being
// evaluated again. That is fine until the carve-out changes underneath it. Stateless
// matching is also what nftables does here — the lock deliberately has no
// established-accept, because a connection opened before the lock went up is exactly what
// it exists to stop.
//
// **`block return` rather than `block drop`.** The nftables rendering rejects rather than
// drops for a reason ADR-0011 is explicit about: a dropped packet leaves an application
// hanging until it times out and the user learns nothing, while a rejected one fails
// immediately with an error the operating system already knows how to describe. `return` is
// pf's spelling of that.
//
// **Only the `out` direction.** Nothing here matches inbound traffic, so the anchor cannot
// disturb anything arriving. The nftables lock hooks `output` alone for the same reason.
func RenderLock(spec LockSpec) (string, error) {
	if spec.Interface == "" {
		return "", nil
	}
	if !interfaceNamePattern.MatchString(spec.Interface) {
		return "", fmt.Errorf("pf: %q is not a usable interface name", spec.Interface)
	}

	var b strings.Builder

	// Loopback first, and unconditionally. The agent's own control socket, a local resolver
	// and everything a desktop does with 127.0.0.1 go through here; a lock that broke them
	// would break the machine rather than its egress.
	//
	// A rule rather than `set skip on lo0`, which would be the idiomatic way to say this and
	// is not available: `set` belongs to the main ruleset and is rejected inside an anchor.
	b.WriteString("pass out quick on lo0 all no state\n")

	// The tunnel itself: this is what the traffic is supposed to use.
	fmt.Fprintf(&b, "pass out quick on %s all no state\n", spec.Interface)

	// The outer packets that carry the tunnel, and the control channel that can end it.
	// Rendered from parsed addresses rather than interpolated text — this ruleset is loaded
	// as root and the endpoints arrive from the control plane.
	for _, ep := range sortedEndpoints(spec.Endpoints) {
		addr := ep.Addr().Unmap()
		family := "inet"
		if addr.Is6() {
			family = "inet6"
		}
		fmt.Fprintf(&b, "pass out quick %s proto { tcp udp } from any to %s port %d no state\n",
			family, addr.String(), ep.Port())
	}

	// Before the carve-out, and that order is the whole of this rule. Refusing DNS after the
	// local network has been permitted would refuse nothing: the resolver is on the local
	// network.
	//
	// Plaintext only, which is what ADR-0011 asks for. DNS over TLS on 853 does not disclose
	// the query to the network it crosses, and DNS over HTTPS is indistinguishable from any
	// other HTTPS. mDNS on 5353 is left alone too: it never leaves the link, and refusing it
	// costs the printer discovery the carve-out exists to keep.
	if spec.PreventDNSLeaks {
		b.WriteString("block return out quick proto { tcp udp } from any to any port 53\n")
	}

	// The local network and anything else carved out.
	excluded := splitPrefixes(spec.Excluded)
	if len(excluded.v4) > 0 {
		fmt.Fprintf(&b, "pass out quick inet from any to { %s } no state\n", strings.Join(excluded.v4, " "))
	}
	if len(excluded.v6) > 0 {
		fmt.Fprintf(&b, "pass out quick inet6 from any to { %s } no state\n", strings.Join(excluded.v6, " "))
	}

	// Keeping the address the machine has. A device that cannot renew a DHCP lease loses its
	// network some minutes later, and a device that cannot do neighbour discovery loses IPv6
	// immediately — both of which look exactly like the bug this feature exists to prevent,
	// and neither of which carries any of the user's traffic.
	b.WriteString("pass out quick proto udp from any to any port { 67 68 546 547 } no state\n")
	b.WriteString("pass out quick inet6 proto icmp6 all no state\n")

	// And everything else is refused, audibly.
	b.WriteString("block return out quick all\n")

	return b.String(), nil
}

// sortedEndpoints puts the endpoints in a stable order, so the same specification renders
// the same ruleset and an unchanged lock is not reloaded for nothing.
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

// families is prefixes sorted into the two address families, because a pf list may not mix
// them: `inet` and `inet6` rules are written separately.
type families struct{ v4, v6 []string }

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
