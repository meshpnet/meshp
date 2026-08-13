// Package nftables turns a compiled PacketFilter into a ruleset the Linux kernel enforces.
//
// It is the destination-side half of ADR-0007: the control plane decides who may reach
// what, and this is where that decision stops packets. Split the way wgplan and wglink are
// — rendering is pure and testable anywhere, and only applying needs a kernel and root.
//
// Three things shape the ruleset.
//
// **Nothing outside the tunnel is ever touched.** Both chains accept anything not on the
// meshp interface as their first rule, and the chain policy is accept. A bug in here can
// therefore drop mesh traffic and nothing else. That bound is deliberate: the alternative
// is a policy mistake, or a rendering bug, locking an operator out of the machine they
// would use to fix it.
//
// **The ruleset is replaced atomically.** Everything is one table, flushed and rebuilt in
// a single nft transaction, so there is no window in which half a policy is in force. A
// rule-by-rule update would have one, and the window would be exactly when traffic is
// permitted that the new policy denies.
//
// **Nothing from the wire is interpolated.** Every address, port and protocol is parsed and
// re-rendered from its parsed form, so a control plane — compromised, or merely buggy —
// cannot put its own text into a script that runs as root.
package nftables

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// TableName is the table meshp owns.
//
// Its own table, in the inet family so one set of rules covers IPv4 and IPv6. Owning a
// whole table is what makes flush-and-rebuild safe: meshp never touches a rule it did not
// write, and nothing meshp writes outlives the table.
const TableName = "meshp"

// interfaceNamePattern is what a Linux network interface may be called.
//
// Checked before the name reaches a script rather than trusted, because it arrives as
// configuration and ends up inside a quoted string in a file run as root.
var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// Render turns a filter into an nft script.
//
// A nil filter renders a script that removes meshp's table and adds nothing: no policy
// means no enforcement, and it must be possible to go back to that state. That is not the
// same as an empty filter, which is a policy that permits nothing and renders a table that
// drops all mesh traffic.
func Render(iface string, filter *meshpv1.PacketFilter) (string, error) {
	if !interfaceNamePattern.MatchString(iface) {
		return "", fmt.Errorf("nftables: %q is not a usable interface name", iface)
	}

	var b strings.Builder
	// Idempotent teardown. `delete table` on a table that does not exist is an error, so
	// it is created first and then deleted — the standard way to write "make sure this is
	// gone" in a single transaction.
	fmt.Fprintf(&b, "add table inet %s\n", TableName)
	fmt.Fprintf(&b, "delete table inet %s\n", TableName)

	if filter == nil {
		return b.String(), nil
	}

	fmt.Fprintf(&b, "add table inet %s\n", TableName)
	for _, chain := range []struct {
		name    string
		hook    string
		ifmatch string
		rules   []*meshpv1.PacketFilter_Rule
	}{
		{"input", "input", "iifname", filter.GetInbound()},
		{"output", "output", "oifname", filter.GetOutbound()},
	} {
		// policy accept, not drop. The last rule drops what reached it, and everything
		// that is not mesh traffic has already been accepted above — so a chain that
		// somehow ends up empty fails open for the host rather than cutting it off the
		// network entirely.
		fmt.Fprintf(&b, "add chain inet %s %s { type filter hook %s priority filter; policy accept; }\n",
			TableName, chain.name, chain.hook)

		// Anything not on this interface is none of our business, and this is the first
		// rule so that no later mistake can reach it.
		fmt.Fprintf(&b, "add rule inet %s %s %s != %q accept\n",
			TableName, chain.name, chain.ifmatch, iface)

		// Return traffic for a connection that was allowed. Without this, a device
		// permitted to reach a server on tcp/22 sends its SYN and has the SYN-ACK dropped
		// on the way back, so every allowed connection would hang instead of working.
		fmt.Fprintf(&b, "add rule inet %s %s ct state established,related accept\n",
			TableName, chain.name)
		fmt.Fprintf(&b, "add rule inet %s %s ct state invalid drop\n", TableName, chain.name)

		for i, rule := range chain.rules {
			rendered, err := renderRule(rule)
			if err != nil {
				return "", fmt.Errorf("nftables: %s rule %d: %w", chain.name, i, err)
			}
			for _, expr := range rendered {
				fmt.Fprintf(&b, "add rule inet %s %s %s accept\n", TableName, chain.name, expr)
			}
		}

		if filter.GetDefaultDeny() {
			// Counted, because "the policy is denying something" and "nothing is reaching
			// this host at all" look identical without a number.
			fmt.Fprintf(&b, "add rule inet %s %s counter drop\n", TableName, chain.name)
		}
	}

	return b.String(), nil
}

// renderRule turns one compiled rule into nft match expressions.
//
// One per address family present on both sides, because a rule cannot match an IPv4 source
// against an IPv6 destination and a table that tried would be rejected as a whole.
func renderRule(rule *meshpv1.PacketFilter_Rule) ([]string, error) {
	if !rule.GetAllow() {
		// The language has no way to express this, so a rule that says otherwise means
		// something upstream is confused and its intent cannot be guessed.
		return nil, fmt.Errorf("is not an allow rule; this ruleset denies by default and permits by rule")
	}

	src, err := byFamily(rule.GetSrcPrefixes())
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	dst, err := byFamily(rule.GetDstPrefixes())
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}

	proto, err := protocolOf(rule.GetProtocol())
	if err != nil {
		return nil, err
	}
	ports, err := portsOf(rule.GetPorts(), proto)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, family := range []struct {
		v6           bool
		saddr, daddr string
		icmp         string
	}{
		{false, "ip saddr", "ip daddr", "ip protocol icmp"},
		{true, "ip6 saddr", "ip6 daddr", "ip6 nexthdr ipv6-icmp"},
	} {
		sources, destinations := src.v4, dst.v4
		if family.v6 {
			sources, destinations = src.v6, dst.v6
		}
		// A rule whose sides do not meet in this family is not a rule in this family.
		// Emitting one half would match every address in the other.
		if len(sources) == 0 || len(destinations) == 0 {
			continue
		}

		var parts []string
		parts = append(parts, family.saddr+" "+set(sources))
		parts = append(parts, family.daddr+" "+set(destinations))

		switch proto {
		case "any":
			// No protocol match at all.
		case "icmp":
			parts = append(parts, family.icmp)
		default:
			if len(ports) > 0 {
				parts = append(parts, proto+" dport "+set(ports))
			} else {
				parts = append(parts, "meta l4proto "+proto)
			}
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out, nil
}

type families struct{ v4, v6 []string }

// byFamily parses prefixes and splits them, discarding nothing silently.
func byFamily(prefixes []string) (families, error) {
	var out families
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			// Refused rather than skipped, and refused rather than passed through. This is
			// the point at which text from the control plane would otherwise reach a script
			// that runs as root.
			return families{}, fmt.Errorf("%q is not a prefix: %w", raw, err)
		}
		// Rendered from the parsed value, never from the input.
		rendered := prefix.Masked().String()
		if prefix.Addr().Is4() {
			out.v4 = append(out.v4, rendered)
		} else {
			out.v6 = append(out.v6, rendered)
		}
	}
	sort.Strings(out.v4)
	sort.Strings(out.v6)
	return out, nil
}

func protocolOf(p string) (string, error) {
	switch p {
	case "", "any":
		return "any", nil
	case "tcp", "udp", "icmp":
		return p, nil
	default:
		return "", fmt.Errorf("protocol %q is not one of any, tcp, udp, icmp", p)
	}
}

// portsOf parses ports, rendering each from its parsed form.
func portsOf(specs []string, proto string) ([]string, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("ports were given for protocol %q, which has none", proto)
	}

	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		from, to, isRange := strings.Cut(spec, "-")
		lo, err := parsePort(from)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", spec, err)
		}
		if !isRange {
			out = append(out, strconv.Itoa(int(lo)))
			continue
		}
		hi, err := parsePort(to)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", spec, err)
		}
		if hi < lo {
			return nil, fmt.Errorf("port range %q ends before it begins", spec)
		}
		out = append(out, strconv.Itoa(int(lo))+"-"+strconv.Itoa(int(hi)))
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("is not a number")
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("is outside 1-65535")
	}
	return uint16(n), nil
}

// set renders an nft anonymous set, or a bare value when there is only one.
func set(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "{ " + strings.Join(values, ", ") + " }"
}
