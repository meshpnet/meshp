package nftables

import (
	"fmt"
	"net/netip"
	"strings"
)

// CarryChainName is the chain meshp owns inside the host's own filter table.
//
// A chain of its own, jumped to from FORWARD, rather than rules appended straight into
// FORWARD. meshp then rebuilds its chain as often as it likes and touches the host's chain
// exactly once in its whole life — and removal is deleting one jump rule rather than hunting
// for handles of rules it appended some time ago.
//
// This is the DOCKER-USER pattern, for the reason Docker uses it: a tool that has to manage
// somebody else's chain needs a seam it can own.
const CarryChainName = "meshp_carry"

// CarryTable is the table this lives in, which is not one of meshp's.
//
// `ip filter` is where iptables keeps FORWARD, and on any current distribution `iptables` is
// iptables-nft, so this is the same chain a foreign FORWARD drop policy lives in (#89).
//
// Writing here is a real intrusion and is done for exactly one reason: an accept in meshp's
// own table cannot undo a drop in this one. Every chain registered at a hook runs, and a drop
// in any of them ends the packet, so there is no rule meshp can write in a table of its own
// that survives another table's policy.
const CarryTable = "ip filter"

// RenderCarry builds the rules that let this host forward what it advertises.
//
// The chain only, never the jump. Adding the jump edits a chain meshp does not own, which
// happens once and is checked first — see the apply path. Keeping the two apart means the
// part that runs on every reconcile touches nothing but meshp's own chain.
//
// Flushed and refilled rather than deleted and recreated, because deleting it would break the
// jump FORWARD holds to it.
//
// No prefixes empties the chain, which is what a device that has stopped carrying needs: the
// jump stays and lands on nothing (Invariant 20).
func RenderCarry(iface string, prefixes []netip.Prefix) (string, error) {
	if !interfaceNamePattern.MatchString(iface) {
		return "", fmt.Errorf("nftables: %q is not a usable interface name", iface)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "add chain %s %s\n", CarryTable, CarryChainName)
	fmt.Fprintf(&b, "flush chain %s %s\n", CarryTable, CarryChainName)

	for _, p := range prefixes {
		if !p.IsValid() || !p.Addr().Is4() {
			// This is the IPv4 table. An IPv6 prefix belongs in `ip6 filter`, and putting
			// one here would be a rule that matches nothing while looking correct.
			continue
		}
		// Both directions. A reply that cannot come back is the same outage as a request
		// that cannot go out, and the foreign policy drops both.
		fmt.Fprintf(&b, "add rule %s %s iifname \"%s\" ip daddr %s accept\n",
			CarryTable, CarryChainName, iface, p.Masked())
		fmt.Fprintf(&b, "add rule %s %s oifname \"%s\" ip saddr %s accept\n",
			CarryTable, CarryChainName, iface, p.Masked())
	}
	return b.String(), nil
}

// CarryJump is the one rule meshp adds to a chain it does not own.
//
// Appended rather than inserted, which the probe behind #89 settled: an appended jump is
// still reached on a host where Docker has put its own jumps ahead of it, because those
// chains return rather than ending the packet. Inserting at the top would put meshp ahead of
// rules an operator wrote deliberately, which is a claim this has no business making.
func CarryJump() string {
	return fmt.Sprintf("add rule %s FORWARD jump %s\n", CarryTable, CarryChainName)
}
