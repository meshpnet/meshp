//go:build linux

package wglink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/jsimonetti/rtnetlink/v2"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The full-tunnel routing mechanism, decided in ADR-0019.
//
// A device claiming a default route has one problem to solve: the outer WireGuard packets
// carrying the tunnel must not be sent into it. Put 0.0.0.0/0 on the tunnel in the main
// table and the packets to the relay match it, get encapsulated, and are routed back into
// the tunnel they belong to — the tunnel never establishes, and since ADR-0011 installs the
// kill switch first, the device is off the network entirely.
//
// So WireGuard marks its own packets and three rules sort them out:
//
//	32764:  from all lookup main suppress_prefixlength 0
//	32765:  not from all fwmark <mark> lookup <table>
//	32766:  from all lookup main                          (the kernel's own)
//
// An ordinary packet to a LAN address matches a specific route in main and goes out on the
// LAN. An ordinary packet to the internet finds only main's default route, which the first
// rule suppresses, so it falls to the second and takes the tunnel. A packet WireGuard
// generated carries the mark, fails `not fwmark`, falls past both, and follows whatever the
// real default route happens to be.
//
// The last part is the point. Nothing here records the gateway, so a laptop moving from
// Wi-Fi to tethering rewrites none of this: the marked traffic follows main, and main has
// already changed by itself. The alternative — a host route to each endpoint via the
// current gateway — has to be rebuilt on every roam, which is a race on the device that
// roams most, while a kill switch is holding the line.
//
// The ordering matters and the wrong way round is a bricked machine. If the mark rule came
// first, every unmarked packet would take the tunnel immediately, including packets to the
// local network — so a device would lose its own LAN, its printer, and the gateway its
// outer packets leave through.

const (
	// EgressMark is the firewall mark WireGuard puts on its own outer packets.
	//
	// The same number is used for the routing table, as wg-quick does: one value to
	// recognise, one to remove, and no chance of the two drifting apart. It is high and
	// arbitrary to stay clear of the marks other software picks, which conventionally live
	// in the low bits.
	EgressMark uint32 = 0x6d657368 // "mesh"

	// EgressTable is the routing table holding the tunnel's default route.
	EgressTable uint32 = 0x6d657368

	// suppressPriority must be lower than markPriority: main's specific routes have to be
	// consulted before anything is handed to the tunnel.
	suppressPriority uint32 = 32764
	markPriority     uint32 = 32765
)

// ClaimDefaultRoute sends everything except the tunnel's own packets through the tunnel.
//
// Idempotent, because the reconciler is a loop. Adding a rule that already exists returns
// EEXIST rather than replacing it, and a device that accumulated one rule per pass would
// end up with thousands.
func ClaimDefaultRoute(iface string, mark uint32) error {
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("wglink: no interface %s to claim a default route through: %w", iface, err)
	}

	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("wglink: rtnetlink: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// The table first, then the rules that point at it. A rule naming an empty table sends
	// traffic nowhere; a table nothing points at is inert. So the harmless order is the one
	// where the table is ready before anything is directed into it.
	for _, def := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	} {
		if err := addTableDefault(conn, uint32(link.Index), def); err != nil {
			return err
		}
	}

	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		if err := addRule(conn, suppressRule(family)); err != nil {
			return err
		}
		if err := addRule(conn, markRule(family, mark)); err != nil {
			return err
		}
	}
	return nil
}

// ReleaseDefaultRoute takes it all off again.
//
// Rules come off before the table, the reverse of installing them: a rule pointing at a
// table that has just been emptied is a rule that blackholes everything it matches, and
// this runs on a device whose traffic is going through it.
//
// Every step is attempted even when an earlier one fails, and the first error is returned
// at the end. Stopping at the first failure is right for an apply, which can be retried,
// and wrong for a teardown: what is left behind after a partial teardown is precisely the
// stuck state this exists to clear (Invariant 20).
func ReleaseDefaultRoute(mark uint32) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("wglink: rtnetlink: %w", err)
	}
	defer func() { _ = conn.Close() }()

	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		keep(deleteRule(conn, markRule(family, mark)))
		keep(deleteRule(conn, suppressRule(family)))
	}
	keep(flushEgressTable(conn))
	return first
}

// DefaultRouteClaimed reports whether the rules are installed.
//
// Asked at startup for the same reason the kill switch is: these outlive the process, so a
// daemon that died holding them leaves a device routing through a tunnel that is gone, and
// something has to notice and say so.
func DefaultRouteClaimed(mark uint32) (bool, error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return false, fmt.Errorf("wglink: rtnetlink: %w", err)
	}
	defer func() { _ = conn.Close() }()

	rules, err := conn.Rule.List()
	if err != nil {
		return false, fmt.Errorf("wglink: listing rules: %w", err)
	}
	for _, r := range rules {
		if r.Attributes == nil || r.Attributes.FwMark == nil {
			continue
		}
		if *r.Attributes.FwMark == mark {
			return true, nil
		}
	}
	return false, nil
}

// suppressRule consults main but ignores its default route, so specific routes — the local
// network, anything an administrator added — keep winning over the tunnel.
func suppressRule(family uint8) *rtnetlink.RuleMessage {
	zero := uint32(0)
	priority := suppressPriority
	table := uint32(unix.RT_TABLE_MAIN)
	return &rtnetlink.RuleMessage{
		Family: family,
		Action: unix.RTN_UNICAST,
		Table:  unix.RT_TABLE_MAIN,
		Attributes: &rtnetlink.RuleAttributes{
			Priority:          &priority,
			Table:             &table,
			SuppressPrefixLen: &zero,
		},
	}
}

// markRule sends everything that is not the tunnel's own traffic to the tunnel's table.
func markRule(family uint8, mark uint32) *rtnetlink.RuleMessage {
	priority := markPriority
	table := EgressTable
	m := mark
	return &rtnetlink.RuleMessage{
		Family: family,
		Action: unix.RTN_UNICAST,
		// Inverted: this matches packets that do NOT carry the mark. The marked ones are
		// WireGuard's own, and they have to fall through to the ordinary default route or
		// the tunnel has no way to reach its relay.
		Flags: unix.FIB_RULE_INVERT,
		Attributes: &rtnetlink.RuleAttributes{
			Priority: &priority,
			FwMark:   &m,
			Table:    &table,
		},
	}
}

// addTableDefault puts a default route through the tunnel into the egress table.
func addTableDefault(conn *rtnetlink.Conn, index uint32, prefix netip.Prefix) error {
	family := uint8(unix.AF_INET)
	if prefix.Addr().Is6() {
		family = unix.AF_INET6
	}
	table := EgressTable
	msg := &rtnetlink.RouteMessage{
		Family: family,
		// Unspecified in the header because the identifier does not fit in a byte; the
		// attribute below carries it.
		Table:     unix.RT_TABLE_UNSPEC,
		Protocol:  RouteProtocol,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Type:      unix.RTN_UNICAST,
		DstLength: 0,
		Attributes: rtnetlink.RouteAttributes{
			Dst:      net.IP(prefix.Addr().AsSlice()),
			OutIface: index,
			Table:    table,
		},
	}
	if err := conn.Route.Add(msg); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("wglink: adding the tunnel default route for %s: %w", prefix, err)
	}
	return nil
}

// flushEgressTable removes the routes this package put in the egress table, and only those:
// they carry meshp's protocol number, which is what makes removal exact rather than a guess
// at what else might be in there.
func flushEgressTable(conn *rtnetlink.Conn) error {
	routes, err := conn.Route.List()
	if err != nil {
		return fmt.Errorf("wglink: listing routes: %w", err)
	}
	var first error
	for _, r := range routes {
		if r.Attributes.Table != EgressTable || r.Protocol != RouteProtocol {
			continue
		}
		msg := r
		if err := conn.Route.Delete(&msg); err != nil && !errors.Is(err, unix.ESRCH) && first == nil {
			first = fmt.Errorf("wglink: removing a tunnel default route: %w", err)
		}
	}
	return first
}

func addRule(conn *rtnetlink.Conn, msg *rtnetlink.RuleMessage) error {
	if err := conn.Rule.Add(msg); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("wglink: adding a routing rule: %w", err)
	}
	return nil
}

func deleteRule(conn *rtnetlink.Conn, msg *rtnetlink.RuleMessage) error {
	if err := conn.Rule.Delete(msg); err != nil &&
		!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("wglink: removing a routing rule: %w", err)
	}
	return nil
}

// SetEgressMark tells WireGuard to mark the packets it sends.
//
// Separate from ClaimDefaultRoute because they fail differently and a caller needs to tell
// them apart: this touches the WireGuard device, which may not exist yet, while the rules
// touch the routing table, which always does. Both are needed for a full tunnel, and the
// mark must be set first — a rule that exempts marked traffic exempts nothing until
// something is marking it, and in the gap the tunnel's own packets are routed into the
// tunnel.
func SetEgressMark(iface string, mark uint32) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wglink: opening the WireGuard control socket: %w", err)
	}
	defer func() { _ = client.Close() }()

	m := int(mark)
	if err := client.ConfigureDevice(iface, wgtypes.Config{FirewallMark: &m}); err != nil {
		return fmt.Errorf("wglink: marking %s's traffic: %w", iface, err)
	}
	return nil
}
