//go:build darwin

package wglink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/route"
)

// Claiming a default route on macOS, which has no policy routing.
//
// Linux exempts the tunnel's own outer packets with a firewall mark and puts a default route
// in a table only unmarked traffic reaches. macOS has neither marks nor rules, so the claim
// is made the way wg-quick(8) makes it on this platform: two routes more specific than any
// default, and explicit routes around the tunnel for everything that must not go through it.
//
// # Why halves rather than a default
//
// 0.0.0.0/1 and 128.0.0.0/1 together cover every IPv4 address, and each is one bit longer
// than 0.0.0.0/0 — so they win on longest-prefix match without the existing default route
// being touched. That matters more here than it looks: the machine's real default is how the
// outer WireGuard packets leave, and replacing it would mean putting it back exactly as it
// was afterwards, from a copy taken while the network was in whatever state it was in. This
// way there is nothing to put back. Releasing means deleting four routes that meshp added
// and nothing else.
//
// # Why the carve-out is routed rather than marked
//
// Without a mark there is nothing to distinguish the tunnel's own packets from the traffic
// it carries, so they have to be named. Each endpoint gets a host route through whatever the
// default gateway was when the claim was made — which is also the reason this cannot survive
// the machine changing networks without another pass, and why the reconciler making that
// pass every minute matters more on this platform than on Linux (#160).

// egressHalves are the two routes that beat a default without replacing it.
var egressHalves = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}

// egressHalves6 is the same trick for IPv6.
var egressHalves6 = []netip.Prefix{
	netip.MustParsePrefix("::/1"),
	netip.MustParsePrefix("8000::/1"),
}

// egressRecordPath is where a claim is written down so that a later process can undo it.
//
// This is the routing half of what reclaimEgressLock does at start-up, and the reason it
// needs a file at all is that macOS has no equivalent of the firewall mark. Linux finds a
// claim it did not make by asking the kernel for the mark, which is a constant; the halves
// are a constant here too, but the host routes keeping the relay and the control plane off
// the tunnel are not — they are whatever that claim's endpoints were.
//
// Without this a restarted daemon can see that a claim exists, because EgressHeld reads the
// routing table, and has no way to take it off. It would log that it found one, delete
// nothing, and report success: Invariant 20 not holding on this platform, quietly.
//
// Under /var/run because routes do not survive a reboot either. Nothing depends on that
// directory being cleared, though — a record that outlived its routes asks for deletions
// that are already true, and deleteRoute treats those as success.
var egressRecordPath = filepath.Join("/var/run/meshp", "egress-routes")

// Router claims the default route on macOS.
//
// It remembers what it installed, because releasing means removing exactly those routes and
// nothing else — and it writes the same list down, because that memory dies with the
// process and the routes do not. See egressRecordPath.
type Router struct {
	mu       sync.Mutex
	claimed  []netip.Prefix
	viaLocal []netip.Prefix
}

// NewRouter returns something that can claim a default route.
func NewRouter() *Router { return &Router{} }

// Claim sends everything through the tunnel except what must not go through it.
//
// Order matters and is the opposite of Linux's. There the mark goes first, because a rule
// exempting marked traffic exempts nothing until something is marking it. Here the carve-out
// goes first, because the moment the halves are installed every packet with no more specific
// route goes into the tunnel — including the outer packets carrying the tunnel itself.
func (r *Router) Claim(iface string, endpoints []netip.AddrPort, excluded []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	gateway, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("wglink: finding the current default gateway: %w", err)
	}

	// Everything that must stay off the tunnel, pinned to the gateway the machine is using
	// now. Endpoints become host routes; excluded prefixes are already prefixes.
	var direct []netip.Prefix
	for _, endpoint := range endpoints {
		addr := endpoint.Addr().Unmap()
		if !addr.Is4() {
			// IPv6 endpoints are skipped rather than mishandled: pinning one needs the
			// IPv6 default gateway, which is a second lookup this does not do yet, and a
			// route through the wrong gateway is worse than no route.
			continue
		}
		direct = append(direct, netip.PrefixFrom(addr, addr.BitLen()))
	}
	for _, prefix := range excluded {
		if prefix.Addr().Is4() {
			direct = append(direct, prefix)
		}
	}

	for _, prefix := range direct {
		if err := addRoute(prefix, "-gateway", gateway.String()); err != nil {
			// Undo what has gone in, so a half-made claim does not leave the machine
			// routing some of its traffic somewhere nobody asked for.
			_ = r.releaseLocked()
			return fmt.Errorf("wglink: keeping %s off the tunnel: %w", prefix, err)
		}
		r.viaLocal = append(r.viaLocal, prefix)
	}

	halves, err := halvesFor(iface)
	if err != nil {
		_ = r.releaseLocked()
		return err
	}
	for _, prefix := range halves {
		if err := addRoute(prefix, "-interface", iface); err != nil {
			_ = r.releaseLocked()
			return fmt.Errorf("wglink: claiming %s: %w", prefix, err)
		}
		r.claimed = append(r.claimed, prefix)
	}

	// Written last, so the record only ever describes a claim that is fully in place. A
	// half-made claim has already been undone by the error paths above.
	recordClaim(append(append([]netip.Prefix{}, r.viaLocal...), r.claimed...))
	return nil
}

// halvesFor is the halves to claim, for the address families this tunnel actually carries.
//
// Not both unconditionally, which is what this did first. A network with no IPv6 address
// pool gives its devices a tunnel with no IPv6 address, and routing ::/1 into an interface
// that cannot carry it fails — so the whole claim failed, and a full tunnel never worked on
// an IPv4-only network. Claiming a family the tunnel has no address for would be wrong even
// if the kernel allowed it: it would take the machine's IPv6 traffic and drop it.
func halvesFor(iface string) ([]netip.Prefix, error) {
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("wglink: reading %s: %w", iface, err)
	}
	addrs, err := interfaceAddresses(device)
	if err != nil {
		return nil, err
	}

	var out []netip.Prefix
	for _, addr := range addrs {
		switch {
		case addr.Addr().Is4() && !hasFamily(out, true):
			out = append(out, egressHalves...)
		case addr.Addr().Is6() && !hasFamily(out, false):
			out = append(out, egressHalves6...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("wglink: %s has no addresses, so there is nothing to route into it", iface)
	}
	return out, nil
}

func hasFamily(prefixes []netip.Prefix, v4 bool) bool {
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() == v4 {
			return true
		}
	}
	return false
}

// Release gives the routing back by removing exactly what was added.
func (r *Router) Release() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.releaseLocked()
}

// releaseLocked removes what this Router installed. Not locked: every caller holds it.
//
// Every route is attempted even when one fails, and the errors are joined. Stopping at the
// first would leave the rest installed, which on this path means a machine still sending
// everything into a tunnel that is going away.
func (r *Router) releaseLocked() error {
	remembered := append(append([]netip.Prefix{}, r.claimed...), r.viaLocal...)

	var errs []error
	for _, prefix := range releaseTargets(remembered, recordedClaim()) {
		if err := deleteRoute(prefix); err != nil {
			errs = append(errs, err)
		}
	}
	r.claimed, r.viaLocal = nil, nil
	forgetClaim()
	return errors.Join(errs...)
}

// releaseTargets is which routes a release should take off.
//
// Three cases, and the third is why this is a function of its own rather than three lines
// inside releaseLocked — it is the one that guesses, and guessing wrong takes a machine off
// the network.
//
//   - What this process installed, which is the ordinary release.
//   - Plus what any process wrote down, which is how a restarted daemon undoes a claim it
//     did not make.
//   - And if there is neither, the halves. The only caller that reaches a release with
//     nothing to go on is one that checked EgressHeld first, so something *is* holding the
//     routing and the record has been lost. The halves are the part that captures every
//     packet the machine sends; guessing at them is better than leaving somebody with no way
//     out. The host routes cannot be guessed at and are left behind, which is survivable —
//     they point at a gateway that works, and the next claim corrects them.
func releaseTargets(remembered, recorded []netip.Prefix) []netip.Prefix {
	out := append([]netip.Prefix{}, remembered...)
	for _, prefix := range recorded {
		if !slices.Contains(out, prefix) {
			out = append(out, prefix)
		}
	}
	if len(out) == 0 {
		out = append(append(out, egressHalves...), egressHalves6...)
	}
	return out
}

// recordClaim writes down what this claim installed.
//
// Best effort, and deliberately not fatal: a claim that worked is worth having even on a
// host where /var/run cannot be written. What is lost is the ability of the *next* process
// to undo it precisely, which releaseLocked falls back for.
func recordClaim(prefixes []netip.Prefix) {
	if err := os.MkdirAll(filepath.Dir(egressRecordPath), 0o700); err != nil {
		return
	}
	var b strings.Builder
	for _, prefix := range prefixes {
		b.WriteString(prefix.String())
		b.WriteString("\n")
	}
	_ = os.WriteFile(egressRecordPath, []byte(b.String()), 0o600)
}

// recordedClaim reads back what some process claimed, or nothing.
//
// Unparseable lines are skipped rather than failing the read. A record that has been
// corrupted still names routes that ought to come off, and refusing the whole file over one
// bad line would leave a machine holding all of them.
func recordedClaim() []netip.Prefix {
	raw, err := os.ReadFile(egressRecordPath)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, line := range strings.Split(string(raw), "\n") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// forgetClaim removes the record, once the routes it names are gone.
func forgetClaim() { _ = os.Remove(egressRecordPath) }

// EgressHeld reports whether a default route claim is in place, whoever made it.
//
// Asked of the kernel rather than of this process's memory, which is the point: `meshp
// doctor` runs in a different process from the daemon, usually after the daemon has died,
// and the question it is answering is "is this machine refusing traffic because of something
// meshp left behind".
func EgressHeld() (bool, error) {
	present, err := routeExists(egressHalves[0])
	if err != nil {
		return false, err
	}
	return present, nil
}

// routeEnd is where the routing table currently sends a prefix.
//
// Either a gateway address or an interface name, because those are the two ways a route can
// be written and route(8) takes them as different flags.
type routeEnd struct {
	present bool
	gateway netip.Addr
	iface   string
}

// goesTo reports whether this is already the route a claim is asking for.
func (t routeEnd) goesTo(via []string) bool {
	if !t.present || len(via) != 2 {
		return false
	}
	switch via[0] {
	case "-interface":
		return t.iface != "" && t.iface == via[1]
	case "-gateway":
		want, err := netip.ParseAddr(via[1])
		return err == nil && t.gateway.IsValid() && t.gateway == want.Unmap()
	}
	return false
}

// routeTarget asks the kernel where a prefix currently goes.
func routeTarget(prefix netip.Prefix) (routeEnd, error) {
	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return routeEnd{}, fmt.Errorf("reading the routing table: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return routeEnd{}, fmt.Errorf("parsing the routing table: %w", err)
	}
	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if !ok || len(m.Addrs) < 2 {
			continue
		}
		if got, ok := prefixOf(m); !ok || got != prefix {
			continue
		}
		if link, ok := m.Addrs[1].(*route.LinkAddr); ok {
			return routeEnd{present: true, iface: linkName(link)}, nil
		}
		return routeEnd{present: true, gateway: addrOf(m.Addrs[1]).Unmap()}, nil
	}
	return routeEnd{}, nil
}

// linkName is what an interface route points at, by name.
//
// The routing socket may send the name or only the index, so the index is resolved when it
// has to be. An interface that has gone away since the message was read has no name, and a
// route pointing at one is not a route any claim is asking for.
func linkName(link *route.LinkAddr) string {
	if link.Name != "" {
		return link.Name
	}
	if link.Index == 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(link.Index)
	if err != nil {
		return ""
	}
	return iface.Name
}

// addRoute makes one route exist and point where it is asked to.
//
// Idempotent because the reconciler calls this every pass, and "already there" is the
// ordinary case rather than an error. What matters is what "already there" is taken to mean.
//
// It used to mean success, decided from what route(8) printed. That was wrong twice over.
// route(8) does not modify an existing destination, so a route whose gateway had gone stale
// stayed stale — and on this platform the carve-out keeping the relay and the control plane
// off the tunnel is a set of host routes pinned to whatever gateway was current when the
// claim was made. A laptop that moved to another network went on sending them to a gateway
// that is not on it, and with fail-closed egress in force that is a machine with no way out
// at all. The reconciler running every minute could not fix it, because every pass was told
// the route it wanted was already there (#160).
//
// The second mistake was reading that from the command's output at all. The first attempt at
// this fix branched on route(8) exiting non-zero with "File exists", which is what the old
// comment here claimed it does, and the correction never ran — so the tests below still
// found the stale route. What the kernel says is the only thing that cannot be misread, so
// this asks the routing table before and after rather than trusting either the exit code or
// the message.
//
// Changing in place is preferred to replacing: deleting first leaves a window with no route
// at all, and for the halves that window is one where traffic leaves outside the tunnel.
// Replacing is the fallback for a route that cannot be changed, because a leak measured in
// milliseconds is better than a claim that silently is not what it says.
func addRoute(prefix netip.Prefix, via ...string) error {
	target, err := routeTarget(prefix)
	if err != nil {
		return err
	}
	if target.goesTo(via) {
		return nil
	}

	if !target.present {
		out, err := routeCommand("add", prefix, via...)
		if err == nil {
			return nil
		}
		// It appeared between the read and the write, which is the only way this happens
		// and is not a failure of anything.
		if !bytes.Contains(out, []byte("File exists")) {
			return fmt.Errorf("route add %s: %w: %s", prefix, err, trimNewline(out))
		}
	}

	if _, err := routeCommand("change", prefix, via...); err == nil {
		if now, err := routeTarget(prefix); err == nil && now.goesTo(via) {
			return nil
		}
	}

	if err := deleteRoute(prefix); err != nil {
		return err
	}
	if out, err := routeCommand("add", prefix, via...); err != nil {
		return fmt.Errorf("route add %s: %w: %s", prefix, err, trimNewline(out))
	}

	// Verified rather than assumed, because everything above this line was once assumed.
	now, err := routeTarget(prefix)
	if err != nil {
		return err
	}
	if !now.goesTo(via) {
		return fmt.Errorf("wglink: %s was replaced and still does not go to %s",
			prefix, strings.Join(via, " "))
	}
	return nil
}

// routeCommand runs one route(8) verb against one prefix.
func routeCommand(verb string, prefix netip.Prefix, via ...string) ([]byte, error) {
	family := "-inet"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	args := append([]string{"-n", verb, family, prefix.String()}, via...)
	return exec.CommandContext(ctx, "/sbin/route", args...).CombinedOutput()
}

// deleteRoute removes one, treating "it is not there" as success.
func deleteRoute(prefix netip.Prefix) error {
	family := "-inet"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/sbin/route",
		"-n", "delete", family, prefix.String()).CombinedOutput()
	if err == nil {
		return nil
	}
	if bytes.Contains(out, []byte("not in table")) {
		return nil
	}
	return fmt.Errorf("route delete %s: %w: %s", prefix, err, trimNewline(out))
}

// defaultGateway is where the machine currently sends what it cannot route otherwise.
//
// Read from the routing table rather than remembered, because the claim is made against
// whatever the machine is using at the moment it is made. A laptop that changed networks
// since the last pass has a different one, and pinning the tunnel's endpoints to the old one
// would send them nowhere.
func defaultGateway() (netip.Addr, error) {
	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("reading the routing table: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing the routing table: %w", err)
	}

	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if !ok || len(m.Addrs) < 2 {
			continue
		}
		dst, gw := addrOf(m.Addrs[0]), addrOf(m.Addrs[1])
		// The default route: destination 0.0.0.0 with no netmask, or one of all zeroes.
		if !dst.Is4() || dst != netip.AddrFrom4([4]byte{}) || !gw.IsValid() || !gw.Is4() {
			continue
		}
		// Not one of ours. A machine that already has meshp's halves installed still has a
		// real default underneath them, and that is the one to pin endpoints to.
		return gw, nil
	}
	return netip.Addr{}, errors.New("this machine has no IPv4 default route to send the tunnel's own packets through")
}

// routeExists reports whether a prefix is in the table.
func routeExists(want netip.Prefix) (bool, error) {
	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return false, fmt.Errorf("reading the routing table: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return false, fmt.Errorf("parsing the routing table: %w", err)
	}
	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if got, ok := prefixOf(m); ok && got == want {
			return true, nil
		}
	}
	return false, nil
}

// egressUndo removes the routes this platform's claim installs.
//
// The halves only. The endpoint routes meshp adds alongside them point at the machine's real
// gateway, which is where those destinations would have gone anyway — they are redundant
// rather than harmful once the halves are gone, and listing every one of them would bury the
// two commands that actually give the machine its network back.
func egressUndo() []string {
	var out []string
	for _, half := range append(append([]netip.Prefix{}, egressHalves...), egressHalves6...) {
		family := "-inet"
		if half.Addr().Is6() {
			family = "-inet6"
		}
		out = append(out, fmt.Sprintf("sudo route -n delete %s %s", family, half))
	}
	return out
}
