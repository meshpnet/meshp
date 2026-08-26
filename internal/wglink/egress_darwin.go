//go:build darwin

package wglink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
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

// Router claims the default route on macOS.
//
// It remembers what it installed, because releasing means removing exactly those routes and
// nothing else. That memory is this process's, so a Router that has never claimed cannot
// release what a previous process did — see EgressHeld, which asks the kernel instead.
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
	var errs []error
	for _, prefix := range append(append([]netip.Prefix{}, r.claimed...), r.viaLocal...) {
		if err := deleteRoute(prefix); err != nil {
			errs = append(errs, err)
		}
	}
	r.claimed, r.viaLocal = nil, nil
	return errors.Join(errs...)
}

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

// addRoute installs one route, treating "it is already there" as success.
//
// Idempotent because the reconciler calls this every pass. route(8) reports an existing
// route as "File exists" and exits non-zero, which is not a failure of anything.
func addRoute(prefix netip.Prefix, via ...string) error {
	family := "-inet"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	args := append([]string{"-n", "add", family, prefix.String()}, via...)
	out, err := exec.CommandContext(ctx, "/sbin/route", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	if bytes.Contains(out, []byte("File exists")) {
		return nil
	}
	return fmt.Errorf("route add %s: %w: %s", prefix, err, trimNewline(out))
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
