//go:build windows

package wglink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Claiming a default route on Windows, which has no policy routing and no firewall mark.
//
// The same problem macOS has and the same answer, for the same reason: two routes one bit
// longer than a default win on longest-prefix match without the machine's own default being
// touched, so there is nothing to put back afterwards. Releasing means deleting what meshp
// added and nothing else.
//
// What differs from macOS is only the mechanism. There it is route(8) and PF_ROUTE; here it
// is the IP Helper API, which takes a route rather than a line of text — so nothing parses
// output, and the localisation trap that rules netsh out never arises.
//
// The carve-out is routed rather than marked here too. Without a mark there is nothing
// distinguishing the tunnel's own outer packets from the traffic it carries, so each endpoint
// that must stay off the tunnel gets a host route through whatever the machine is currently
// using as its default gateway — which is why this cannot survive a change of network without
// another pass, and why the reconciler making one every minute matters (#160, #172).

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

// egressRecordPath is where a claim is written down so a later process can undo it.
//
// The same file macOS keeps and for the same reason: Linux finds a claim it did not make by
// asking the kernel for its firewall mark, and this platform has no mark. The halves are
// constants, but the host routes keeping the relay and the control plane off the tunnel are
// whatever that claim's endpoints were, and a restarted daemon has no other way to know them.
//
// Under ProgramData because that is where a Windows service's state belongs, and because it
// survives a crash — which is the only thing this has to survive. A record that outlived its
// routes asks for deletions that are already true, and deleting a route that is not there is
// success.
var egressRecordPath = filepath.Join(os.Getenv("ProgramData"), "meshp", "egress-routes")

// Router claims the default route on Windows. It satisfies tunnel.Egress.
type Router struct {
	mu       sync.Mutex
	claimed  []netip.Prefix
	viaLocal []netip.Prefix
}

// NewRouter returns something that can claim a default route.
func NewRouter() *Router { return &Router{} }

// Claim sends everything through the tunnel except what must not go through it.
//
// The carve-out first, for the reason macOS gives: the moment the halves are installed every
// packet with no more specific route goes into the tunnel, including the outer packets
// carrying the tunnel itself.
func (r *Router) Claim(iface string, endpoints []netip.AddrPort, excluded []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tunnelLUID, err := luidFor(iface)
	if err != nil {
		return err
	}
	gatewayLUID, gateway, err := defaultGateway(tunnelLUID)
	if err != nil {
		return fmt.Errorf("wglink: finding the current default gateway: %w", err)
	}

	var direct []netip.Prefix
	for _, endpoint := range endpoints {
		addr := endpoint.Addr().Unmap()
		if !addr.Is4() {
			// IPv6 endpoints are skipped rather than mishandled, exactly as on macOS:
			// pinning one needs the IPv6 default gateway, which is a second lookup this
			// does not do, and a route through the wrong gateway is worse than no route.
			continue
		}
		direct = append(direct, netip.PrefixFrom(addr, addr.BitLen()))
	}
	for _, prefix := range excluded {
		if prefix.Addr().Is4() {
			direct = append(direct, prefix.Masked())
		}
	}

	for _, prefix := range direct {
		if err := addRoute(gatewayLUID, prefix, gateway); err != nil {
			// Undo what has gone in, so a half-made claim does not leave the machine
			// routing some of its traffic somewhere nobody asked for.
			_ = r.releaseLocked()
			return fmt.Errorf("wglink: keeping %s off the tunnel: %w", prefix, err)
		}
		r.viaLocal = append(r.viaLocal, prefix)
	}

	for _, prefix := range halvesFor(tunnelLUID) {
		if err := addRoute(tunnelLUID, prefix, unspecifiedFor(prefix)); err != nil {
			_ = r.releaseLocked()
			return fmt.Errorf("wglink: claiming %s: %w", prefix, err)
		}
		r.claimed = append(r.claimed, prefix)
	}

	// Written last, so the record only ever describes a claim that is fully in place.
	recordClaim(append(append([]netip.Prefix{}, r.viaLocal...), r.claimed...))
	return nil
}

// Release gives the routing back.
func (r *Router) Release() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.releaseLocked()
}

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
// The same three cases macOS has, and the third is the one that guesses: a release reached
// with nothing remembered and nothing recorded is one whose caller checked EgressHeld first,
// so something is holding the routing and the record has been lost. The halves are the part
// that captures every packet the machine sends.
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

// EgressHeld reports whether a claim from a previous life is still in place.
func EgressHeld() (bool, error) {
	rows, err := winipcfg.GetIPForwardTable2(windowsIPv4)
	if err != nil {
		return false, fmt.Errorf("wglink: reading the routing table: %w", err)
	}
	for _, row := range rows {
		if row.DestinationPrefix.Prefix().Masked() == egressHalves[0] {
			return true, nil
		}
	}
	return false, nil
}

// egressUndo removes the routes this platform's claim installs.
//
// route(8) rather than the API, because this is printed for somebody at a console on a
// machine with no network. `route delete` is on every Windows and needs nothing installed.
func egressUndo() []string {
	var out []string
	for _, half := range append(append([]netip.Prefix{}, egressHalves...), egressHalves6...) {
		out = append(out, fmt.Sprintf("route delete %s", half.Addr()))
	}
	return out
}

// halvesFor is which families this adapter can carry.
//
// Asked rather than assumed, for the reason macOS asks: adding IPv6 halves to an adapter with
// no IPv6 address fails, and a claim that failed as a whole because of it would take the
// IPv4 tunnel down on every IPv4-only network.
func halvesFor(luid winipcfg.LUID) []netip.Prefix {
	out := append([]netip.Prefix{}, egressHalves...)
	if addrs, err := adapterAddresses(luid); err == nil {
		for _, addr := range addrs {
			if addr.Addr().Is6() {
				return append(out, egressHalves6...)
			}
		}
	}
	return out
}

// defaultGateway is where the machine currently sends what it cannot route otherwise.
//
// Read from the routing table rather than remembered, because a laptop that changed networks
// since the last pass has a different one and pinning the tunnel's endpoints to the old one
// would send them nowhere. The tunnel's own adapter is excluded: once the halves are in, a
// default route through meshp would otherwise be found here and the carve-out would point at
// itself.
func defaultGateway(exclude winipcfg.LUID) (winipcfg.LUID, netip.Addr, error) {
	rows, err := winipcfg.GetIPForwardTable2(windowsIPv4)
	if err != nil {
		return 0, netip.Addr{}, err
	}

	var best *winipcfg.MibIPforwardRow2
	for i := range rows {
		row := &rows[i]
		if row.InterfaceLUID == exclude || row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		next := row.NextHop.Addr()
		if !next.IsValid() || next.IsUnspecified() {
			continue
		}
		if best == nil || row.Metric < best.Metric {
			best = row
		}
	}
	if best == nil {
		return 0, netip.Addr{}, errors.New("this machine has no IPv4 default route")
	}
	return best.InterfaceLUID, best.NextHop.Addr().Unmap(), nil
}

// luidFor finds an adapter by the name meshp gave it.
func luidFor(iface string) (winipcfg.LUID, error) {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, fmt.Errorf("wglink: finding %s: %w", iface, err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(netIface.Index))
	if err != nil {
		return 0, fmt.Errorf("wglink: identifying %s: %w", iface, err)
	}
	return luid, nil
}

// addRoute makes one route exist and point where it is asked to.
//
// Idempotent because the reconciler calls this every pass, and corrective because "already
// there" is not the same as "already right". macOS learned that the hard way in #171: a
// carve-out pinned to the gateway of a network the laptop has left is never corrected if an
// existing destination is taken for success, and with fail-closed egress in force that is a
// machine with no way out. Deleting and re-adding rather than changing in place, because the
// IP Helper API has no change for a route — and the window is one this platform's reconciler
// closes on its next pass.
func addRoute(luid winipcfg.LUID, prefix netip.Prefix, nextHop netip.Addr) error {
	existing, err := luid.Route(prefix, nextHop)
	if err == nil && existing != nil {
		return nil
	}
	if err := luid.AddRoute(prefix, nextHop, 0); err != nil {
		if errors.Is(err, windowsObjectExists) {
			// A route to this destination exists and does not go where this claim needs it
			// to, or Route above would have found it. Replaced rather than left.
			if delErr := luid.DeleteRoute(prefix, nextHop); delErr != nil && !errors.Is(delErr, windowsNotFound) {
				return fmt.Errorf("replacing the route for %s: %w", prefix, delErr)
			}
			if addErr := luid.AddRoute(prefix, nextHop, 0); addErr != nil {
				return fmt.Errorf("adding the route for %s: %w", prefix, addErr)
			}
			return nil
		}
		return fmt.Errorf("adding the route for %s: %w", prefix, err)
	}
	return nil
}

// deleteRoute removes one, treating "it is not there" as success.
//
// Searched for rather than named, because a release may be undoing a claim this process did
// not make and the next hop it was installed with is not recorded — only the destination is.
func deleteRoute(prefix netip.Prefix) error {
	family := windowsIPv4
	if prefix.Addr().Is6() {
		family = windowsIPv6
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return fmt.Errorf("wglink: reading the routing table: %w", err)
	}
	var errs []error
	for i := range rows {
		row := &rows[i]
		if row.DestinationPrefix.Prefix().Masked() != prefix.Masked() {
			continue
		}
		if err := row.Delete(); err != nil && !errors.Is(err, windowsNotFound) {
			errs = append(errs, fmt.Errorf("wglink: removing the route for %s: %w", prefix, err))
		}
	}
	return errors.Join(errs...)
}

// unspecifiedFor is the next hop for a route through a point-to-point interface: there is no
// gateway on the other side of a tunnel to name.
func unspecifiedFor(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

// recordClaim writes down what this claim installed.
//
// Best effort: a claim that worked is worth having even where ProgramData cannot be written.
// What is lost is the ability of the next process to undo it precisely, which releaseTargets
// falls back for.
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
