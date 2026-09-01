// Package egress works out what a device must still reach directly when it sends
// everything else through a tunnel.
//
// Claiming a default route is the one change an agent can make that removes its own ability
// to be corrected. The route captures the traffic, the kill switch refuses what the route
// did not send through the tunnel (ADR-0011), and between them they can take away the
// session that would have told the device to stop — leaving a machine that is off the
// network for a reason nobody watching can see. So the carve-out is not a convenience list.
// Each entry is a way the device stays reachable, and getting it wrong is the failure the
// whole feature is written around.
//
// It is computed in one place because two mechanisms consume it and they must agree. The
// firewall decides what may leave without the tunnel; the routing table decides what is not
// handed to the tunnel in the first place. A prefix in one and not the other produces a
// device that is broken in a way that looks like neither: either traffic is routed into a
// tunnel the firewall will not let it leave by, or it is left on the local link where the
// firewall then refuses it.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// alwaysExcluded are the prefixes no device should ever push through a tunnel.
//
// None of them route beyond the local link, and all of them carry something the machine
// needs in order to keep working: neighbour discovery and router advertisements, DHCP,
// mDNS, and the addresses an interface uses before it has been configured at all. Capturing
// them does not protect a user's privacy — nothing here leaves the link — and it does break
// the network it is running on.
var alwaysExcluded = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"), // IPv4 link-local, including APIPA
	netip.MustParsePrefix("224.0.0.0/4"),    // IPv4 multicast
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fe80::/10"), // IPv6 link-local, which NDP depends on
	netip.MustParsePrefix("ff00::/8"),  // IPv6 multicast
}

// Resolver turns a host name into addresses. Injectable because what this computes decides
// whether a device can be reached at all, and a test of that should not depend on DNS.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// SystemResolver looks names up the way the rest of the process would.
func SystemResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Inputs are what the carve-out is computed from.
type Inputs struct {
	// ControlURL is where this device's control plane lives. Its address is the one entry
	// that is not optional: without it the device cannot be told to stop, cannot be
	// revoked, and cannot report that anything is wrong.
	ControlURL string

	// RelayEndpoints are the "host:port" addresses from desired state. Every peer is
	// relayed until discovery exists (ADR-0002), so a device that cannot reach its relay
	// has a tunnel that carries nothing — and a default route into it.
	RelayEndpoints []string

	// LocalPrefixes are the networks this device is directly attached to. Losing them
	// costs the printer, the NAS and, more to the point, the gateway the outer WireGuard
	// packets are sent through.
	LocalPrefixes []netip.Prefix

	// ExtraPrefixes are what an administrator has asked to keep off the tunnel.
	ExtraPrefixes []string
}

// Carveout is what must stay reachable without the tunnel.
type Carveout struct {
	// Prefixes are destinations the default route must not capture and the lock must allow.
	Prefixes []netip.Prefix

	// Endpoints are single addresses with a port: the control plane and the relays. Kept
	// apart from Prefixes because the firewall can be told the port, and a rule naming one
	// port on one address is a smaller hole than a whole prefix.
	Endpoints []netip.AddrPort
}

// ErrNoControlPlane means the control plane's address could not be determined.
//
// Returned rather than worked around. A device that claims a default route and installs a
// lock without knowing where its control plane is has removed the only channel that could
// undo either, and it has done so silently. Refusing is visible: the group goes unhonoured
// and the control plane can see a device that is not where it should be.
var ErrNoControlPlane = errors.New("egress: cannot determine the control plane's address")

// Compute works out what must stay off the tunnel.
//
// A resolution failure for a relay is tolerated and one for the control plane is not. The
// difference is what each costs: a device that cannot reach a relay has no working tunnel
// and stays visibly unconverged, while a device that cannot reach its control plane cannot
// be told anything at all, including to stop.
func Compute(ctx context.Context, in Inputs, resolve Resolver) (Carveout, error) {
	if resolve == nil {
		resolve = SystemResolver
	}

	var out Carveout
	control, err := endpointsOf(ctx, in.ControlURL, resolve)
	if err != nil || len(control) == 0 {
		return Carveout{}, fmt.Errorf("%w: %q", ErrNoControlPlane, in.ControlURL)
	}
	out.Endpoints = append(out.Endpoints, control...)

	for _, raw := range in.RelayEndpoints {
		// Best effort: a relay that will not resolve costs that relay.
		if eps, err := hostPortEndpoints(ctx, raw, resolve); err == nil {
			out.Endpoints = append(out.Endpoints, eps...)
		}
	}

	prefixes := append([]netip.Prefix(nil), alwaysExcluded...)
	prefixes = append(prefixes, in.LocalPrefixes...)
	for _, raw := range in.ExtraPrefixes {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			// One unusable exclusion costs that exclusion. Refusing the whole carve-out
			// would leave the device with no route claimed at all over a typo.
			continue
		}
		prefixes = append(prefixes, p)
	}

	out.Prefixes = normalise(prefixes)
	out.Endpoints = normaliseEndpoints(out.Endpoints)
	return out, nil
}

// normalise sorts, deduplicates, and refuses a default route.
//
// The default route is the one prefix that must never appear here. Excluding ::/0 or
// 0.0.0.0/0 carves out everything, so the lock permits all traffic and the routing table
// hands nothing to the tunnel — a device that reports itself fully tunnelled and is not.
// That is precisely the dishonesty ADR-0011 exists to prevent, and it would arrive through
// a single mistyped line of administrator configuration.
func normalise(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() || p.Bits() == 0 {
			continue
		}
		masked := netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		if _, dup := seen[masked]; dup {
			continue
		}
		seen[masked] = struct{}{}
		out = append(out, masked)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func normaliseEndpoints(in []netip.AddrPort) []netip.AddrPort {
	seen := make(map[netip.AddrPort]struct{}, len(in))
	out := make([]netip.AddrPort, 0, len(in))
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

// endpointsOf turns a control URL into the addresses and port a session dials.
func endpointsOf(ctx context.Context, raw string, resolve Resolver) ([]netip.AddrPort, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("egress: no control url")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		// The scheme's default, because that is what was dialled.
		switch u.Scheme {
		case "https", "wss":
			port = "443"
		case "http", "ws":
			port = "80"
		default:
			return nil, fmt.Errorf("egress: no port and no default for scheme %q", u.Scheme)
		}
	}
	return resolveHostPort(ctx, host, port, resolve)
}

// hostPortEndpoints turns a "host:port" from desired state into addresses.
func hostPortEndpoints(ctx context.Context, raw string, resolve Resolver) ([]netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	return resolveHostPort(ctx, host, port, resolve)
}

func resolveHostPort(ctx context.Context, host, port string, resolve Resolver) ([]netip.AddrPort, error) {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("egress: %q is not a port", port)
	}

	// An address needs no resolver, which matters: a deployment that names its control
	// plane by address stays reachable on a device whose DNS the lock is about to refuse.
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(addr.Unmap(), uint16(n))}, nil
	}

	addrs, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.AddrPortFrom(a.Unmap(), uint16(n)))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("egress: %q resolved to nothing", host)
	}
	return out, nil
}

// LocalNetworks reports the networks this host is directly attached to, other than the
// tunnel's own.
//
// The tunnel is identified by the addresses it carries rather than by its name, and that is
// the whole of #200. It used to take the interface name, which is correct on Linux — where
// the interface really is called meshp0 — and matches nothing on macOS, where meshp0 is a
// label in a name file and the kernel knows a utunN. So the tunnel was not skipped, its own
// address was collected as a network to keep off the tunnel, and the claim then asked the
// kernel to route the device's own mesh address via the LAN gateway. It refuses, correctly,
// and a laptop in a network with an egress group had no internet at all.
//
// An address is a fact about an interface that every platform agrees on. A name is not: this
// project already carries a translation layer for exactly that reason (wglink's resolve), and
// anything comparing names here would need to know about it.
//
// Interfaces that are down are skipped too, since a prefix on a link with no carrier is a
// hole in the lock for a network that is not there.
func LocalNetworks(own []netip.Prefix) []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var out []netip.Prefix
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		carried := make([]netip.Prefix, 0, len(addrs))
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if p := netip.PrefixFrom(addr.Unmap(), ones); p.IsValid() {
				carried = append(carried, p)
			}
		}
		out = append(out, contributes(carried, own)...)
	}
	return normalise(out)
}

// contributes returns the networks one interface adds to the carve-out.
//
// Separate from LocalNetworks so the decision can be tested without needing a machine whose
// interfaces happen to be arranged the right way. That is not tidiness: a mutation that
// excluded only the matching prefix instead of the whole interface passed every test here,
// because the host it ran on carried exactly one global prefix per interface and the two
// behaviours are identical in that case.
//
// carried holds the interface's addresses as unmasked prefixes, so each one still knows both
// the address and the mask.
//
// An interface carrying one of the tunnel's addresses contributes nothing at all, not merely
// the prefix that matched. A tunnel with several addresses — every device has at least a v4
// and a v6 — would otherwise have the rest of them carved out and routed direct, which sends
// part of the mesh out of the wrong door.
func contributes(carried, own []netip.Prefix) []netip.Prefix {
	for _, p := range carried {
		if holds(own, p.Addr()) {
			return nil
		}
	}
	out := make([]netip.Prefix, 0, len(carried))
	for _, p := range carried {
		out = append(out, p.Masked())
	}
	return out
}

// holds reports whether one of the tunnel's own prefixes is this exact address.
//
// Compared as an address rather than by prefix containment, because containment would match
// far too much: the tunnel's addresses come from the network's range (ADR-0005), and a
// device whose LAN happened to overlap it would have its real network mistaken for the
// tunnel and quietly dropped from the carve-out.
func holds(own []netip.Prefix, addr netip.Addr) bool {
	for _, p := range own {
		if p.Addr() == addr {
			return true
		}
	}
	return false
}
