package tunnel

import (
	"context"
	"net/netip"
	"strings"

	"github.com/meshpnet/meshp/internal/dns"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/peerset"
)

// Names is where this reconciler publishes the names its network can answer for.
//
// An interface rather than *dns.Zones so the tunnel package does not depend on a resolver
// being present. Nil is the ordinary case for a build or a test with no resolver, and means
// names are simply not published.
type Names interface {
	// Replace sets one membership's names, dropping whatever it had before.
	Replace(owner string, zone dns.Zone)

	// Forget drops them, for a device that has left a network.
	Forget(owner string)
}

// WithNames lets this reconciler publish the names of the network it is in.
func (r *Reconciler) WithNames(n Names) *Reconciler {
	r.names = n
	return r
}

// publishNames turns the peer set into resolvable names.
//
// The peer list the reconciler has just handed to WireGuard is the same data that answers an
// A query, which is the whole of ADR-0021's first decision: no second source, no query to
// the control plane, and the names keep working exactly as long as the tunnel configuration
// does.
//
// Keyed by interface name, like the route-claim registry, so a membership replaces its own
// names and nobody else's.
func (r *Reconciler) publishNames(state *peerset.Set) {
	if r.names == nil {
		return
	}

	suffix := suffixFrom(state)
	if suffix == "" {
		// A control plane that sends no search domain has not been told what this
		// network's names look like, so there are none. Publishing under a suffix
		// invented here would resolve names the server never said existed.
		r.names.Forget(r.membership.InterfaceName)
		return
	}

	zone := dns.Zone{Suffix: suffix}
	for _, peer := range state.Peers() {
		// The label the server assigned, not something derived here from the display
		// name. The server is the only party that can make it unique within the network,
		// which is what makes it resolvable at all — a name computed on the device would
		// be one guess among however many devices are guessing.
		label := peer.GetDnsLabel()
		if !dns.ValidLabel(label) {
			// Absent from a control plane too old to send one, or malformed from one that
			// should not have. Left out rather than repaired: repairing would name a
			// device something the server does not think it is called, so the name would
			// resolve here and nowhere else.
			continue
		}
		var addrs []netip.Addr
		for _, raw := range peer.GetAllowedIps() {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			// AllowedIPs are single-host prefixes for a peer's own addresses, so the
			// address is the prefix's. A wider one would be a carried route rather than
			// a device, and naming it would point a name at a whole network.
			if prefix.Bits() != prefix.Addr().BitLen() {
				continue
			}
			addrs = append(addrs, prefix.Addr())
		}
		if len(addrs) == 0 {
			continue
		}
		zone.Hosts = append(zone.Hosts, dns.Host{Name: label, Addrs: addrs})
	}

	r.names.Replace(r.membership.InterfaceName, zone)
}

// suffixFrom reads the network's DNS suffix out of desired state.
//
// The first search domain. There is one today; if there are ever several, the first is the
// network's own and the rest are additions, so taking the first stays correct.
func suffixFrom(state *peerset.Set) string {
	for _, d := range state.DNS().GetSearchDomains() {
		if s := strings.ToLower(strings.Trim(d, ".")); s != "" {
			return s
		}
	}
	return ""
}

// SystemResolver points the host's resolver at meshp for the names meshp owns.
//
// An interface, and nil on any host where meshp does not know how to configure the resolver
// and put it back afterwards. Nil means names resolve when something asks the agent directly
// and not otherwise — which is honest, and better than editing a file this agent cannot
// restore (ADR-0021).
type SystemResolver interface {
	Configure(ctx context.Context, iface string, server netip.AddrPort, domains []string) error
	Revert(ctx context.Context, iface string) error
}

// WithSystemResolver lets this reconciler make its network's names resolve for the whole
// machine, rather than only for something querying the agent directly.
//
// The address is a function because the resolver's port is the kernel's choice and is not
// known when the reconciler is built — 53 is almost always taken, so the agent asks for any
// port and reports what it got.
func (r *Reconciler) WithSystemResolver(s SystemResolver, addr func() netip.AddrPort) *Reconciler {
	r.systemResolver = s
	r.resolverAddr = addr
	return r
}

// applySystemResolver tells the host where to send queries for this network's names.
//
// After the interface exists, unlike publishing the names themselves: systemd-resolved
// configures a *link*, so there has to be one. That is also what makes this safe to scope —
// each membership configures its own interface and its own domain, so two networks on one
// device do not fight over a single global setting.
//
// Skipped when nothing changed, like the filter and the forwarding rules. Every call is a
// process spawn and a bus round trip, and the reconciler runs on a timer.
func (r *Reconciler) applySystemResolver(ctx context.Context, iface string, state *peerset.Set) []string {
	if r.systemResolver == nil || r.resolverAddr == nil {
		return nil
	}
	server := r.resolverAddr()

	var domains []string
	if suffix := suffixFrom(state); suffix != "" && server.IsValid() {
		domains = []string{suffix}
	}

	want := systemResolverState{server: server, domains: strings.Join(domains, ",")}
	r.mu.Lock()
	unchanged := r.lastResolver == want
	r.mu.Unlock()
	if unchanged {
		return nil
	}

	var err error
	if len(domains) == 0 {
		// No names to route, so the link goes back as it was. Reverting rather than
		// leaving a stale pointer: a link still aimed at this resolver after the device
		// left the network would send it queries nothing here can answer.
		err = r.systemResolver.Revert(ctx, iface)
	} else {
		err = r.systemResolver.Configure(ctx, iface, server, domains)
	}
	if err != nil {
		r.log.Error("this machine's resolver was not pointed at meshp",
			"interface", iface, "error", logx.SafeError(err),
			"consequence", "names in this network will not resolve; addresses still work")
		return []string{"dns"}
	}

	r.mu.Lock()
	r.lastResolver = want
	r.mu.Unlock()

	if len(domains) > 0 {
		r.log.Info("names in this network now resolve on this machine",
			"interface", iface, "resolver", server.String(), "domains", strings.Join(domains, ","))
	}
	return nil
}

// systemResolverState is what was last asked of the host, so an unchanged ask is skipped.
type systemResolverState struct {
	server  netip.AddrPort
	domains string
}
