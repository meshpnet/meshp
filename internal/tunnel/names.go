package tunnel

import (
	"net/netip"
	"strings"

	"github.com/meshpnet/meshp/internal/dns"
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
