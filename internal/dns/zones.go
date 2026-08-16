package dns

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// DefaultTTL is how long an answer may be cached.
//
// Short, because the underlying fact changes without warning: a device gets a new address
// when it re-enrols, and a peer that has been revoked should stop resolving quickly. Sixty
// seconds is long enough that a shell loop does not re-query on every iteration and short
// enough that a stale answer is a nuisance rather than an outage.
const DefaultTTL = 60

// Host is one name and the addresses it has in one network.
type Host struct {
	// Name is the device's label, without any suffix. Already lowercased.
	Name string

	Addrs []netip.Addr
}

// Zone is one membership's names.
type Zone struct {
	// Suffix is what this network's names end with, such as "acme.internal". Lowercased,
	// no leading or trailing dot.
	Suffix string

	Hosts []Host
}

// Zones is every name this device can answer for, across every network it is in.
//
// Safe for concurrent use: the resolver reads it while each membership's reconciler
// replaces its own zone from a state delta.
type Zones struct {
	mu sync.RWMutex

	// byOwner is keyed by interface name, the same key the route-claim registry uses, so
	// a membership replaces its own names and nobody else's.
	byOwner map[string]Zone
}

func NewZones() *Zones { return &Zones{byOwner: make(map[string]Zone)} }

// Replace sets one membership's names, dropping whatever it had before.
//
// Replace rather than merge, for the reason a snapshot replaces a peer set: a name that has
// gone must stop resolving, and merging would leave a revoked device answering forever.
func (z *Zones) Replace(owner string, zone Zone) {
	if z == nil {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if zone.Suffix == "" || len(zone.Hosts) == 0 {
		delete(z.byOwner, owner)
		return
	}
	z.byOwner[owner] = zone
}

// Forget drops a membership's names, for a device that has left a network.
func (z *Zones) Forget(owner string) {
	if z == nil {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.byOwner, owner)
}

// Suffixes lists the domains this device can answer for, sorted.
//
// Used to tell the system resolver which names to send here, and to decide whether a bare
// name can be offered as a search domain at all.
func (z *Zones) Suffixes() []string {
	if z == nil {
		return nil
	}
	z.mu.RLock()
	defer z.mu.RUnlock()

	out := make([]string, 0, len(z.byOwner))
	for _, zone := range z.byOwner {
		out = append(out, zone.Suffix)
	}
	sort.Strings(out)
	return out
}

// Resolution is what a lookup found.
type Resolution struct {
	Addrs []netip.Addr

	// Code is the disposition. Success with no addresses means the name exists in this
	// network and has no address of the requested family, which is a different answer
	// from the name not existing.
	Code RCode

	// Ambiguous names the fully-qualified alternatives when a bare name matched more than
	// one network. Non-empty only with RCodeRefused, and it is the whole point of
	// refusing: the caller can be told what to type instead.
	Ambiguous []string
}

// Lookup answers a name.
//
// Three cases, and the third is the one this package exists to get right.
//
// A name ending in one of this device's suffixes is answered from that network alone. There
// is nothing to disambiguate — the network is in the name.
//
// A name ending in a suffix this device does not have is not ours. NXDOMAIN would be a lie
// (the name may exist perfectly well elsewhere), so it is refused, and the system resolver
// should not have sent it here in the first place.
//
// A bare single label is looked up across every network, and answered **only if exactly one
// has it**. Two matches is refused, naming both alternatives. There is deliberately no
// precedence between memberships: an order would turn an ambiguous question into a confident
// wrong answer, sending a technician to whichever customer sorted first (ADR-0021). A
// person who is told `fileserver` is ambiguous has lost a keystroke; one who reaches the
// wrong company's file server has lost more than that.
func (z *Zones) Lookup(name string) Resolution {
	if z == nil {
		return Resolution{Code: RCodeNXDomain}
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return Resolution{Code: RCodeNXDomain}
	}

	z.mu.RLock()
	defer z.mu.RUnlock()

	if strings.Contains(name, ".") {
		return z.qualifiedLocked(name)
	}
	return z.bareLocked(name)
}

// qualifiedLocked answers a name that already says which network it means.
func (z *Zones) qualifiedLocked(name string) Resolution {
	for _, zone := range z.byOwner {
		label, ok := strings.CutSuffix(name, "."+zone.Suffix)
		if !ok {
			continue
		}
		// One label only. `a.b.acme.internal` is not a device in acme; answering it from
		// the host called `a` would invent a name nobody configured.
		if label == "" || strings.Contains(label, ".") {
			return Resolution{Code: RCodeNXDomain}
		}
		for _, host := range zone.Hosts {
			if host.Name == label {
				return Resolution{Addrs: host.Addrs, Code: RCodeSuccess}
			}
		}
		// The suffix is ours and the device is not in it. That is a real NXDOMAIN, and
		// saying so stops a stub from trying the next search domain and finding a
		// different customer's machine.
		return Resolution{Code: RCodeNXDomain}
	}
	// Not a suffix this device serves.
	return Resolution{Code: RCodeRefused}
}

// bareLocked answers a single label, or refuses to choose.
func (z *Zones) bareLocked(label string) Resolution {
	var found []netip.Addr
	var qualified []string

	for _, zone := range z.byOwner {
		for _, host := range zone.Hosts {
			if host.Name != label {
				continue
			}
			qualified = append(qualified, label+"."+zone.Suffix)
			found = host.Addrs
		}
	}

	switch len(qualified) {
	case 0:
		return Resolution{Code: RCodeNXDomain}
	case 1:
		return Resolution{Addrs: found, Code: RCodeSuccess}
	default:
		// Sorted so the same ambiguity reads the same way every time, rather than
		// changing order with map iteration and looking like a new problem each query.
		sort.Strings(qualified)
		return Resolution{Code: RCodeRefused, Ambiguous: qualified}
	}
}
