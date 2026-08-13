package acl

import (
	"fmt"
	"net/netip"
	"sort"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// Device is what the compiler needs to know about one member of a network.
type Device struct {
	// Key is the WireGuard public key, which is what identifies a device to everything
	// downstream and what makes two Devices comparable.
	Key string

	// Addresses are this device's own addresses, as single-host prefixes.
	Addresses []netip.Prefix

	// Tags are what selectors match on. Authoritative here because this comes from the
	// control plane's own record, and nowhere else — a device does not get to say what it
	// is tagged with.
	Tags []string
}

// hasTag reports whether this device carries a tag.
func (d Device) hasTag(tag string) bool {
	for _, t := range d.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// matches reports whether a selector picks this device.
//
// Literal prefixes match a device when they contain one of its addresses, so a rule written
// about 100.90.0.0/24 covers the devices inside it. That is what someone writing a prefix
// means, and the alternative — prefixes matching only non-device destinations — would make
// a policy's behaviour depend on whether an address happens to belong to a device.
func (d Device) matches(s Selector) bool {
	if s.IsEverything() {
		return true
	}
	if tag, ok := s.Tag(); ok {
		return d.hasTag(tag)
	}
	if prefix, ok := s.Prefix(); ok {
		for _, addr := range d.Addresses {
			if prefix.Overlaps(addr) {
				return true
			}
		}
	}
	return false
}

// Compile turns a policy into the filter one device should enforce.
//
// Two directions, and they are not equal in standing. The inbound rules are the
// authoritative check: traffic is permitted or dropped where it arrives, so a compromised
// or modified sender cannot talk its way past the receiver's policy (ADR-0007). The
// outbound rules describe the same permissions from the sending side and exist to fail
// fast — a connection refused locally is a far better error than one that vanishes — but
// they are never the boundary.
//
// What a filter governs is mesh traffic and nothing else. It is enforced on the WireGuard
// interface, so a policy cannot cut a device off from its control plane, from a relay, or
// from its own addresses — those never traverse the tunnel. That bound is worth knowing
// deliberately: it means the worst a mistaken policy can do is isolate devices from each
// other, and an operator always has a way back in to fix it.
func Compile(doc Document, self Device, peers []Device) (*meshpv1.PacketFilter, error) {
	if err := doc.Validate(); err != nil {
		return nil, err
	}

	filter := &meshpv1.PacketFilter{
		// The whole point. Anything no rule permits is dropped, which is what makes the
		// language allow-only and order-independent.
		DefaultDeny: true,
	}

	selfPrefixes := sortedPrefixes(self.Addresses)
	if len(selfPrefixes) == 0 {
		return nil, fmt.Errorf("acl: cannot compile a filter for a device with no addresses")
	}

	for i, rule := range doc.Rules {
		ports, err := rule.PortRanges()
		if err != nil {
			return nil, fmt.Errorf("acl: rule %d: %w", i, err)
		}
		proto := rule.CanonicalProtocol()

		// Inbound: this device is a destination, so whoever the rule allows may reach it.
		if matchesAny(self, rule.Dst) {
			if sources := resolve(rule.Src, peers); len(sources) > 0 {
				filter.Inbound = append(filter.Inbound, &meshpv1.PacketFilter_Rule{
					SrcPrefixes: sources,
					DstPrefixes: selfPrefixes,
					Protocol:    proto,
					Ports:       renderPorts(ports),
					Allow:       true,
				})
			}
		}

		// Outbound: this device is a source, so it may reach whoever the rule allows.
		if matchesAny(self, rule.Src) {
			if destinations := resolve(rule.Dst, peers); len(destinations) > 0 {
				filter.Outbound = append(filter.Outbound, &meshpv1.PacketFilter_Rule{
					SrcPrefixes: selfPrefixes,
					DstPrefixes: destinations,
					Protocol:    proto,
					Ports:       renderPorts(ports),
					Allow:       true,
				})
			}
		}
	}

	return filter, nil
}

// matchesAny reports whether any selector picks this device.
func matchesAny(d Device, selectors []Selector) bool {
	for _, s := range selectors {
		if d.matches(s) {
			return true
		}
	}
	return false
}

// resolve turns selectors into the concrete prefixes they name.
//
// Devices contribute their addresses; literal prefixes contribute themselves, whether or
// not any device sits inside them — a rule about an office subnet has to survive the subnet
// being empty of meshp devices, because that is exactly when a gateway is carrying it.
func resolve(selectors []Selector, peers []Device) []string {
	seen := make(map[netip.Prefix]struct{})

	for _, s := range selectors {
		if prefix, ok := s.Prefix(); ok {
			seen[prefix] = struct{}{}
			continue
		}
		for _, peer := range peers {
			if !peer.matches(s) {
				continue
			}
			for _, addr := range peer.Addresses {
				seen[addr] = struct{}{}
			}
		}
	}

	out := make([]netip.Prefix, 0, len(seen))
	for prefix := range seen {
		out = append(out, prefix)
	}
	return sortedPrefixes(out)
}

// sortedPrefixes renders prefixes in a stable order.
//
// Stability is not cosmetic. Everything downstream diffs this to decide whether a device's
// policy changed, and a set rendered in Go's map order would differ between two compilations
// of the same policy — so every state recomputation would look like a policy change and be
// pushed to every agent in the network.
func sortedPrefixes(prefixes []netip.Prefix) []string {
	sorted := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Addr() != b.Addr() {
			return a.Addr().Less(b.Addr())
		}
		return a.Bits() < b.Bits()
	})

	out := make([]string, 0, len(sorted))
	var last string
	for _, p := range sorted {
		s := p.String()
		if s == last {
			continue
		}
		out = append(out, s)
		last = s
	}
	return out
}

func renderPorts(ranges []PortRange) []string {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, r.String())
	}
	return out
}
