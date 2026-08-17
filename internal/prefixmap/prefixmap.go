// Package prefixmap chooses the range a colliding customer prefix is reached by.
//
// The decision logic, held in memory and free of any database, for the reason internal/ipam
// is: what makes a mapped range correct is arithmetic and a set of things it must not
// overlap, and both are far easier to get right and to test here than in SQL. The store
// persists what this decides.
//
// ADR-0020 is the why. Two customers of one MSP both use 192.168.1.0/24 and a technician's
// routing table cannot hold that prefix twice, so each colliding prefix is given a distinct
// range to be reached by and the device rewrites the destination on the way into the tunnel.
package prefixmap

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// Errors a caller is expected to tell apart.
var (
	// ErrExhausted means the block has no room left for a prefix of this size.
	ErrExhausted = errors.New("prefixmap: the mapped block has no free range of that size")

	// ErrUnmappable means the prefix cannot be given a mapped range at all, whatever the
	// block contains — a default route, or one larger than the block itself.
	ErrUnmappable = errors.New("prefixmap: this prefix cannot be mapped")
)

// Reserved is a range the allocator must not hand out.
//
// Mesh address pools, other mappings, and anything else already meaningful to a device that
// will hold the result. ADR-0020's warning is that choosing the block badly "recreates this
// problem one level up", and this is where that is prevented rather than hoped for.
type Reserved []netip.Prefix

// Allocate returns the lowest free range in block that can carry prefix.
//
// Same size as the prefix, because the host part is carried across unchanged: 100.71.5.5 is
// 192.168.1.5 at the other end. That is what makes the translation stateless, and a range of
// a different size could not express it.
//
// Lowest free rather than random or sequential-from-last. The result ends up in support
// tickets and in `ip route` output, so a deployment that has allocated three ranges should
// have three small numbers rather than three scattered ones, and re-running after a release
// should produce the same answer.
//
// Aligned to its own size, so the arithmetic on the device is a mask rather than an offset.
func Allocate(block, prefix netip.Prefix, reserved Reserved) (netip.Prefix, error) {
	if !block.IsValid() || !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("%w: block %v, prefix %v", ErrUnmappable, block, prefix)
	}
	if block.Addr().Is4() != prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%w: %v cannot come out of %v", ErrUnmappable, prefix, block)
	}
	if prefix.Bits() == 0 {
		// A default route contains every address, so there is no distinct range to reach it
		// by. Two full tunnels on one device stay refused, which is the honest answer.
		return netip.Prefix{}, fmt.Errorf("%w: a default route has nothing to be mapped into", ErrUnmappable)
	}
	if prefix.Bits() < block.Bits() {
		// A customer network larger than the whole block. Distinguished from exhaustion
		// because no amount of freeing up would help.
		return netip.Prefix{}, fmt.Errorf("%w: %v is larger than the block %v", ErrUnmappable, prefix, block)
	}

	for candidate := range candidates(block, prefix.Bits()) {
		if overlapsAny(candidate, reserved) {
			continue
		}
		return candidate, nil
	}
	return netip.Prefix{}, fmt.Errorf("%w: %v in %v", ErrExhausted, prefix, block)
}

// candidates walks the block in aligned steps of the requested size, lowest first.
//
// An iterator rather than a slice: a /16 block cut into /30s is sixteen thousand ranges, and
// all but the first few are usually reserved. Building them all to use one is work nobody
// asked for, on a path the control plane runs while a device waits.
func candidates(block netip.Prefix, bits int) func(func(netip.Prefix) bool) {
	return func(yield func(netip.Prefix) bool) {
		addr := block.Masked().Addr()
		for {
			candidate := netip.PrefixFrom(addr, bits)
			if !block.Contains(addr) {
				return
			}
			if !yield(candidate) {
				return
			}
			next, ok := advance(addr, bits)
			if !ok {
				return // the address space ran out before the block did
			}
			addr = next
		}
	}
}

// advance returns the first address of the next aligned range of this size.
func advance(addr netip.Addr, bits int) (netip.Addr, bool) {
	// The last address of this range, then one past it. Adding the range's size directly
	// would need arithmetic on a 128-bit integer; walking the boundary is the same thing
	// expressed with what netip already offers.
	last := lastOf(netip.PrefixFrom(addr, bits))
	next := last.Next()
	return next, next.IsValid()
}

// lastOf returns the highest address in a prefix.
func lastOf(p netip.Prefix) netip.Addr {
	bytes := p.Addr().AsSlice()
	for i := p.Bits(); i < len(bytes)*8; i++ {
		bytes[i/8] |= 1 << (7 - i%8)
	}
	addr, _ := netip.AddrFromSlice(bytes)
	return addr
}

// overlapsAny reports whether a candidate touches anything spoken for.
//
// Overlap in either direction, which is the part that is easy to get wrong: a candidate /24
// inside a reserved /16 does not contain it, and a reserved /28 inside a candidate /24 is not
// contained by it either. Both are collisions.
func overlapsAny(candidate netip.Prefix, reserved Reserved) bool {
	return slices.ContainsFunc(reserved, func(r netip.Prefix) bool {
		return r.IsValid() && r.Addr().Is4() == candidate.Addr().Is4() &&
			(r.Overlaps(candidate) || candidate.Overlaps(r))
	})
}

// Colliding reports the prefixes carried in more than one of a device's networks.
//
// The input is what each network the device belongs to carries. A prefix appearing in two of
// them is one the device's routing table cannot hold twice, which is the whole condition
// ADR-0020 addresses.
//
// Identical prefixes only, not overlapping ones. ADR-0019 settled that overlap is decided by
// longest match and is well defined — a /24 inside somebody else's /16 is reached by the /24,
// which is what the operator meant. Only an exact repeat is genuinely ambiguous.
//
// Default routes are excluded here as well as refused by Allocate, because this is what
// decides whether anything is wrong at all: reporting a device as colliding when the only
// repeat is 0.0.0.0/0 would mark two ordinary full-tunnel networks as a fault nobody can fix.
func Colliding(byNetwork map[string][]netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]map[string]bool)
	for network, prefixes := range byNetwork {
		for _, p := range prefixes {
			if !p.IsValid() || p.Bits() == 0 {
				continue
			}
			p = p.Masked()
			if seen[p] == nil {
				seen[p] = make(map[string]bool)
			}
			seen[p][network] = true
		}
	}

	var out []netip.Prefix
	for prefix, networks := range seen {
		if len(networks) > 1 {
			out = append(out, prefix)
		}
	}
	// Sorted, so the same device produces the same list every pass rather than reordering
	// with map iteration and looking like something changed.
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}
