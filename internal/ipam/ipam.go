// Package ipam allocates mesh addresses from a prefix.
//
// This is the decision logic, held in memory. In production the authoritative
// record lives in the address_allocations table and an Allocator is rehydrated
// from it with Restore; the rules encoded here are the specification that the
// SQL path must match. Keeping the rules in one testable place is the point —
// address reuse bugs are the kind that surface weeks later as "sometimes I reach
// the wrong machine".
//
// Two behaviours are deliberate and easy to get wrong:
//
//   - A released address is quarantined, not freed. DNS caches, compiled ACLs
//     and long-lived connections all still refer to it after the device holding
//     it has gone (Invariant 17).
//   - Allocation sweeps forward and wraps, rather than reusing the lowest free
//     address. That maximises the time before any address is handed out again,
//     which is the same thing quarantine is trying to achieve.
package ipam

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
)

// Errors returned by an Allocator. Callers are expected to distinguish these:
// "the pool is full" and "everything free is still cooling down" need different
// operator responses, which is why they are not the same error.
var (
	ErrExhausted        = errors.New("ipam: no address available in pool")
	ErrAllQuarantined   = errors.New("ipam: every free address is quarantined")
	ErrOutOfRange       = errors.New("ipam: address is not in the pool prefix")
	ErrAlreadyAllocated = errors.New("ipam: address is already allocated")
	ErrNotAllocated     = errors.New("ipam: address is not allocated")
	ErrReserved         = errors.New("ipam: address is reserved")
	ErrQuarantined      = errors.New("ipam: address is quarantined")
)

// DefaultQuarantine is how long a released address is withheld. Fifteen minutes
// comfortably outlives our default DNS TTL of 60s and a typical TCP retransmit
// window, without making small pools feel full.
const DefaultQuarantine = 15 * time.Minute

// Config describes a pool.
type Config struct {
	// Prefix is the allocatable range. It is masked on construction, so
	// 100.90.0.5/16 and 100.90.0.0/16 describe the same pool.
	Prefix netip.Prefix

	// Quarantine is how long a released address is withheld before it can be
	// handed out again. Zero means DefaultQuarantine; use a negative duration to
	// disable quarantine entirely, which is only appropriate in tests.
	Quarantine time.Duration

	// Reserved addresses are never allocated. Use this for infrastructure that
	// is addressed by convention, such as the first few addresses in a network.
	// Addresses outside the prefix are rejected rather than ignored.
	Reserved []netip.Addr
}

// Entry is one allocation, used to rehydrate an Allocator from storage.
type Entry struct {
	Addr   netip.Addr
	Holder string
	// ReleasedAt is zero for an active allocation. When set, the address is
	// quarantined until ReleasedAt plus the pool's quarantine period.
	ReleasedAt time.Time
}

// Stats describes pool occupancy.
type Stats struct {
	Allocated   int
	Quarantined int
	// Usable is the number of allocatable addresses, or -1 when the prefix is
	// large enough that the count does not fit in an int64. A /48 of IPv6 has
	// more addresses than there are useful things to say about the number.
	Usable int64
	Free   int64 // -1 when Usable is -1
}

// Allocator hands out addresses from a single prefix. It is safe for concurrent
// use.
type Allocator struct {
	clk clock.Clock

	prefix     netip.Prefix
	quarantine time.Duration
	first      netip.Addr // lowest address in the prefix
	last       netip.Addr // highest address in the prefix
	size       int64      // total addresses in the prefix, -1 when uncountable
	usable     int64      // size minus reservations, -1 when uncountable
	reserved   map[netip.Addr]struct{}

	mu          sync.Mutex
	allocated   map[netip.Addr]string
	quarantined map[netip.Addr]time.Time // addr -> instant it becomes free
	cursor      netip.Addr               // next address to consider
}

// New builds an Allocator. It returns an error for a prefix that cannot hold a
// single allocatable address, which is a configuration mistake worth failing
// loudly rather than discovering on first enrolment.
func New(cfg Config, clk clock.Clock) (*Allocator, error) {
	if clk == nil {
		clk = clock.System{}
	}
	if !cfg.Prefix.IsValid() {
		return nil, fmt.Errorf("ipam: invalid prefix %q", cfg.Prefix)
	}

	p := cfg.Prefix.Masked()
	a := &Allocator{
		clk:         clk,
		prefix:      p,
		quarantine:  cfg.Quarantine,
		reserved:    make(map[netip.Addr]struct{}),
		allocated:   make(map[netip.Addr]string),
		quarantined: make(map[netip.Addr]time.Time),
	}
	if a.quarantine == 0 {
		a.quarantine = DefaultQuarantine
	}

	a.first = p.Addr()
	a.last = lastAddr(p)

	// Structural reservations. IPv4 loses the network and broadcast addresses,
	// except on /31 and /32 where RFC 3021 makes both usable. IPv6 loses only
	// the subnet-router anycast address at the base of the prefix; there is no
	// broadcast address to lose.
	hostBits := p.Addr().BitLen() - p.Bits()
	if p.Addr().Is4() {
		if hostBits >= 2 {
			a.reserved[a.first] = struct{}{}
			a.reserved[a.last] = struct{}{}
		}
	} else if hostBits >= 1 {
		a.reserved[a.first] = struct{}{}
	}

	for _, r := range cfg.Reserved {
		r = r.Unmap()
		if !p.Contains(r) {
			return nil, fmt.Errorf("%w: reserved %v not in %v", ErrOutOfRange, r, p)
		}
		a.reserved[r] = struct{}{}
	}

	a.size = countAddrs(hostBits)
	a.usable = countUsable(hostBits, len(a.reserved))
	if a.usable == 0 {
		return nil, fmt.Errorf("ipam: prefix %v has no allocatable addresses", p)
	}

	a.cursor = a.first
	return a, nil
}

// Prefix returns the pool's masked prefix.
func (a *Allocator) Prefix() netip.Prefix { return a.prefix }

// Allocate returns the next free address and records holder against it.
func (a *Allocator) Allocate(holder string) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.clk.Now()
	a.reclaimLocked(now)

	// Bound the sweep so a full pool terminates. The bound must be the total
	// size of the prefix rather than the usable count: reserved and quarantined
	// addresses are visited and skipped, so a shorter bound can stop before
	// reaching a free address and report a full pool that is not full. For
	// prefixes too large to count we cap the work instead — with a cursor that
	// only moves forward, a free address is always close by unless something is
	// badly wrong.
	steps := a.size
	if steps < 0 {
		steps = 1 << 20
	}

	sawQuarantined := false
	addr := a.cursor
	for range steps {
		if !a.isAllocatableLocked(addr, now, &sawQuarantined) {
			addr = a.nextLocked(addr)
			continue
		}
		a.allocated[addr] = holder
		a.cursor = a.nextLocked(addr)
		return addr, nil
	}

	if sawQuarantined {
		return netip.Addr{}, ErrAllQuarantined
	}
	return netip.Addr{}, ErrExhausted
}

// AllocateSpecific records a particular address against holder. It is used when
// importing existing state and when an operator pins an address deliberately.
func (a *Allocator) AllocateSpecific(addr netip.Addr, holder string) error {
	addr = addr.Unmap()

	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.clk.Now()
	a.reclaimLocked(now)

	if !a.prefix.Contains(addr) {
		return fmt.Errorf("%w: %v not in %v", ErrOutOfRange, addr, a.prefix)
	}
	if _, ok := a.reserved[addr]; ok {
		return fmt.Errorf("%w: %v", ErrReserved, addr)
	}
	if _, ok := a.allocated[addr]; ok {
		return fmt.Errorf("%w: %v", ErrAlreadyAllocated, addr)
	}
	if until, ok := a.quarantined[addr]; ok && now.Before(until) {
		return fmt.Errorf("%w: %v until %v", ErrQuarantined, addr, until)
	}

	delete(a.quarantined, addr)
	a.allocated[addr] = holder
	return nil
}

// Release moves an allocated address into quarantine. Releasing an address that
// is not allocated is an error rather than a no-op: it almost always means the
// caller has lost track of which membership owns what.
func (a *Allocator) Release(addr netip.Addr) error {
	addr = addr.Unmap()

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.allocated[addr]; !ok {
		return fmt.Errorf("%w: %v", ErrNotAllocated, addr)
	}
	delete(a.allocated, addr)
	if a.quarantine > 0 {
		a.quarantined[addr] = a.clk.Now().Add(a.quarantine)
	}
	return nil
}

// Reclaim frees addresses whose quarantine has expired and reports how many.
// Allocate reclaims implicitly; this exists so a background job can keep the
// stored state tidy and so the count is observable.
func (a *Allocator) Reclaim() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reclaimLocked(a.clk.Now())
}

// Holder reports which holder an address is allocated to.
func (a *Allocator) Holder(addr netip.Addr) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, ok := a.allocated[addr.Unmap()]
	return h, ok
}

// Restore rehydrates the allocator from stored state, replacing anything it
// currently holds. Entries outside the prefix are an error: silently dropping
// them would let a pool reconfiguration hand out an address that a live device
// is still using.
func (a *Allocator) Restore(entries []Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	allocated := make(map[netip.Addr]string, len(entries))
	quarantined := make(map[netip.Addr]time.Time)

	for _, e := range entries {
		addr := e.Addr.Unmap()
		if !a.prefix.Contains(addr) {
			return fmt.Errorf("%w: restored %v not in %v", ErrOutOfRange, addr, a.prefix)
		}
		if e.ReleasedAt.IsZero() {
			allocated[addr] = e.Holder
			continue
		}
		if a.quarantine > 0 {
			quarantined[addr] = e.ReleasedAt.Add(a.quarantine)
		}
	}

	a.allocated = allocated
	a.quarantined = quarantined

	// Resume sweeping after the highest live address so restored state does not
	// immediately start reusing the low end of the pool.
	a.cursor = a.first
	var highest netip.Addr
	for addr := range allocated {
		if !highest.IsValid() || addr.Compare(highest) > 0 {
			highest = addr
		}
	}
	if highest.IsValid() {
		a.cursor = a.nextLocked(highest)
	}
	a.reclaimLocked(a.clk.Now())
	return nil
}

// Snapshot returns the live allocations, sorted by address. Sorted output keeps
// callers — including tests and API responses — free of map iteration order.
func (a *Allocator) Snapshot() []Entry {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Entry, 0, len(a.allocated))
	for addr, holder := range a.allocated {
		out = append(out, Entry{Addr: addr, Holder: holder})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Compare(out[j].Addr) < 0 })
	return out
}

// Stats reports occupancy.
func (a *Allocator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.clk.Now()
	quarantined := 0
	for _, until := range a.quarantined {
		if now.Before(until) {
			quarantined++
		}
	}
	s := Stats{
		Allocated:   len(a.allocated),
		Quarantined: quarantined,
		Usable:      a.usable,
		Free:        -1,
	}
	if a.usable >= 0 {
		s.Free = a.usable - int64(s.Allocated) - int64(quarantined)
	}
	return s
}

// --- internals -------------------------------------------------------------

func (a *Allocator) isAllocatableLocked(addr netip.Addr, now time.Time, sawQuarantined *bool) bool {
	if _, ok := a.reserved[addr]; ok {
		return false
	}
	if _, ok := a.allocated[addr]; ok {
		return false
	}
	if until, ok := a.quarantined[addr]; ok && now.Before(until) {
		*sawQuarantined = true
		return false
	}
	return true
}

// nextLocked advances one address, wrapping from the end of the prefix back to
// the start.
func (a *Allocator) nextLocked(addr netip.Addr) netip.Addr {
	if addr.Compare(a.last) >= 0 {
		return a.first
	}
	return addr.Next()
}

func (a *Allocator) reclaimLocked(now time.Time) int {
	n := 0
	for addr, until := range a.quarantined {
		if !now.Before(until) {
			delete(a.quarantined, addr)
			n++
		}
	}
	return n
}

// lastAddr returns the highest address inside p by setting every host bit.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		low := i * 8
		switch {
		case low >= bits: // wholly host bits
			b[i] = 0xff
		case low+8 <= bits: // wholly prefix bits
			continue
		default: // straddles the boundary
			b[i] |= 0xff >> (bits - low)
		}
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

// countAddrs returns the total number of addresses in a prefix with the given
// number of host bits, or -1 when that does not fit in an int64.
func countAddrs(hostBits int) int64 {
	if hostBits >= 63 {
		return -1
	}
	return int64(1) << hostBits
}

// countUsable returns the number of allocatable addresses, or -1 when the total
// does not fit in an int64.
func countUsable(hostBits, reserved int) int64 {
	total := countAddrs(hostBits)
	if total < 0 {
		return -1
	}
	if total <= int64(reserved) {
		return 0
	}
	return total - int64(reserved)
}
