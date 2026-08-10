package ipam

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func newTestAllocator(t *testing.T, prefix string, reserved ...string) (*Allocator, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake()
	cfg := Config{Prefix: mustPrefix(t, prefix)}
	for _, r := range reserved {
		cfg.Reserved = append(cfg.Reserved, mustAddr(t, r))
	}
	a, err := New(cfg, clk)
	if err != nil {
		t.Fatalf("New(%q): %v", prefix, err)
	}
	return a, clk
}

func TestUsableCounts(t *testing.T) {
	// The structural reservations differ by family, and RFC 3021 makes both
	// addresses of a /31 usable. Getting these wrong silently shrinks or
	// oversubscribes every pool.
	tests := []struct {
		prefix     string
		wantUsable int64
		wantFirst  string // first address Allocate should return
	}{
		{"10.0.0.0/24", 254, "10.0.0.1"},
		{"100.90.0.0/16", 65534, "100.90.0.1"},
		{"10.0.0.0/30", 2, "10.0.0.1"},
		{"10.0.0.0/31", 2, "10.0.0.0"}, // RFC 3021: no network or broadcast
		{"10.0.0.0/32", 1, "10.0.0.0"},
		{"fd00::/126", 3, "fd00::1"}, // IPv6 loses only the anycast base
		{"fd00::/127", 1, "fd00::1"},
		{"fd00::/128", 1, "fd00::"},
		{"fd00::/48", -1, "fd00::1"}, // too large to count
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			a, _ := newTestAllocator(t, tt.prefix)
			if got := a.Stats().Usable; got != tt.wantUsable {
				t.Errorf("Usable = %d, want %d", got, tt.wantUsable)
			}
			got, err := a.Allocate("first")
			if err != nil {
				t.Fatalf("Allocate: %v", err)
			}
			if want := mustAddr(t, tt.wantFirst); got != want {
				t.Errorf("first Allocate = %v, want %v", got, want)
			}
		})
	}
}

func TestNewRejectsUnusablePrefix(t *testing.T) {
	// A /31 of IPv6 has two addresses, one of which is the anycast base, so it
	// is usable. A prefix whose every address is reserved is not.
	clk := clock.NewFake()
	_, err := New(Config{
		Prefix:   mustPrefix(t, "10.0.0.0/32"),
		Reserved: []netip.Addr{mustAddr(t, "10.0.0.0")},
	}, clk)
	if err == nil {
		t.Fatal("New accepted a prefix with no allocatable address")
	}
}

func TestNewRejectsReservedOutsidePrefix(t *testing.T) {
	clk := clock.NewFake()
	_, err := New(Config{
		Prefix:   mustPrefix(t, "10.0.0.0/24"),
		Reserved: []netip.Addr{mustAddr(t, "10.0.1.5")},
	}, clk)
	if !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("New with out-of-range reservation: got %v, want ErrOutOfRange", err)
	}
}

func TestReservedAddressesAreNeverAllocated(t *testing.T) {
	a, _ := newTestAllocator(t, "10.0.0.0/29", "10.0.0.1", "10.0.0.3")
	banned := map[netip.Addr]bool{
		mustAddr(t, "10.0.0.0"): true, // network
		mustAddr(t, "10.0.0.7"): true, // broadcast
		mustAddr(t, "10.0.0.1"): true, // explicit
		mustAddr(t, "10.0.0.3"): true, // explicit
	}

	var got []netip.Addr
	for {
		addr, err := a.Allocate("h")
		if err != nil {
			break
		}
		if banned[addr] {
			t.Fatalf("Allocate returned reserved address %v", addr)
		}
		got = append(got, addr)
	}
	if len(got) != 4 { // .2 .4 .5 .6
		t.Errorf("allocated %d addresses (%v), want 4", len(got), got)
	}
}

func TestAllocateSweepsForwardAndWraps(t *testing.T) {
	a, clk := newTestAllocator(t, "10.0.0.0/29") // usable .1-.6

	first, err := a.Allocate("a")
	if err != nil {
		t.Fatal(err)
	}
	if want := mustAddr(t, "10.0.0.1"); first != want {
		t.Fatalf("first = %v, want %v", first, want)
	}

	// Releasing and immediately reallocating must not hand the same address
	// straight back: the sweep continues forward, which is what maximises the
	// gap before reuse.
	if err := a.Release(first); err != nil {
		t.Fatal(err)
	}
	next, err := a.Allocate("b")
	if err != nil {
		t.Fatal(err)
	}
	if next == first {
		t.Errorf("Allocate reused %v immediately after Release", first)
	}

	// Once everything else is taken and quarantine has lapsed, the sweep wraps
	// and picks it up again.
	for {
		if _, err := a.Allocate("filler"); err != nil {
			break
		}
	}
	clk.Advance(DefaultQuarantine + time.Second)
	again, err := a.Allocate("c")
	if err != nil {
		t.Fatalf("after quarantine lapsed: %v", err)
	}
	if again != first {
		t.Errorf("after wrap got %v, want the reclaimed %v", again, first)
	}
}

// Regression test. The allocation sweep must be bounded by the total size of the
// prefix, not by the usable count: reserved and quarantined addresses are
// visited and skipped, so a bound of `usable` can stop short of a free address
// and wrongly report the pool full. With a /29 whose cursor sits on the
// broadcast address, the two structural reservations consume two iterations and
// the last usable address falls outside a `usable`-sized window.
func TestSweepBoundReachesTheLastFreeAddress(t *testing.T) {
	a, clk := newTestAllocator(t, "10.0.0.0/29") // usable .1-.6, cursor ends at .7

	var all []netip.Addr
	for {
		addr, err := a.Allocate("h")
		if err != nil {
			break
		}
		all = append(all, addr)
	}
	if len(all) != 6 {
		t.Fatalf("filled pool with %d addresses, want 6", len(all))
	}

	target := all[len(all)-1] // 10.0.0.6, the furthest point from the wrapped cursor
	if err := a.Release(target); err != nil {
		t.Fatal(err)
	}
	clk.Advance(DefaultQuarantine + time.Second)

	got, err := a.Allocate("late")
	if err != nil {
		t.Fatalf("Allocate reported %v with %v free", err, target)
	}
	if got != target {
		t.Errorf("got %v, want %v", got, target)
	}
}

func TestReleaseQuarantinesBeforeReuse(t *testing.T) {
	a, clk := newTestAllocator(t, "10.0.0.0/30") // usable .1 .2

	first, _ := a.Allocate("a")
	second, _ := a.Allocate("b")
	if err := a.Release(first); err != nil {
		t.Fatal(err)
	}

	// One address is free on paper but quarantined, so the pool reports a
	// distinct error. Conflating this with exhaustion sends an operator looking
	// for capacity they already have.
	if _, err := a.Allocate("c"); !errors.Is(err, ErrAllQuarantined) {
		t.Fatalf("got %v, want ErrAllQuarantined", err)
	}
	if s := a.Stats(); s.Quarantined != 1 || s.Allocated != 1 {
		t.Errorf("Stats = %+v, want 1 allocated and 1 quarantined", s)
	}

	// Not one tick early.
	clk.Advance(DefaultQuarantine - time.Nanosecond)
	if _, err := a.Allocate("c"); !errors.Is(err, ErrAllQuarantined) {
		t.Fatalf("one tick before expiry: got %v, want ErrAllQuarantined", err)
	}

	clk.Advance(time.Nanosecond)
	got, err := a.Allocate("c")
	if err != nil {
		t.Fatalf("at expiry: %v", err)
	}
	if got != first {
		t.Errorf("got %v, want the reclaimed %v", got, first)
	}
	_ = second
}

func TestExhaustionIsExactAndDistinctFromQuarantine(t *testing.T) {
	a, _ := newTestAllocator(t, "10.0.0.0/28") // 16 total, 14 usable

	for i := range 14 {
		if _, err := a.Allocate("h"); err != nil {
			t.Fatalf("allocation %d of 14 failed: %v", i+1, err)
		}
	}
	_, err := a.Allocate("overflow")
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("got %v, want ErrExhausted", err)
	}
	if s := a.Stats(); s.Free != 0 {
		t.Errorf("Free = %d, want 0", s.Free)
	}
}

func TestQuarantineCanBeDisabled(t *testing.T) {
	clk := clock.NewFake()
	a, err := New(Config{Prefix: mustPrefix(t, "10.0.0.0/30"), Quarantine: -1}, clk)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := a.Allocate("a")
	if err := a.Release(first); err != nil {
		t.Fatal(err)
	}
	if s := a.Stats(); s.Quarantined != 0 {
		t.Errorf("Quarantined = %d with quarantine disabled, want 0", s.Quarantined)
	}
}

func TestAllocateSpecific(t *testing.T) {
	a, clk := newTestAllocator(t, "10.0.0.0/24")
	pinned := mustAddr(t, "10.0.0.50")

	if err := a.AllocateSpecific(pinned, "server"); err != nil {
		t.Fatalf("AllocateSpecific: %v", err)
	}
	if h, ok := a.Holder(pinned); !ok || h != "server" {
		t.Errorf("Holder(%v) = %q, %v; want \"server\", true", pinned, h, ok)
	}

	if err := a.AllocateSpecific(pinned, "other"); !errors.Is(err, ErrAlreadyAllocated) {
		t.Errorf("double AllocateSpecific: got %v, want ErrAlreadyAllocated", err)
	}
	if err := a.AllocateSpecific(mustAddr(t, "10.0.1.1"), "x"); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("out of range: got %v, want ErrOutOfRange", err)
	}
	if err := a.AllocateSpecific(mustAddr(t, "10.0.0.0"), "x"); !errors.Is(err, ErrReserved) {
		t.Errorf("network address: got %v, want ErrReserved", err)
	}

	// A quarantined address cannot be pinned until it comes back, otherwise
	// AllocateSpecific would be a way to bypass Invariant 17.
	if err := a.Release(pinned); err != nil {
		t.Fatal(err)
	}
	if err := a.AllocateSpecific(pinned, "again"); !errors.Is(err, ErrQuarantined) {
		t.Errorf("quarantined: got %v, want ErrQuarantined", err)
	}
	clk.Advance(DefaultQuarantine + time.Second)
	if err := a.AllocateSpecific(pinned, "again"); err != nil {
		t.Errorf("after quarantine: %v", err)
	}
}

func TestReleaseUnallocatedIsAnError(t *testing.T) {
	a, _ := newTestAllocator(t, "10.0.0.0/24")
	if err := a.Release(mustAddr(t, "10.0.0.9")); !errors.Is(err, ErrNotAllocated) {
		t.Fatalf("got %v, want ErrNotAllocated", err)
	}
}

func TestRestore(t *testing.T) {
	a, _ := newTestAllocator(t, "10.0.0.0/24")
	base := clock.NewFake().Now()

	err := a.Restore([]Entry{
		{Addr: mustAddr(t, "10.0.0.5"), Holder: "alice"},
		{Addr: mustAddr(t, "10.0.0.9"), Holder: "bob"},
		{Addr: mustAddr(t, "10.0.0.7"), ReleasedAt: base}, // still cooling down
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if h, ok := a.Holder(mustAddr(t, "10.0.0.5")); !ok || h != "alice" {
		t.Errorf("restored holder = %q, %v", h, ok)
	}
	if s := a.Stats(); s.Allocated != 2 || s.Quarantined != 1 {
		t.Errorf("Stats = %+v, want 2 allocated 1 quarantined", s)
	}

	// The sweep resumes above the highest live address rather than restarting at
	// the bottom of the pool.
	next, err := a.Allocate("carol")
	if err != nil {
		t.Fatal(err)
	}
	if want := mustAddr(t, "10.0.0.10"); next != want {
		t.Errorf("Allocate after Restore = %v, want %v", next, want)
	}
}

func TestRestoreRejectsAddressOutsidePool(t *testing.T) {
	a, _ := newTestAllocator(t, "10.0.0.0/24")
	err := a.Restore([]Entry{{Addr: mustAddr(t, "10.9.9.9"), Holder: "ghost"}})
	if !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("got %v, want ErrOutOfRange", err)
	}
}

func TestSnapshotIsSortedAndComplete(t *testing.T) {
	a, _ := newTestAllocator(t, "10.0.0.0/24")
	for range 20 {
		if _, err := a.Allocate("h"); err != nil {
			t.Fatal(err)
		}
	}
	snap := a.Snapshot()
	if len(snap) != 20 {
		t.Fatalf("Snapshot has %d entries, want 20", len(snap))
	}
	for i := 1; i < len(snap); i++ {
		if snap[i-1].Addr.Compare(snap[i].Addr) >= 0 {
			t.Fatalf("Snapshot not sorted at %d: %v then %v", i, snap[i-1].Addr, snap[i].Addr)
		}
	}
}

// Allocation happens from HTTP handlers, so concurrent callers must never
// receive the same address. Meaningful only under -race, which CI enforces.
func TestConcurrentAllocateNeverDuplicates(t *testing.T) {
	a, _ := newTestAllocator(t, "10.0.0.0/22") // 1022 usable

	const workers, each = 16, 60
	var (
		mu   sync.Mutex
		seen = map[netip.Addr]bool{}
		wg   sync.WaitGroup
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				addr, err := a.Allocate("h")
				if err != nil {
					t.Errorf("Allocate: %v", err)
					return
				}
				mu.Lock()
				if seen[addr] {
					t.Errorf("duplicate allocation of %v", addr)
				}
				seen[addr] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != workers*each {
		t.Errorf("got %d distinct addresses, want %d", len(seen), workers*each)
	}
}

func TestLastAddr(t *testing.T) {
	tests := []struct{ prefix, want string }{
		{"10.0.0.0/24", "10.0.0.255"},
		{"10.0.0.0/20", "10.0.15.255"},
		{"10.0.0.0/32", "10.0.0.0"},
		{"10.0.0.0/31", "10.0.0.1"},
		{"192.168.1.0/23", "192.168.1.255"},
		{"fd00::/126", "fd00::3"},
		{"fd00::/64", "fd00::ffff:ffff:ffff:ffff"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got := lastAddr(mustPrefix(t, tt.prefix).Masked())
			if want := mustAddr(t, tt.want); got != want {
				t.Errorf("lastAddr(%s) = %v, want %v", tt.prefix, got, want)
			}
		})
	}
}
