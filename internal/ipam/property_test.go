package ipam

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
)

// model is a deliberately naive shadow implementation. It is not efficient and
// it is not the thing that ships; it exists so the real allocator's behaviour
// can be checked against rules stated directly, rather than against itself.
type model struct {
	prefix      netip.Prefix
	reserved    map[netip.Addr]bool
	allocated   map[netip.Addr]string
	quarantined map[netip.Addr]time.Time
}

func newModel(p netip.Prefix) *model {
	m := &model{
		prefix:      p.Masked(),
		reserved:    map[netip.Addr]bool{},
		allocated:   map[netip.Addr]string{},
		quarantined: map[netip.Addr]time.Time{},
	}
	first := m.prefix.Addr()
	last := lastAddr(m.prefix)
	hostBits := first.BitLen() - m.prefix.Bits()
	if first.Is4() {
		if hostBits >= 2 {
			m.reserved[first], m.reserved[last] = true, true
		}
	} else if hostBits >= 1 {
		m.reserved[first] = true
	}
	return m
}

// check asserts every rule the allocator promises, against the model.
func (m *model) check(t *testing.T, a *Allocator, step int, now time.Time) {
	t.Helper()

	snap := a.Snapshot()
	if len(snap) != len(m.allocated) {
		t.Fatalf("step %d: allocator holds %d addresses, model holds %d", step, len(snap), len(m.allocated))
	}

	seen := map[netip.Addr]bool{}
	for _, e := range snap {
		// Invariant: an address is handed out at most once.
		if seen[e.Addr] {
			t.Fatalf("step %d: %v allocated twice", step, e.Addr)
		}
		seen[e.Addr] = true

		// Invariant: only addresses inside the pool, never a reserved one.
		if !m.prefix.Contains(e.Addr) {
			t.Fatalf("step %d: %v is outside %v", step, e.Addr, m.prefix)
		}
		if m.reserved[e.Addr] {
			t.Fatalf("step %d: %v is reserved", step, e.Addr)
		}

		// Invariant 17: a live allocation is never simultaneously quarantined.
		if until, ok := m.quarantined[e.Addr]; ok && now.Before(until) {
			t.Fatalf("step %d: %v allocated while quarantined until %v", step, e.Addr, until)
		}

		if want := m.allocated[e.Addr]; want != e.Holder {
			t.Fatalf("step %d: %v held by %q, model says %q", step, e.Addr, e.Holder, want)
		}
	}

	wantQuarantined := 0
	for _, until := range m.quarantined {
		if now.Before(until) {
			wantQuarantined++
		}
	}
	if got := a.Stats().Quarantined; got != wantQuarantined {
		t.Fatalf("step %d: Stats().Quarantined = %d, model says %d", step, got, wantQuarantined)
	}
}

// runOps drives allocator and model through the same operation sequence and
// returns the addresses allocated, in order, so two runs can be compared.
func runOps(t *testing.T, prefix string, ops []byte) []netip.Addr {
	t.Helper()

	p := mustPrefix(t, prefix)
	clk := clock.NewFake()
	a, err := New(Config{Prefix: p}, clk)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := newModel(p)

	var order []netip.Addr
	var live []netip.Addr // allocated addresses, for choosing one to release

	for step, op := range ops {
		now := clk.Now()

		switch op % 4 {
		case 0, 1: // allocate, weighted so pools actually fill up
			holder := fmt.Sprintf("h%d", step)
			addr, err := a.Allocate(holder)
			switch {
			case err == nil:
				m.allocated[addr] = holder
				delete(m.quarantined, addr)
				live = append(live, addr)
				order = append(order, addr)
			case errors.Is(err, ErrExhausted), errors.Is(err, ErrAllQuarantined):
				// A refusal must be truthful: if the model has a free,
				// unquarantined, unreserved address, the allocator was wrong to
				// refuse. This is the check that catches a sweep that stops
				// short.
				if free := m.firstFree(now); free.IsValid() {
					t.Fatalf("step %d: allocator returned %v but %v is free", step, err, free)
				}
			default:
				t.Fatalf("step %d: unexpected error %v", step, err)
			}

		case 2: // release something
			if len(live) == 0 {
				break
			}
			idx := int(op) % len(live)
			addr := live[idx]
			live = append(live[:idx], live[idx+1:]...)
			if err := a.Release(addr); err != nil {
				t.Fatalf("step %d: Release(%v): %v", step, addr, err)
			}
			delete(m.allocated, addr)
			m.quarantined[addr] = now.Add(DefaultQuarantine)

		case 3: // let time pass, sometimes past a quarantine boundary
			clk.Advance(time.Duration(op) * time.Minute)
		}

		m.check(t, a, step, clk.Now())
	}
	return order
}

// firstFree returns an address the model believes is allocatable, if any.
func (m *model) firstFree(now time.Time) netip.Addr {
	addr := m.prefix.Addr()
	last := lastAddr(m.prefix)
	for {
		_, isAllocated := m.allocated[addr]
		until, hasQuarantine := m.quarantined[addr]
		inQuarantine := hasQuarantine && now.Before(until)
		if !m.reserved[addr] && !isAllocated && !inQuarantine {
			return addr
		}
		if addr.Compare(last) >= 0 {
			return netip.Addr{}
		}
		addr = addr.Next()
	}
}

func TestPropertyAgainstModel(t *testing.T) {
	// A fixed seed keeps failures reproducible. Widening coverage is the fuzz
	// target's job, not this test's.
	rng := rand.New(rand.NewPCG(0x6d65_7368, 0x70_00))

	for _, prefix := range []string{"10.0.0.0/29", "10.0.0.0/26", "10.0.0.0/24", "fd00::/125"} {
		t.Run(prefix, func(t *testing.T) {
			for round := range 40 {
				ops := make([]byte, 200)
				for i := range ops {
					ops[i] = byte(rng.UintN(256))
				}
				if t.Failed() {
					t.Fatalf("stopping at round %d", round)
				}
				runOps(t, prefix, ops)
			}
		})
	}
}

func TestPropertyIsDeterministic(t *testing.T) {
	// Map iteration order in Go is randomised per run. Any allocator that leaks
	// that order into its output would both fail this test and, in production,
	// hand out unpredictable addresses across control-plane replicas.
	rng := rand.New(rand.NewPCG(42, 42))
	ops := make([]byte, 500)
	for i := range ops {
		ops[i] = byte(rng.UintN(256))
	}

	first := runOps(t, "10.0.0.0/26", ops)
	for attempt := range 5 {
		again := runOps(t, "10.0.0.0/26", ops)
		if len(first) != len(again) {
			t.Fatalf("attempt %d allocated %d addresses, first run allocated %d", attempt, len(again), len(first))
		}
		for i := range first {
			if first[i] != again[i] {
				t.Fatalf("attempt %d diverged at allocation %d: %v vs %v", attempt, i, again[i], first[i])
			}
		}
	}
}

func FuzzAllocatorOperations(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, 3, 0})
	f.Add([]byte{2, 2, 2, 2})                      // releases with nothing allocated
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})    // straight to exhaustion
	f.Add([]byte{0, 2, 3, 0, 2, 3, 0, 2, 3})       // allocate, release, wait
	f.Add([]byte{0, 0, 2, 2, 3, 3, 0, 0, 2, 2, 3}) // churn

	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 4096 {
			ops = ops[:4096]
		}
		// A small pool reaches the interesting states — exhaustion, full
		// quarantine, wrap-around — in far fewer operations.
		runOps(t, "10.0.0.0/29", ops)
	})
}
