package clock

import (
	"sync"
	"testing"
	"time"
)

func TestFakeDoesNotMoveOnItsOwn(t *testing.T) {
	f := NewFake()
	first := f.Now()
	for range 1000 {
		if got := f.Now(); !got.Equal(first) {
			t.Fatalf("Now() moved without Advance: %v then %v", first, got)
		}
	}
}

func TestFakeAdvance(t *testing.T) {
	f := NewFake()
	start := f.Now()
	f.Advance(90 * time.Second)
	if got, want := f.Now(), start.Add(90*time.Second); !got.Equal(want) {
		t.Errorf("after Advance(90s): got %v, want %v", got, want)
	}
}

func TestFakeAdvanceNegativePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Advance(-1s) did not panic")
		}
	}()
	NewFake().Advance(-time.Second)
}

// The fake is shared between a test's goroutines and the code under test, so it
// has to be race-free itself. Run with -race for this to mean anything.
func TestFakeIsConcurrencySafe(t *testing.T) {
	f := NewFake()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); f.Advance(time.Millisecond) }()
		go func() { defer wg.Done(); _ = f.Now() }()
	}
	wg.Wait()
	if want := 8 * time.Millisecond; !f.Now().Equal(NewFake().Now().Add(want)) {
		t.Errorf("lost an Advance: got %v", f.Now())
	}
}

func TestNewFakeAtAndSet(t *testing.T) {
	// Both exist so a test can construct a starting state — a monitor restored
	// from a snapshot taken at a particular instant, for example — rather than
	// only ever counting forward from the default.
	at := time.Date(2031, time.June, 5, 12, 0, 0, 0, time.UTC)
	f := NewFakeAt(at)
	if got := f.Now(); !got.Equal(at) {
		t.Errorf("NewFakeAt(%v).Now() = %v", at, got)
	}

	earlier := at.Add(-72 * time.Hour)
	f.Set(earlier)
	if got := f.Now(); !got.Equal(earlier) {
		t.Errorf("after Set(%v): Now() = %v", earlier, got)
	}

	// Set is for building a starting point; Advance is how time passes. Setting
	// backwards is allowed, advancing backwards is not.
	f.Advance(time.Hour)
	if got, want := f.Now(), earlier.Add(time.Hour); !got.Equal(want) {
		t.Errorf("Advance after Set: got %v, want %v", got, want)
	}
}

func TestNilCoalescingIsCallersJob(t *testing.T) {
	// Constructors take a Clock and substitute System when given nil, so a caller
	// that forgets one gets real time rather than a panic. Assert the interface
	// is satisfied by both implementations, which is what makes that safe.
	var _ Clock = System{}
	var _ Clock = NewFake()
	var _ Clock = NewFakeAt(time.Now())
}

func TestSystemClockMovesForward(t *testing.T) {
	var c Clock = System{}
	first := c.Now()
	second := c.Now()
	if second.Before(first) {
		t.Errorf("system clock went backwards: %v then %v", first, second)
	}
}
