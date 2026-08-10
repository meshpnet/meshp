// Package clock provides an injectable time source.
//
// Every part of meshp that makes a decision based on elapsed time — quarantine
// expiry, health thresholds, failback delays, anti-flap cooldowns — takes a
// Clock rather than calling time.Now. Those are exactly the behaviours that
// matter most and that are impossible to test honestly against a real clock: a
// test for "does not fail back for five minutes" either sleeps for five minutes
// or proves nothing.
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time.
type Clock interface {
	Now() time.Time
}

// System is the real clock. Use it everywhere outside tests.
type System struct{}

// Now returns the current wall-clock time.
func (System) Now() time.Time { return time.Now() }

// Fake is a manually advanced clock for tests. It is safe for concurrent use so
// that tests can exercise goroutines without the race detector complaining
// about the clock itself.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake set to a fixed, arbitrary instant. The instant is
// deliberately not time.Now: a test that passes only because the clock happens
// to be near the present is a test with a hidden dependency.
func NewFake() *Fake {
	return &Fake{now: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}
}

// NewFakeAt returns a Fake set to t.
func NewFakeAt(t time.Time) *Fake { return &Fake{now: t} }

// Now returns the fake's current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake forward by d. Advancing by a negative duration panics:
// time going backwards is never something a test means to express, and silently
// allowing it hides the bug in the test rather than in the code.
func (f *Fake) Advance(d time.Duration) {
	if d < 0 {
		panic("clock: Fake.Advance called with a negative duration")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set moves the fake to t, which may be in the past. Use this only to construct
// a starting state, never to simulate time passing.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}
