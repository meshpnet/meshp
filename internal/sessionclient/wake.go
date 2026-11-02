package sessionclient

import (
	"errors"
	"sync"
	"time"
)

// Noticing that this machine slept.
//
// A sleeping laptop freezes this process, and the session it held looks, from in here, exactly
// as it did a moment before the lid shut. Go's timers do not help. They run on the monotonic
// clock, which on macOS is mach_absolute_time and on Linux is CLOCK_MONOTONIC, and neither
// advances while the machine is asleep — so the read deadline that should notice a dead session
// resumes on waking with whatever it had left before the lid closed. That is the ninety seconds
// after a wake in which `meshp status` went on reporting a session the control plane had already
// ended (docs/testing/macos-laptop.md, 2026-08-31).
//
// The wall clock does keep counting. How much further it moved than the monotonic clock over
// the same stretch is how long this process was not running, and a session that spans a freeze
// of any length worth the name is one the control plane may well have ended: it stops counting
// an agent that leaves a liveness probe unanswered for thirty seconds. So such a session is
// ended here too, at once, and a new one opened — rather than reported as connected until a
// deadline that slept through the whole thing gets round to expiring.
//
// Where the monotonic clock counts through sleep, as Windows' does, the two clocks agree and
// this never fires. It does not need to: the deadlines there are measured in time that passed,
// and the ones that expired during the sleep fire as soon as the machine wakes.

// wakeCheckInterval is how often the two clocks are compared, and so the longest `meshp status`
// can go on showing a session from before a sleep. A variable so a test can shorten it.
var wakeCheckInterval = 5 * time.Second

// suspendThreshold is how long a freeze must be before the session is not trusted to have
// survived it.
//
// Far above anything a running process sees from its scheduler or its garbage collector, and
// below the thirty seconds the control plane waits for an answer, so a session that might have
// been ended is never kept. A wall clock stepped forward by this much looks the same, and costs
// one reconnection.
const suspendThreshold = 10 * time.Second

// errSlept ends a session that spanned a sleep.
var errSlept = errors.New("sessionclient: this machine was asleep")

// clocks reads the wall clock and the monotonic clock separately, so a test can make them
// disagree the way a machine that slept makes them disagree.
type clocks struct {
	// wall keeps counting while the machine sleeps.
	wall func() time.Time
	// running is monotonic time since some fixed point; it stops while the machine sleeps.
	running func() time.Duration
}

// processStart anchors the monotonic reading. Any fixed instant would do.
var processStart = time.Now()

func systemClocks() clocks {
	return clocks{
		// Round(0) strips the monotonic reading, which is what makes this the wall clock: a
		// time.Time that kept it would subtract monotonically and agree with running.
		wall:    func() time.Time { return time.Now().Round(0) },
		running: func() time.Duration { return time.Since(processStart) },
	}
}

// suspendWatch measures how long this process spent frozen.
type suspendWatch struct {
	clk clocks

	mu      sync.Mutex
	wall    time.Time
	running time.Duration
}

func newSuspendWatch(clk clocks) *suspendWatch {
	return &suspendWatch{clk: clk, wall: clk.wall(), running: clk.running()}
}

// frozen reports how much further the wall clock moved than the monotonic one since the last
// call: time that passed while this process was not running. Negative when the wall clock was
// stepped back, which is not a sleep.
func (w *suspendWatch) frozen() time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	wall, running := w.clk.wall(), w.clk.running()
	gap := wall.Sub(w.wall) - (running - w.running)
	w.wall, w.running = wall, running
	return gap
}
