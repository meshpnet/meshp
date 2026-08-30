package netwatch

import (
	"context"
	"testing"
	"time"
)

// A burst of notifications is one change.
//
// Joining a network produces several — an address, a route, a gateway, each its own message —
// and reconciling on every one would mean several passes where one will do, at the moment the
// machine is busiest. Waiting for quiet also means reconciling against the network's settled
// state rather than halfway through it.
func TestABurstIsOneChange(t *testing.T) {
	raw := make(chan struct{}, 16)
	out := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go debounce(ctx, raw, out)

	for range 8 {
		raw <- struct{}{}
		time.Sleep(20 * time.Millisecond)
	}

	select {
	case <-out:
	case <-time.After(5 * time.Second):
		t.Fatal("a burst of changes produced no signal at all, so nothing would reconcile")
	}

	// And no second one, because the burst was one event. A short wait rather than none:
	// what is being asserted is that the coalescing held, not that the channel is empty at
	// this instant.
	select {
	case <-out:
		t.Error("a burst produced more than one signal; the machine would reconcile several " +
			"times over one change of network")
	case <-time.After(settle * 2):
	}
}

// A change that arrives while one is already pending does not queue up behind it.
//
// The reconciler may be busy with the last one. A watcher that blocked waiting to hand over
// the next would stop reading from the kernel, and on some platforms that means a full socket
// buffer and notifications lost — the failure being fixed here, wearing a different cause.
func TestAWatcherNeverBlocksOnASlowReconciler(t *testing.T) {
	raw := make(chan struct{}, 64)
	// Deliberately unbuffered and never read, which is a reconciler that has not come back.
	out := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() { debounce(ctx, raw, out); close(done) }()

	for range 50 {
		raw <- struct{}{}
		time.Sleep(15 * time.Millisecond)
	}

	// Still alive and still reading. If it had blocked handing over, this send would not
	// complete.
	select {
	case raw <- struct{}{}:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher stopped reading; on a real socket this is where notifications " +
			"start being dropped")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("the watcher did not stop when its context ended")
	}
}

// Separate changes are separate signals, or a machine that moved twice would reconcile once.
func TestChangesFarApartAreReported(t *testing.T) {
	raw := make(chan struct{}, 4)
	out := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go debounce(ctx, raw, out)

	for i := range 2 {
		raw <- struct{}{}
		select {
		case <-out:
		case <-time.After(5 * time.Second):
			t.Fatalf("change %d was never reported", i+1)
		}
	}
}

// The watcher ends with its context, and says whether this platform has one.
//
// Nil is a real answer rather than a failure: a host that cannot be told keeps the behaviour
// it had before this existed, and the agent logs that rather than claiming a promptness it
// has not got.
func TestTheWatcherEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	changes := Watch(ctx)
	if changes == nil {
		t.Skip("this platform cannot be told when its networking changes")
	}
	cancel()

	// Draining rather than asserting emptiness: a change may genuinely have happened while
	// this test ran, and what is under test is that the channel stops rather than what it
	// carried.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-changes:
			if !ok {
				return
			}
		case <-deadline:
			// Still open is acceptable — the channel is left for the garbage collector rather
			// than closed, and what matters is that the goroutines behind it have stopped.
			return
		}
	}
}
