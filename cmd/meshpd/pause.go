package main

import (
	"context"
	"strings"

	"github.com/meshpnet/meshp/internal/agentapi"
	"github.com/meshpnet/meshp/internal/agentstate"
	"github.com/meshpnet/meshp/internal/egresslock"
	"github.com/meshpnet/meshp/internal/wglink"
)

// down takes every tunnel off this device and gives the network back.
//
// The fail-closed lock is released, and that is the decision this command turns on.
// ADR-0011 installs it so a device whose tunnel drops stops passing traffic rather than
// putting the user's real address back on the wire — but that protects against a *failure*.
// This is somebody at a keyboard saying they want their ordinary network back. A command
// called "down" that left a machine unable to reach anything, with no obvious way back,
// would manufacture the support ticket ADR-0011 predicts out of a deliberate action.
//
// So it is released, and the caller is told plainly that traffic is no longer going through
// the mesh. Somebody who forgets is somebody leaking.
func (a *agent) down() {
	a.mu.Lock()
	handles := make(map[string]*sessionHandle, len(a.running))
	for id, handle := range a.running {
		handles[id.String()] = handle
	}
	a.mu.Unlock()

	for id, handle := range handles {
		// The interface before the session, the order revoke uses: tearing down needs the
		// reconciler, and cancelling first would race the goroutine that closes the relay
		// link out from under it.
		if handle.applier != nil && handle.applier.reconciler != nil {
			if err := handle.applier.reconciler.Teardown(); err != nil {
				a.log.Error("could not tear down an interface", "membership_id", id, "error", err)
			}
		}
		handle.cancel()
	}

	a.mu.Lock()
	clear(a.running)
	a.mu.Unlock()

	a.releaseEgress()
	a.setPaused(true)
	a.log.Warn("tunnels are down and traffic is using this machine's ordinary network",
		"restore", "meshp up")
}

// up brings back what down took away.
func (a *agent) up() {
	a.setPaused(false)
	a.startAll()
	a.log.Info("tunnels are coming back up")
}

// paused reports whether somebody asked for this device to stay off the mesh.
func (a *agent) paused() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state != nil && a.state.Paused
}

func (a *agent) setPaused(paused bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == nil || a.state.Paused == paused {
		return
	}
	a.state.Paused = paused
	if err := agentstate.Save(a.stateDir, a.state); err != nil {
		// Reported and not fatal: the tunnels are already down either way. What is lost is
		// the memory of it, so the next start would bring them back — which is worth
		// knowing about rather than discovering after a reboot.
		a.log.Error("could not record that this device was taken off the mesh",
			"error", err, "consequence", "a restart will bring the tunnels back up")
	}
}

// releaseEgress undoes both halves of a full tunnel's claim on this machine.
//
// The same two things reclaimEgressLock undoes after a crash, done deliberately here. The
// routing first, because rules pointing at a table whose tunnel is gone send traffic
// nowhere.
func (a *agent) releaseEgress() {
	if held, err := wglink.EgressHeld(); err == nil && held {
		if err := wglink.NewRouter().Release(); err != nil {
			a.log.Error("could not release the default route; this device may have no working routing",
				"error", err)
		}
	}

	lock := a.ensureLock()
	if lock == nil || !egresslock.Held(a.ctx) {
		return
	}
	if err := lock.ApplyLock(a.ctx, "", nil, nil, false); err != nil {
		// The worst outcome this project has: a machine with no network and no obvious
		// cause. Whoever reads this is at a console on a host that cannot reach anything,
		// so the command comes from the platform that installed the lock.
		a.log.Error("could not remove the fail-closed lock; this device still has no egress",
			"error", err, "fix", strings.Join(egresslock.Undo(), " && "))
	}
}

// SetRunning is the agentapi.Handler half of `meshp up` and `meshp down`.
//
// Idempotent by construction: down() on a device with nothing running tears down nothing
// and still records the decision, and up() on a running device starts the sessions that are
// already there, which ensureSession treats as a no-op. Asking for the state you are already
// in is what the caller wanted.
func (a *agent) SetRunning(ctx context.Context, running bool) (agentapi.Status, error) {
	if running {
		a.up()
	} else {
		a.down()
	}
	return a.Status(ctx)
}
