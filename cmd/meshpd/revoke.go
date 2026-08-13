package main

import (
	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/agentstate"
	"github.com/meshpnet/meshp/internal/logx"
)

// membershipRevoker acts on the control plane ending one membership.
//
// One per session, because a device may belong to several networks (ADR-0004) and one
// revoking it says nothing about the others. Everything here is scoped to the membership
// named at construction.
type membershipRevoker struct {
	agent        *agent
	membershipID uuid.UUID
}

// Revoked implements sessionclient.Revoker.
//
// The interface comes down first (Invariant 20: what the agent installed, the agent
// removes), then the local record goes. Both matter and for different reasons: an interface
// left up would hold addresses and routes for a network this device is no longer part of,
// and a membership left on disk would have meshpd trying to open a session that the control
// plane refuses, forever, at every start.
func (r *membershipRevoker) Revoked(reason string, wipeLocalState bool) {
	r.agent.log.Warn("revoked from a network; tearing down",
		"membership_id", r.membershipID,
		"reason", logx.Safe(reason),
		"wipe_local_state", wipeLocalState)
	r.agent.revoke(r.membershipID, wipeLocalState)
}

// revoke removes every trace of one membership from this device.
func (a *agent) revoke(membershipID uuid.UUID, wipeLocalState bool) {
	a.mu.Lock()
	handle, running := a.running[membershipID]
	a.mu.Unlock()

	// The interface before the session. Tearing down needs the reconciler, and cancelling
	// the session first would race the goroutine that closes the relay link out from under
	// it.
	if running && handle.applier.reconciler != nil {
		if err := handle.applier.reconciler.Teardown(); err != nil {
			// Reported, not fatal. The membership is over regardless, and an interface that
			// could not be removed is a mess to clean up rather than a reason to keep a
			// device in a network it has been thrown out of.
			a.log.Error("could not tear down the interface of a revoked membership",
				"membership_id", membershipID, "error", err)
		}
	}
	if running {
		// Stops the session supervisor and the relay link together; the deferred close in
		// ensureSession releases the relay's sockets.
		handle.cancel()
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == nil {
		return
	}
	if !a.state.RemoveMembership(membershipID) {
		return
	}
	// Only once nothing is left. The identity names this device to every network it has
	// joined (ADR-0006), so discarding it because one network revoked this device would
	// quietly lock it out of the others.
	if wipeLocalState && len(a.state.Memberships) == 0 {
		a.state.ForgetIdentity()
	}
	if err := agentstate.Save(a.stateDir, a.state); err != nil {
		a.log.Error("could not record a revocation locally",
			"membership_id", membershipID, "error", err,
			"hint", "meshpd will try to reopen this session until the file is written")
	}
}
