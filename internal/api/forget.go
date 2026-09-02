package api

import (
	"errors"
	"net/http"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// handleForgetDevice erases a device from every network at once.
//
// The destructive counterpart to handleRevokeMembership, and a different route rather than
// a flag on that one, because it answers a different question. Revocation is per network
// and leaves the row visible so an administrator can confirm a device is out. This leaves
// nothing, and until it existed "remove my laptop from this system" had no answer at all —
// the listing keeps revoked memberships on purpose, and no query anywhere deleted a device.
//
// Organisation-scoped: a device can hold memberships in several networks (ADR-0004), so no
// one network's permissions should be enough to destroy it.
//
// The database commits first, then the other agents are nudged, for the reason revocation
// gives — the peers are what enforce this, so the gap between the two is the window in
// which an erased device is still reachable.
//
// The device itself is not told. Revocation tells it as a courtesy, addressed to the
// membership being revoked; here there is no membership left to address and nothing on the
// control plane still refers to it. A still-running agent finds out the way a revoked one
// does when it is switched off at the time: its peers stop answering.
func (s *Server) handleForgetDevice(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	deviceID, ok := s.pathUUID(w, r, "deviceID")
	if !ok {
		return
	}

	forgotten, err := s.store.ForgetDevice(r.Context(), store.ForgetRequest{
		OrganizationID: orgID,
		DeviceID:       deviceID,
		Actor:          s.actor(r),
		SourceIP:       sourceAddr(r),
	})
	if errors.Is(err, store.ErrNoSuchDevice) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found",
			"no such device in this organisation")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	s.log.Info("device forgotten",
		"organization_id", orgID, "device_id", forgotten.DeviceID,
		"networks", len(forgotten.Networks), "keys", len(forgotten.Keys))

	// Every network it was in, not only the ones whose keys changed: it may have been an
	// advertiser in a network where its own membership had already been revoked, and the
	// devices routing through it still have to be told.
	for _, networkID := range forgotten.Networks {
		s.tellNetwork(networkID)
	}

	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"device_id":    forgotten.DeviceID,
		"name":         forgotten.Name,
		"networks":     forgotten.Networks,
		"keys_removed": len(forgotten.Keys),
	})
}
