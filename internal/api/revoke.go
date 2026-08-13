package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// handleRevokeMembership takes a device out of a network.
//
// The order here is the whole design. The database commits first, so the network's desired
// state no longer contains this peer; then the other agents are nudged, so they drop it;
// only then is the device itself told, because telling it is a courtesy rather than the
// mechanism. A device that is switched off, or hostile, or simply gone is out of the
// network regardless — its peers stop accepting its key, and nothing it does changes that
// (the same shape as ACLs enforced at the destination, ADR-0007).
func (s *Server) handleRevokeMembership(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	membershipID, ok := s.pathUUID(w, r, "membershipID")
	if !ok {
		return
	}

	var body struct {
		Reason string `json:"reason"`
		// Wipe asks the device to destroy its local keys as well as its interface. Off by
		// default: it is unrecoverable, and an administrator removing a device from one
		// network rarely means to erase its identity for every other.
		Wipe bool `json:"wipe_local_state"`
	}
	if payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<16)); err == nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, &body); err != nil {
			httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "body must be JSON")
			return
		}
	}

	req := store.RevokeRequest{
		NetworkID:    networkID,
		MembershipID: membershipID,
		Reason:       body.Reason,
		ActorLabel:   "admin token",
		SourceIP:     sourceAddr(r),
	}
	// Best effort: the organisation only labels the audit row, and failing to read it is
	// not a reason to leave a device in a network someone has decided to remove it from.
	if network, err := s.store.Queries().GetNetwork(r.Context(), networkID); err == nil {
		req.OrganizationID = &network.OrganizationID
	}

	revoked, err := s.store.RevokeMembership(r.Context(), req)
	if errors.Is(err, store.ErrNotAMember) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found",
			"no such device in that network, or it was already revoked")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	s.log.Info("device revoked",
		"network_id", networkID, "membership_id", revoked.MembershipID,
		"device_id", revoked.DeviceID, "reason", logx.Safe(body.Reason))

	// The peers first. They are what enforces this, so any delay here is the window in
	// which a revoked device is still reachable.
	s.tellNetwork(networkID)
	s.tellRevoked(revoked, body.Reason, body.Wipe)

	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"status":               "revoked",
		"membership_id":        revoked.MembershipID,
		"device_id":            revoked.DeviceID,
		"wireguard_public_key": revoked.WireGuardPublicKey,
	})
}

// tellRevoked asks the device to tear itself down, if it happens to be listening.
//
// Courtesy, not enforcement: it saves the device from holding an interface that can no
// longer carry anything, and it lets a person at the keyboard see why. A device that is
// offline is equally revoked and will find out when it tries to reconnect.
func (s *Server) tellRevoked(revoked store.Revoked, reason string, wipe bool) {
	if s.session == nil {
		return
	}
	sess, ok := s.session.Hub().Get(revoked.MembershipID)
	if !ok {
		return
	}

	sess.Farewell(&meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_Command{
		Command: &meshpv1.Command{Payload: &meshpv1.Command_Revoke{Revoke: &meshpv1.Revoke{
			Reason:         reason,
			WipeLocalState: wipe,
		}}},
	}})
}

// handleListMemberships answers "who is in this network, and are they still allowed in".
//
// Revoked memberships are listed rather than hidden. An administrator checking that a
// device really is out needs to see that it is out, and a device that silently vanished
// from a list is indistinguishable from one that was never there.
func (s *Server) handleListMemberships(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	rows, err := s.store.Queries().ListMembershipsForNetwork(r.Context(), networkID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	if rows == nil {
		rows = []dbgen.ListMembershipsForNetworkRow{}
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"devices": rows})
}
