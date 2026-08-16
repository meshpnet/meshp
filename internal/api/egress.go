package api

import (
	"errors"
	"net/http"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// handleGetEgressFailClosed reports whether this network's devices refuse egress outside the
// tunnel while they claim a default route.
//
// Readable on its own, because an administrator asking "is this fleet protected?" should not
// have to infer the answer from what the agents happen to be doing.
func (s *Server) handleGetEgressFailClosed(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	enforced, err := s.store.EgressFailClosed(r.Context(), networkID)
	if errors.Is(err, store.ErrNoSuchNetwork) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found", "no such network")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"enforced": enforced})
}

// handleSetEgressFailClosed records an administrator's decision under ADR-0011.
//
// The interesting part is what this refuses. `enforced` is a pointer and a body that omits it
// is rejected, rather than being read as Go's zero value — which for a bool is false, which
// here means "let every device in this network leak if its tunnel drops". A typo in a field
// name, a client that sends `{}`, or a script whose variable was empty would all otherwise
// turn off a safety property and get a 200 back. decode already refuses unknown fields, so
// this closes the other half of the same hole: a field that is simply not there.
func (s *Server) handleSetEgressFailClosed(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	var body struct {
		Enforced *bool `json:"enforced"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if body.Enforced == nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"enforced must be true or false; leaving it out would read as false, "+
				"which lets devices in this network send traffic in the clear if the tunnel drops")
		return
	}

	changed, err := s.store.SetEgressFailClosed(r.Context(), networkID, *body.Enforced)
	if errors.Is(err, store.ErrNoSuchNetwork) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found", "no such network")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	if changed {
		if *body.Enforced {
			s.log.Info("this network's devices will refuse egress outside the tunnel",
				"network_id", networkID)
		} else {
			// Warn rather than Info, and said in full. Whoever turned this off should be able
			// to find out from the log that they did, and whoever is reading the log a year
			// later after an incident should not have to know what "fail_closed=false" meant.
			s.log.Warn("this network's devices will no longer refuse egress outside the tunnel",
				"network_id", networkID,
				"consequence", "traffic leaves in the clear if a device's tunnel drops while it carries a default route")
		}
		// Only when something changed: agents were told nothing otherwise, and nudging them
		// to fetch a state they already hold is work for every device in the network.
		s.tellNetwork(networkID)
	}

	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"enforced": *body.Enforced,
		"changed":  changed,
	})
}
