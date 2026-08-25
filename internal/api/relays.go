package api

import (
	"errors"
	"net/http"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// handleListRelays answers what relays this deployment offers and whether each is taking
// new sessions.
//
// Draining and disabled relays are included, because "did that drain actually take" is the
// question this list is opened to answer.
func (s *Server) handleListRelays(w http.ResponseWriter, r *http.Request) {
	relays, err := s.store.ListRelays(r.Context())
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(relays))
	for _, relay := range relays {
		entry := map[string]any{
			"relay":      relay.Slug,
			"endpoints":  relay.Endpoints,
			"state":      relay.State,
			"created_at": relay.CreatedAt.UTC(),
			// Always present and always null for now: relays do not check in, so nothing
			// here knows whether one is up. Sent as an explicit unknown rather than
			// omitted, so a consumer renders "unknown" instead of inventing a health this
			// control plane has no basis for (#128).
			"last_seen_at": nil,
		}
		if relay.LastSeenAt != nil {
			entry["last_seen_at"] = relay.LastSeenAt.UTC()
		}
		out = append(out, entry)
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"relays": out})
}

// handleSetRelayState takes a relay out of service, or puts it back.
//
// Its own sub-resource rather than a field on a general relay update, for the reason the
// egress setting gives: it is the one thing here that changes what devices do, a PUT naming
// it in the path cannot be made by accident, and it reads unambiguously in an access log.
func (s *Server) handleSetRelayState(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("relay")
	if slug == "" {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "name a relay")
		return
	}

	var body struct {
		State string `json:"state"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	relay, err := s.store.SetRelayState(r.Context(), store.SetRelayStateRequest{
		Slug:     slug,
		State:    body.State,
		Actor:    s.actor(r),
		SourceIP: requestAddr(r),
	})
	switch {
	case errors.Is(err, store.ErrNoSuchRelay):
		httpx.Error(w, s.log, http.StatusNotFound, "no_such_relay",
			"no relay by that name; MESHP_RELAYS is what names them")
		return
	case errors.Is(err, store.ErrBadRelayState):
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"state must be active, draining or disabled")
		return
	case err != nil:
		s.respondError(w, r, err)
		return
	}

	// Every network, because a relay belongs to the deployment rather than to one of them.
	// Without this an agent already at head is never asked for state again and keeps using
	// a relay it should be letting go of — the drain would be recorded and never delivered.
	//
	// A fan-out, and an acceptable one: this is a rare, deliberate act by an operator, and
	// the alternative is a relay list that only takes effect when something else happens to
	// change in each network.
	s.tellEveryNetwork(r)

	s.log.Info("relay state changed", "relay", relay.Slug, "state", relay.State)
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"relay": relay.Slug,
		"state": relay.State,
		// Said plainly, because "draining" does not mean what an operator might assume and
		// the difference matters at the moment they are about to turn a machine off.
		"note": relayStateNote(relay.State),
	})
}

// relayStateNote says what a state actually does.
func relayStateNote(state string) string {
	switch state {
	case store.RelayDraining:
		return "new sessions will not be given this relay; sessions already using it keep " +
			"working, so it empties rather than dropping. Nothing here reports when it is " +
			"empty — relays do not check in yet."
	case store.RelayDisabled:
		return "agents are no longer told about this relay. Anything still using it loses " +
			"that path when it next reconnects."
	default:
		return "agents are told about this relay again."
	}
}

// tellEveryNetwork nudges every network on this deployment.
//
// For deployment-wide changes only. Relays are the one thing an agent is told about that is
// not a property of its network, so this is the one place a change has to reach all of them.
func (s *Server) tellEveryNetwork(r *http.Request) {
	networks, err := s.store.Queries().ListAllNetworks(r.Context())
	if err != nil {
		s.log.Error("could not tell every network about a relay change", "error", err,
			"consequence", "agents keep the relay list they have until something else changes")
		return
	}
	for _, network := range networks {
		s.tellNetwork(network.ID)
	}
}
