package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/meshpnet/meshp/internal/acl"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// maxPolicyBytes bounds a policy document.
//
// Generous for anything a person writes and far below what would trouble the compiler; the
// point is that an unbounded body is a way to make a control plane allocate whatever it is
// sent.
const maxPolicyBytes = 1 << 20

// handleGetPolicy returns the policy in force.
//
// A network with no policy answers 404 rather than an empty document, because those mean
// opposite things: no policy permits everything, and an empty policy permits nothing. An
// administrator reading `{"rules":[]}` for a network that has never had a policy would
// believe their network was closed.
func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	policy, err := s.store.ActivePolicy(r.Context(), networkID)
	if errors.Is(err, store.ErrNoPolicy) {
		httpx.Error(w, s.log, http.StatusNotFound, "no_policy",
			"this network has no policy; every device may reach every other")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"version":    policy.Version,
		"created_at": policy.CreatedAt,
		"document":   policy.Document,
	})
}

// handlePublishPolicy stores a document and makes it the one in force.
func (s *Server) handlePublishPolicy(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	payload, err := io.ReadAll(io.LimitReader(r.Body, maxPolicyBytes+1))
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "could not read the body")
		return
	}
	if len(payload) > maxPolicyBytes {
		httpx.Error(w, s.log, http.StatusRequestEntityTooLarge, "too_large",
			"that policy is larger than this control plane will accept")
		return
	}

	doc, err := acl.Parse(payload)
	if err != nil {
		// The reason reaches the author verbatim. This is the one place where a detailed
		// error is the whole value: "rule 3: names ports with protocol icmp" is the
		// difference between fixing a policy and guessing at it, and the caller is an
		// administrator holding this network's token rather than an untrusted device.
		httpx.Error(w, s.log, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}

	req := store.PublishPolicyRequest{
		NetworkID: networkID,
		Document:  doc,
		Actor:     s.actor(r),
		SourceIP:  sourceAddr(r),
	}
	if network, err := s.store.Queries().GetNetwork(r.Context(), networkID); err == nil {
		req.OrganizationID = &network.OrganizationID
	}

	policy, err := s.store.PublishPolicy(r.Context(), req)
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	s.log.Info("policy published",
		"network_id", networkID, "policy_version", policy.Version, "rules", len(doc.Rules))

	// Every device's filter changed, so every connected agent needs fresh state. Without
	// this a policy takes up to a heartbeat interval to reach anyone, which for a control
	// that exists to deny traffic is the wrong direction to be slow in.
	s.tellNetwork(networkID)

	httpx.WriteJSON(w, s.log, http.StatusCreated, map[string]any{
		"status":     "published",
		"version":    policy.Version,
		"created_at": policy.CreatedAt,
	})
}

// handleListPolicyVersions returns every version ever published.
//
// With their documents, because a policy is meant to be diffed and rolled back (ADR-0007)
// and a list of numbers supports neither.
func (s *Server) handleListPolicyVersions(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	rows, err := s.store.Queries().ListPolicyVersions(r.Context(), networkID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		entry := map[string]any{
			"version":    row.Version,
			"active":     row.IsActive,
			"created_at": row.CreatedAt,
		}
		// Passed through as stored rather than re-encoded. A version this build can no
		// longer parse is exactly the one an operator most needs to read, so a policy that
		// fails to validate must still be visible here.
		entry["document"] = json.RawMessage(row.Document)
		out = append(out, entry)
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"policies": out})
}
