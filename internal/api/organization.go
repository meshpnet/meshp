package api

import (
	"net/http"

	"github.com/meshpnet/meshp/internal/httpx"
)

// handleCreateOrganization makes the tenant a network belongs to.
//
// The first thing a deployment needs and the last endpoint to exist. Until now the
// quickstart told people to run `psql`, which meant standing meshp up required database
// access — for a row with two fields in it.
//
// Behind the administrative token, and not readable by a browser session: an organisation
// is not scoped to a network, and ADR-0022 §5 keeps that credential to what one network can
// see.
func (s *Server) handleCreateOrganization(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	org, err := s.store.CreateOrganization(r.Context(), body.Slug, body.Name)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusCreated, map[string]any{
		// Named organization_id rather than id, matching what network creation returns and
		// what the quickstart puts in a shell variable. A caller stringing these together
		// should not have to notice that one endpoint calls it something else.
		"organization_id": org.ID,
		"slug":            org.Slug,
		"name":            org.Name,
		"created_at":      org.CreatedAt.UTC(),
	})
}

// handleListOrganizations answers which tenants exist.
func (s *Server) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrganizations(r.Context())
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(orgs))
	for _, org := range orgs {
		out = append(out, map[string]any{
			"organization_id": org.ID,
			"slug":            org.Slug,
			"name":            org.Name,
			"created_at":      org.CreatedAt.UTC(),
			"network_count":   org.Networks,
		})
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"organizations": out})
}
