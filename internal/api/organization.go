package api

import (
	"net/http"
	"slices"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// handleCreateOrganization makes the tenant a network belongs to.
//
// The first thing a deployment needs and the last endpoint to exist. Until now the
// quickstart told people to run `psql`, which meant standing meshp up required database
// access — for a row with two fields in it.
//
// Behind the administrative token, and not behind a permission. A person belongs to exactly
// one organisation, so there is no organisation somebody could hold a permission over that
// would authorise creating another: making a tenant is deployment administration, and the
// deployment's own credential is the honest gate for it.
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

// handleListOrganizations answers which organisation the caller is in.
//
// Behind no permission, because knowing which organisation you belong to is not a privilege:
// GET /api/v1/me already answers it, and a page that cannot ask would have to be told by
// whoever configured it.
//
// One organisation for a person, because a person belongs to one. Until permissions existed
// this returned every tenant this control plane holds to anybody who was signed in, which on
// a deployment with more than one customer was a list of the others — invisible in
// development, where there is only ever one.
//
// The administrative token belongs to no organisation and sees them all, which is what it is
// for and is the only way a deployment operator can find a tenant to work in.
func (s *Server) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrganizations(r.Context())
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	// A person sees their own organisation; a token sees its owner's. The administrative
	// token belongs to none and sees them all, which is the only way a deployment operator
	// can find a tenant to work in.
	if mine := callerOrganization(callerFrom(r)); mine != nil {
		orgs = slices.DeleteFunc(orgs, func(org store.Organization) bool {
			return org.ID != *mine
		})
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
