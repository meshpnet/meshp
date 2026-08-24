package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/authz"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// handleListPermissions answers what permissions exist.
//
// The catalogue, and nothing about the caller. It is served because a consumer choosing what
// a role should hold is choosing from this list, and a list nobody can enumerate has to be
// read out of the source. ADR-0009 makes the commercial layer one of those consumers.
//
// Behind no permission of its own: what a system *can* express is not a secret, and any
// caller this control plane can identify has already been told more than this by /api/v1/me.
func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	out := make([]map[string]any, 0, len(authz.Catalogue))
	for _, e := range authz.Catalogue {
		out = append(out, map[string]any{
			"permission":  string(e.Name),
			"description": e.Description,
			// Said rather than left to be derived from the name, because it is what
			// decides whether a binding narrowed to one network can grant it.
			"scope": scopeOf(e.Name),
		})
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"permissions": out})
}

// scopeOf is where a permission is held: in one network, or across an organisation.
//
// The difference is the design rather than a naming convention. A grant narrowed to a single
// network can carry a `network.` permission and never carries an `organization.` one, which
// is what stops a technician who looks after one customer from being able to create accounts
// across the organisation that customer sits in.
func scopeOf(p authz.Permission) string {
	if strings.HasPrefix(string(p), "network.") {
		return "network"
	}
	return "organization"
}

// handleListRoles answers what roles this organisation can grant.
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	roles, err := s.store.ListRoles(r.Context(), orgID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		permissions := role.Permissions
		if permissions == nil {
			permissions = []string{}
		}
		out = append(out, map[string]any{
			"role":        role.Slug,
			"name":        role.Name,
			"permissions": permissions,
			// Said out loud because it decides whether editing it would survive a restart:
			// the built-ins are reconciled from the permission catalogue at startup, so a
			// deployment that wants a different set makes its own role.
			"builtin": role.Builtin,
		})
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"roles": out})
}

// handleListUserRoles answers what one person holds in this organisation.
func (s *Server) handleListUserRoles(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	userID, ok := s.pathUUID(w, r, "userID")
	if !ok {
		return
	}
	bindings, err := s.store.ListBindings(r.Context(), orgID, userID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"user_id": userID,
		"roles":   renderBindings(bindings),
	})
}

func renderBindings(bindings []store.Binding) []map[string]any {
	out := make([]map[string]any, 0, len(bindings))
	for _, b := range bindings {
		entry := map[string]any{
			"binding_id": b.ID,
			"role":       b.RoleSlug,
			"name":       b.RoleName,
			"granted_at": b.CreatedAt.UTC(),
			// Rendered as an explicit scope rather than as a null network id, because
			// "everywhere in this organisation" and "this one network" are the two
			// answers somebody is reading this to tell apart.
			"scope": "organization",
		}
		if b.Network != nil {
			entry["scope"] = "network"
			entry["network_id"] = *b.Network
			entry["network"] = b.NetworkSlug
			entry["network_name"] = b.NetworkName
		}
		out = append(out, entry)
	}
	return out
}

// handleGrantRole gives somebody a role, optionally in one network only.
func (s *Server) handleGrantRole(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	userID, ok := s.pathUUID(w, r, "userID")
	if !ok {
		return
	}

	var body struct {
		Role string `json:"role"`
		// NetworkID narrows the grant to one network. Omitted grants it across the
		// organisation, which is the ordinary case and the more powerful one — so it is
		// what you get by saying nothing only because the alternative, a required field
		// somebody sets to a network they happen to be looking at, is worse.
		NetworkID string `json:"network_id"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if body.Role == "" {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"say which role: "+knownRoles())
		return
	}

	var networkID *uuid.UUID
	if body.NetworkID != "" {
		parsed, err := uuid.Parse(body.NetworkID)
		if err != nil {
			httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "network_id must be a UUID")
			return
		}
		networkID = &parsed
	}

	binding, err := s.store.BindRole(r.Context(), store.BindRequest{
		Organization: orgID,
		User:         userID,
		Role:         body.Role,
		Network:      networkID,
		Actor:        s.actor(r),
		SourceIP:     requestAddr(r),
	})
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	s.log.Info("role granted",
		"role", binding.RoleSlug, "user_id", userID, "organization_id", orgID)
	httpx.WriteJSON(w, s.log, http.StatusCreated, map[string]any{
		"user_id": userID,
		"role":    binding.RoleSlug,
		"roles":   renderBindings([]store.Binding{binding}),
	})
}

// handleRevokeRole takes a role away.
func (s *Server) handleRevokeRole(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	bindingID, ok := s.pathUUID(w, r, "bindingID")
	if !ok {
		return
	}

	err := s.store.UnbindRole(r.Context(), store.UnbindRequest{
		Organization: orgID,
		Binding:      bindingID,
		Actor:        s.actor(r),
		SourceIP:     requestAddr(r),
	})
	if errors.Is(err, store.ErrLastOwner) {
		httpx.Error(w, s.log, http.StatusConflict, "last_owner",
			"that is the last owner of this organisation; grant somebody else the owner role first")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// knownRoles is the built-in slugs, for a message telling somebody what they may have meant.
// An organisation's own roles are deliberately not listed: this is the fallback when nothing
// was said at all, and the four built-ins are what every deployment has.
func knownRoles() string {
	out := ""
	for i, b := range authz.Builtins() {
		if i > 0 {
			out += ", "
		}
		out += b.Slug
	}
	return out
}
