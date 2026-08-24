package api

import (
	"net/http"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// handleCreateUser adds a person to an organisation and gives them a role.
//
// The role is optional and the default is not the same for everybody: the first person in an
// organisation becomes its owner, because somebody has to be able to grant a role and on a
// fresh organisation there is nobody who can; everybody after them becomes an administrator,
// because making every account an owner is how a permission system ends up meaning nothing.
// What was granted comes back in the response rather than being left to be discovered.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`

		// Role is a slug: one of the built-ins, or one this organisation defined. The
		// permission catalogue is at GET /api/v1/permissions and the roles that can be
		// granted at GET /api/v1/organizations/{id}/roles.
		Role string `json:"role"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	user, binding, err := s.store.CreateUser(r.Context(), store.CreateUserRequest{
		Organization: orgID,
		Email:        body.Email,
		Name:         body.Name,
		Password:     body.Password,
		Role:         body.Role,
		Actor:        s.actor(r),
		SourceIP:     requestAddr(r),
	})
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	out := userJSON(user)
	out["role"] = binding.RoleSlug
	httpx.WriteJSON(w, s.log, http.StatusCreated, out)
}

// handleListUsers answers who is in an organisation.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	users, err := s.store.ListUsers(r.Context(), orgID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, user := range users {
		out = append(out, userJSON(user))
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"users": out})
}

// handleSetUserSuspended stops somebody signing in, or lets them again.
//
// Its own sub-resource rather than a field on a general update, for the reason the
// fail-closed setting gives: it is the one thing here that decides whether a person can
// still get in, a PUT that names it in the path cannot be made by accident, and it reads
// unambiguously in an access log.
//
// Suspending ends every session they hold. A suspension that left one running would be a
// decision the system agreed with and did not act on.
func (s *Server) handleSetUserSuspended(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	userID, ok := s.pathUUID(w, r, "userID")
	if !ok {
		return
	}
	var body struct {
		Suspended bool `json:"suspended"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	if err := s.store.SetUserSuspended(r.Context(), orgID, userID, body.Suspended); err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"user_id":   userID,
		"suspended": body.Suspended,
	})
}

// handleDeleteUser removes a person.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	userID, ok := s.pathUUID(w, r, "userID")
	if !ok {
		return
	}
	if err := s.store.DeleteUser(r.Context(), orgID, userID); err != nil {
		s.respondError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSetUserPassword sets somebody else's password.
//
// The administrative half of ADR-0024 §6: no email is required to run meshp, so a person
// who has forgotten their password is given a new one by an administrator rather than sent
// a link by a mail server this deployment may not have.
//
// It ends every session that person holds, like any other password change.
func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	userID, ok := s.pathUUID(w, r, "userID")
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	// Scoped to the organisation named in the path before anything is changed, so a caller
	// cannot set the password of a user in another one by guessing an id.
	users, err := s.store.ListUsers(r.Context(), orgID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	found := false
	for _, user := range users {
		if user.ID == userID {
			found = true
		}
	}
	if !found {
		s.respondError(w, r, store.ErrNoSuchUser)
		return
	}

	if err := s.store.SetPassword(r.Context(), userID, body.Password); err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"user_id": userID,
		"message": "password set; every session that user held was ended",
	})
}

func userJSON(user store.User) map[string]any {
	return map[string]any{
		"user_id":         user.ID,
		"email":           user.Email,
		"name":            user.Name,
		"organization_id": user.OrganizationID,
		"created_at":      user.CreatedAt.UTC(),
		"suspended":       user.Suspended,
	}
}
