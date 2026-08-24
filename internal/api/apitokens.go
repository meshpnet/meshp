package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// handleMintToken gives a machine a credential to act as the caller.
//
// Your own, and nobody else's. There is no route that mints a token for another person,
// because a token acts within its owner's permissions — so minting one for somebody else
// would be a way to act as them, and an endpoint that could do it would be a way for an
// administrator to become an owner.
//
// A token cannot mint a token either. Otherwise a leaked credential could produce a fresh
// one on the way out and survive its own revocation, which is exactly the property revoking
// is for.
func (s *Server) handleMintToken(w http.ResponseWriter, r *http.Request) {
	user := s.personOrRefuse(w, r, "minting a token")
	if user == nil {
		return
	}

	var body struct {
		Name string `json:"name"`

		// Permissions is required. A credential minted without saying what it is for is one
		// that ends up being used for everything, and this is the only moment somebody is
		// thinking about the question.
		Permissions []string `json:"permissions"`

		// NetworkID narrows the token to one network, the same shape a role binding uses.
		// Omitted reaches every network its owner does.
		NetworkID string `json:"network_id"`

		// ExpiresInSeconds defaults to ninety days and may not exceed a year. There is no
		// unexpiring token on purpose.
		ExpiresInSeconds int64 `json:"expires_in_seconds"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
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

	minted, err := s.store.MintToken(r.Context(), store.MintTokenRequest{
		Organization: user.OrganizationID,
		Owner:        user.ID,
		Name:         body.Name,
		Scope:        body.Permissions,
		Network:      networkID,
		ExpiresIn:    time.Duration(body.ExpiresInSeconds) * time.Second,
		Actor:        s.actor(r),
		SourceIP:     requestAddr(r),
	})
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	s.log.Info("api token minted",
		"name", minted.Name, "user_id", user.ID, "expires_at", minted.ExpiresAt)

	out := tokenJSON(minted.APIToken)
	// The one time this is ever returned. Said out loud, because a caller that does not
	// store it now has to mint another and prune this one.
	out["token"] = minted.Plaintext
	out["note"] = "this is the only time the token is shown; store it now"
	httpx.WriteJSON(w, s.log, http.StatusCreated, out)
}

// handleListOwnTokens answers what credentials the caller has out.
func (s *Server) handleListOwnTokens(w http.ResponseWriter, r *http.Request) {
	user := s.personOrRefuse(w, r, "listing your tokens")
	if user == nil {
		return
	}
	tokens, err := s.store.ListTokensForUser(r.Context(), user.ID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"tokens": renderTokens(tokens)})
}

// handleRevokeOwnToken withdraws one of the caller's own credentials.
//
// Not behind a permission: pruning your own credentials is like changing your own password,
// and needing to be granted the right to do it would leave somebody unable to clean up after
// themselves.
func (s *Server) handleRevokeOwnToken(w http.ResponseWriter, r *http.Request) {
	user := s.personOrRefuse(w, r, "revoking a token")
	if user == nil {
		return
	}
	tokenID, ok := s.pathUUID(w, r, "tokenID")
	if !ok {
		return
	}

	owner := user.ID
	if err := s.store.RevokeToken(r.Context(), store.RevokeTokenRequest{
		Organization: user.OrganizationID,
		Token:        tokenID,
		Owner:        &owner,
		Actor:        s.actor(r),
		SourceIP:     requestAddr(r),
	}); err != nil {
		s.respondError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListOrganizationTokens answers what credentials exist in an organisation.
//
// What somebody opens when a person leaves. Carries whose each token is, which is the whole
// reason to look.
func (s *Server) handleListOrganizationTokens(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	tokens, err := s.store.ListTokensForOrganization(r.Context(), orgID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"tokens": renderTokens(tokens)})
}

// handleRevokeOrganizationToken withdraws somebody else's credential.
func (s *Server) handleRevokeOrganizationToken(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.pathUUID(w, r, "organizationID")
	if !ok {
		return
	}
	tokenID, ok := s.pathUUID(w, r, "tokenID")
	if !ok {
		return
	}
	if err := s.store.RevokeToken(r.Context(), store.RevokeTokenRequest{
		Organization: orgID,
		Token:        tokenID,
		Actor:        s.actor(r),
		SourceIP:     requestAddr(r),
	}); err != nil {
		s.respondError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// personOrRefuse is the caller as a person, or nil having already answered.
//
// The routes that use it are behind guardSignedIn, which admits machines as well — so this
// is what separates "any caller we can identify" from "a person". Minting a credential and
// changing a password are both things a machine holding somebody's token must not be able to
// do on their behalf.
func (s *Server) personOrRefuse(w http.ResponseWriter, r *http.Request, what string) *store.User {
	c := callerFrom(r)
	if c.user != nil {
		return c.user
	}
	if c.token != nil {
		// Named specifically, because the alternative is somebody debugging a CI job that
		// gets a generic refusal from a credential that works everywhere else.
		httpx.Error(w, s.log, http.StatusForbidden, "person_required",
			"an API token cannot do this on its owner's behalf; "+what+" needs a person signed in. "+
				"A token that could mint a token would survive its own revocation.")
		return nil
	}
	httpx.Error(w, s.log, http.StatusForbidden, "person_required",
		"this needs a person signed in; "+what+" is not something the administrative token does")
	return nil
}

func renderTokens(tokens []store.APIToken) []map[string]any {
	out := make([]map[string]any, 0, len(tokens))
	for _, token := range tokens {
		out = append(out, tokenJSON(token))
	}
	return out
}

func tokenJSON(token store.APIToken) map[string]any {
	scope := token.Scope
	if scope == nil {
		scope = []string{}
	}
	out := map[string]any{
		"token_id":    token.ID,
		"name":        token.Name,
		"permissions": scope,
		"expires_at":  token.ExpiresAt.UTC(),
		"created_at":  token.CreatedAt.UTC(),
		// Rendered as a scope rather than as a null network id, for the reason a role
		// binding is: "everywhere its owner reaches" and "this one network" are the two
		// answers somebody is reading this to tell apart.
		"scope":   "organization",
		"revoked": token.RevokedAt != nil,
	}
	if token.Network != nil {
		out["scope"] = "network"
		out["network_id"] = *token.Network
	}
	if token.OwnerEmail != "" {
		out["owner"] = token.OwnerEmail
	}
	if token.LastUsedAt != nil {
		out["last_used_at"] = token.LastUsedAt.UTC()
	}
	return out
}
