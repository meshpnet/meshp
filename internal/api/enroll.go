package api

import (
	"encoding/base64"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/enroll"
	"github.com/meshpnet/meshp/internal/httpx"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// --- device endpoints -------------------------------------------------------

type challengeRequest struct {
	Token             string `json:"token"`
	IdentityPublicKey string `json:"identity_public_key"` // base64
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if err := decode(w, r, &req); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	identity, err := base64.StdEncoding.DecodeString(req.IdentityPublicKey)
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"identity_public_key must be standard base64")
		return
	}

	resp, err := s.enroll.IssueChallenge(r.Context(), enroll.ChallengeRequest{
		Token:             req.Token,
		IdentityPublicKey: identity,
	})
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, resp)
}

type redeemRequest struct {
	Token              string `json:"token"`
	IdentityPublicKey  string `json:"identity_public_key"`  // base64
	Challenge          string `json:"challenge"`            // base64, as issued
	Signature          string `json:"signature"`            // base64, over the challenge
	WireGuardPublicKey string `json:"wireguard_public_key"` // base64

	Name         string `json:"name,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os,omitempty"`
	OSVersion    string `json:"os_version,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

func (s *Server) handleRedeem(w http.ResponseWriter, r *http.Request) {
	var req redeemRequest
	if err := decode(w, r, &req); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	identity, err := base64.StdEncoding.DecodeString(req.IdentityPublicKey)
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"identity_public_key must be standard base64")
		return
	}
	challenge, err := enroll.ParseChallenge(req.Challenge)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"signature must be standard base64")
		return
	}

	source := sourceAddr(r)
	res, err := s.enroll.Redeem(r.Context(), enroll.RedeemRequest{
		Token:              req.Token,
		IdentityPublicKey:  identity,
		Challenge:          challenge,
		Signature:          signature,
		WireGuardPublicKey: req.WireGuardPublicKey,
		Name:               req.Name,
		Hostname:           req.Hostname,
		OS:                 req.OS,
		OSVersion:          req.OSVersion,
		AgentVersion:       req.AgentVersion,
		SourceIP:           source,
	})
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusCreated, res)
}

// sourceAddr extracts the caller's address for the audit trail. Nil when it cannot
// be parsed, which is better than recording something invented.
func sourceAddr(r *http.Request) *netip.Addr {
	host := clientKey(r)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	return &addr
}

// --- administrative endpoints -----------------------------------------------

type createTokenRequest struct {
	MaxUses          int32    `json:"max_uses,omitempty"`
	ExpiresInSeconds int64    `json:"expires_in_seconds,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type createTokenResponse struct {
	// Token is the only time the plaintext exists outside the device that will use
	// it. Nothing stores it; if it is lost, mint another.
	Token     string    `json:"token"`
	TokenID   uuid.UUID `json:"token_id"`
	NetworkID uuid.UUID `json:"network_id"`
	MaxUses   int32     `json:"max_uses"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	var req createTokenRequest
	if err := decode(w, r, &req); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	// A short default life, because an enrolment token is meant to be used within
	// minutes of being handed over, and one that lingers for a month is a credential
	// nobody is thinking about any more.
	if req.ExpiresInSeconds <= 0 {
		req.ExpiresInSeconds = int64((1 * time.Hour).Seconds())
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}

	network, err := s.store.Queries().GetNetwork(r.Context(), networkID)
	if err != nil {
		s.notFoundOr(w, r, err, "no such network")
		return
	}

	token, err := enroll.NewToken()
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	expiresAt := s.cfg.Clock.Now().Add(time.Duration(req.ExpiresInSeconds) * time.Second)

	row, err := s.store.Queries().CreateEnrollmentToken(r.Context(), dbgen.CreateEnrollmentTokenParams{
		NetworkID:       network.ID,
		OrganizationID:  network.OrganizationID,
		TokenHash:       token.Hash,
		PreassignedTags: req.Tags,
		MaxUses:         req.MaxUses,
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	// The plaintext is deliberately absent from this log line.
	s.log.Info("enrolment token minted",
		"token_id", row.ID, "network_id", network.ID,
		"max_uses", row.MaxUses, "expires_at", row.ExpiresAt)

	httpx.WriteJSON(w, s.log, http.StatusCreated, createTokenResponse{
		Token:     token.Plaintext,
		TokenID:   row.ID,
		NetworkID: row.NetworkID,
		MaxUses:   row.MaxUses,
		ExpiresAt: row.ExpiresAt,
	})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	// Rows only, never plaintext — there is none to return, which is the point of
	// storing a hash.
	rows, err := s.store.Queries().ListEnrollmentTokensForNetwork(r.Context(), networkID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	if rows == nil {
		rows = []dbgen.ListEnrollmentTokensForNetworkRow{}
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"tokens": rows})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	tokenID, ok := s.pathUUID(w, r, "tokenID")
	if !ok {
		return
	}

	// Scoped by network as well as id, so a token id from one network cannot be used
	// to revoke in another.
	affected, err := s.store.Queries().RevokeEnrollmentToken(r.Context(), dbgen.RevokeEnrollmentTokenParams{
		ID:        tokenID,
		NetworkID: networkID,
	})
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	if affected == 0 {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found",
			"no such token in that network, or it was already revoked")
		return
	}
	s.log.Info("enrolment token revoked", "token_id", tokenID, "network_id", networkID)
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]string{"status": "revoked"})
}

// pathUUID parses a path parameter, answering the client on failure.
func (s *Server) pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	raw := r.PathValue(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", name+" must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

// notFoundOr turns a missing row into a 404 and anything else into a 500.
func (s *Server) notFoundOr(w http.ResponseWriter, r *http.Request, err error, message string) {
	if isNotFound(err) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found", message)
		return
	}
	s.respondError(w, r, err)
}
