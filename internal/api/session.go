package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/httpx"
)

type sessionChallengeRequest struct {
	IdentityPublicKey string `json:"identity_public_key"` // base64
	MembershipID      string `json:"membership_id"`
}

type sessionChallengeResponse struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// handleSessionChallenge mints something for an agent to sign.
//
// It does not check that the membership exists. Doing so would turn this into an
// enumeration oracle for membership ids, and it would buy nothing: the signature
// check at connect time is what decides, and a challenge for a membership that does
// not exist simply fails there.
func (s *Server) handleSessionChallenge(w http.ResponseWriter, r *http.Request) {
	if s.session == nil {
		httpx.Error(w, s.log, http.StatusServiceUnavailable,
			"not_ready", "the control channel is not available")
		return
	}

	var req sessionChallengeRequest
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
	membershipID, err := uuid.Parse(req.MembershipID)
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "membership_id must be a UUID")
		return
	}

	ch, err := s.session.IssueChallenge(identity, membershipID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, sessionChallengeResponse{
		Challenge: ch.Encoded(),
		ExpiresAt: ch.ExpiresAt,
	})
}

// handleSession upgrades to the control channel.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if s.session == nil {
		httpx.Error(w, s.log, http.StatusServiceUnavailable,
			"not_ready", "the control channel is not available")
		return
	}
	s.session.Serve(w, r)
}
