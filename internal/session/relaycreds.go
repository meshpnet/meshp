package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/relayproto"
	"github.com/meshpnet/meshp/internal/relaytoken"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// reissueWithin is how close to expiry a token must be before a new one is minted.
//
// Asking again while the current token is comfortably valid gets the same token back rather
// than a new one. That bounds a misbehaving agent to one live credential instead of as many
// as it cares to request, and makes a retry loop cost nothing (ADR-0017).
const reissueWithin = 5 * time.Minute

// RelayIssuer mints the capability a relay checks.
//
// Held by the control plane and nowhere else: the relay verifies a signature and cannot
// produce one, which is what stops a compromised relay granting access to a network it was
// never given (ADR-0016).
type RelayIssuer struct {
	signer ed25519.PrivateKey
	ttl    time.Duration
}

// NewRelayIssuer returns an issuer, or nothing if the deployment has no signing key.
//
// A control plane with no key cannot issue, and says so when asked rather than failing to
// start: relaying is one feature, and a deployment that has not configured it should still
// enrol devices and carry state.
func NewRelayIssuer(signer ed25519.PrivateKey, ttl time.Duration) (*RelayIssuer, error) {
	if len(signer) == 0 {
		return nil, nil
	}
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("session: relay signing key is %d bytes, want %d",
			len(signer), ed25519.PrivateKeySize)
	}
	if ttl <= 0 {
		ttl = relaytoken.DefaultTTL
	}
	return &RelayIssuer{signer: signer, ttl: ttl}, nil
}

// PublicKey is what a relay must be configured with.
func (r *RelayIssuer) PublicKey() ed25519.PublicKey {
	if r == nil {
		return nil
	}
	return r.signer.Public().(ed25519.PublicKey)
}

// handleRelayTokenRequest answers an agent asking for a relay credential.
//
// The membership comes from the session rather than from the request, so an agent can only
// ever be issued a token for the key it authenticated as.
func (s *Server) handleRelayTokenRequest(ctx context.Context, sess *Session) {
	token, expires, err := s.relayTokenFor(ctx, sess)

	msg := &meshpv1.RelayToken{}
	if err != nil {
		// The reason reaches the agent so a person reading its log can see why relaying is
		// not working, but it is a short phrase rather than an internal error: this crosses
		// a trust boundary in the direction of a device.
		msg.Error = "relaying is not available"
		s.log.Warn("could not issue a relay token",
			"membership_id", sess.MembershipID, "error", err)
	} else {
		msg.Token = token
		msg.ExpiresAtUnix = expires.Unix()
	}

	sess.enqueue(&meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_RelayToken{RelayToken: msg}})
}

// relayTokenFor mints, or returns the one already in force.
func (s *Server) relayTokenFor(ctx context.Context, sess *Session) ([]byte, time.Time, error) {
	if s.relay == nil {
		return nil, time.Time{}, errors.New("this deployment has no relay signing key configured")
	}

	membership, err := s.store.Queries().GetMembershipForSession(ctx, sess.MembershipID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("loading membership: %w", err)
	}

	// Re-checked here rather than trusted from the handshake. A session outlives the
	// request that opened it, so a device revoked mid-session would otherwise be handed a
	// fresh half-hour capability on its way out — and the relay cannot know better,
	// because a token it can verify is a token it must honour.
	//
	// It does not make an outstanding token expire. That is the reason revocation is
	// enforced by the peers dropping the key rather than by cutting off the relay: the
	// revoked device may still reach the relay until its token runs out, and there is
	// no longer anybody on the far side willing to decrypt what it sends.
	if membership.DeviceRevokedAt != nil || membership.MembershipState != "active" {
		return nil, time.Time{}, errors.New("this membership is no longer active")
	}

	encoded, err := s.store.Queries().GetWireGuardKeyForMembership(ctx, sess.MembershipID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("loading this membership's WireGuard key: %w", err)
	}
	key, err := relayKeyOf(encoded)
	if err != nil {
		return nil, time.Time{}, err
	}

	now := s.clk.Now()
	// Reuse while there is comfortable life left, so a retry loop costs one signature rather
	// than one per attempt, and a device holds one credential rather than a collection.
	if existing, expires, ok := sess.relayToken(); ok && expires.Sub(now) > reissueWithin {
		return existing, expires, nil
	}

	expires := now.Add(s.relay.ttl)
	token, err := relaytoken.Issue(s.relay.signer, key, networkIDBytes(membership.NetworkID), expires)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("issuing: %w", err)
	}
	sess.setRelayToken(token, expires)
	return token, expires, nil
}

// relayKeyOf turns the stored base64 WireGuard key into the raw form a token names.
func relayKeyOf(encoded string) (relayproto.Key, error) {
	var key relayproto.Key
	parsed, err := keys.ParseWireGuardKey(encoded)
	if err != nil {
		return key, fmt.Errorf("this membership's WireGuard key is unusable: %w", err)
	}
	copy(key[:], parsed[:])
	return key, nil
}

func networkIDBytes(id uuid.UUID) [16]byte {
	var out [16]byte
	copy(out[:], id[:])
	return out
}
