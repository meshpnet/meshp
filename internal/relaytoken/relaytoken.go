// Package relaytoken issues and verifies the capability a relay checks before forwarding.
//
// The relay must be able to say no without being able to say yes on its own: it holds a
// public key and nothing else, so a compromised relay cannot mint access to a network it was
// never given (ADR-0016). The control plane signs; the relay verifies.
//
// The token is deliberately not a bearer credential for anything but relaying. It names one
// WireGuard key and one network, and it expires. Stealing one buys the ability to have that
// key's relayed packets delivered to you — which you still cannot decrypt — until it
// expires, and nothing else.
package relaytoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/meshpnet/meshp/internal/relayproto"
)

// Version is the token layout this package writes.
//
// First byte on the wire, so a relay meeting a token from a newer control plane can say
// which version it does not understand instead of failing to parse and blaming the
// signature.
const Version byte = 1

// DefaultTTL is how long an issued token is good for.
//
// Short, because a token is trivially reissued over the control channel an agent already
// holds, and the whole cost of a stolen one is bounded by this. Long enough that a relay
// reconnect during a brief control-plane outage still works — losing the control plane must
// not cost connectivity (Invariant 15).
const DefaultTTL = 30 * time.Minute

// Layout, all fixed width so parsing cannot disagree with writing:
//
//	 1  version
//	32  WireGuard public key this token speaks for
//	16  network id
//	 8  expiry, unix seconds, big endian
//	64  Ed25519 signature over everything above
const (
	versionLen   = 1
	networkIDLen = 16
	expiryLen    = 8

	signedLen = versionLen + relayproto.KeyLen + networkIDLen + expiryLen
	// Size is the encoded length of a token.
	Size = signedLen + ed25519.SignatureSize
)

// Errors verification can produce. Distinguished because they mean different things to an
// operator: an expired token is an agent that needs to ask for another, while a bad
// signature is a relay configured with the wrong public key, or an attack.
var (
	// ErrMalformed means the token is not the right shape.
	ErrMalformed = errors.New("relaytoken: malformed")
	// ErrVersion means the token was written by a newer issuer.
	ErrVersion = errors.New("relaytoken: unsupported version")
	// ErrSignature means the signature does not verify against the given public key.
	ErrSignature = errors.New("relaytoken: signature does not verify")
	// ErrExpired means the token is past its expiry.
	ErrExpired = errors.New("relaytoken: expired")
)

// Grant is what a valid token permits.
type Grant struct {
	Key       relayproto.Key
	NetworkID [networkIDLen]byte
	ExpiresAt time.Time
}

// Network renders the network id as a UUID string, which is what it is everywhere else.
func (g Grant) Network() string {
	b := g.NetworkID
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Issue signs a token granting a key the use of a relay on a network.
func Issue(signer ed25519.PrivateKey, key relayproto.Key, networkID [networkIDLen]byte, expiresAt time.Time) ([]byte, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("relaytoken: signing key is %d bytes, want %d", len(signer), ed25519.PrivateKeySize)
	}
	if expiresAt.IsZero() {
		return nil, errors.New("relaytoken: a token without an expiry is a permanent credential")
	}

	out := make([]byte, Size)
	out[0] = Version
	copy(out[versionLen:], key[:])
	copy(out[versionLen+relayproto.KeyLen:], networkID[:])
	binary.BigEndian.PutUint64(out[versionLen+relayproto.KeyLen+networkIDLen:], uint64(expiresAt.Unix()))
	copy(out[signedLen:], ed25519.Sign(signer, out[:signedLen]))
	return out, nil
}

// Verify checks a token and reports what it grants.
//
// The signature is checked before the expiry, deliberately. Reporting "expired" for a
// forgery would tell an attacker their forgery parsed, and the cheaper check is the one that
// leaks more.
func Verify(public ed25519.PublicKey, token []byte, now time.Time) (Grant, error) {
	if len(public) != ed25519.PublicKeySize {
		return Grant{}, fmt.Errorf("relaytoken: public key is %d bytes, want %d", len(public), ed25519.PublicKeySize)
	}
	if len(token) != Size {
		return Grant{}, fmt.Errorf("%w: %d bytes, want %d", ErrMalformed, len(token), Size)
	}
	if token[0] != Version {
		return Grant{}, fmt.Errorf("%w: %d, this relay understands %d", ErrVersion, token[0], Version)
	}
	if !ed25519.Verify(public, token[:signedLen], token[signedLen:]) {
		return Grant{}, ErrSignature
	}

	var grant Grant
	copy(grant.Key[:], token[versionLen:versionLen+relayproto.KeyLen])
	copy(grant.NetworkID[:], token[versionLen+relayproto.KeyLen:versionLen+relayproto.KeyLen+networkIDLen])
	grant.ExpiresAt = time.Unix(
		int64(binary.BigEndian.Uint64(token[versionLen+relayproto.KeyLen+networkIDLen:])), 0).UTC()

	if now.After(grant.ExpiresAt) {
		return Grant{}, fmt.Errorf("%w: at %s, now %s",
			ErrExpired, grant.ExpiresAt.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return grant, nil
}

// Encode renders a token for a place that needs text, such as the control plane's JSON.
func Encode(token []byte) string { return base64.StdEncoding.EncodeToString(token) }

// Decode parses the text form.
func Decode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: not base64: %w", ErrMalformed, err)
	}
	return b, nil
}
