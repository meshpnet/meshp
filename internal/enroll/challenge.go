package enroll

import (
	"time"

	"github.com/meshpnet/meshp/internal/challenge"
	"github.com/meshpnet/meshp/internal/clock"
)

// Why a challenge at all, when the token already authorises?
//
// Because without proof that the enroller holds the private key for the public key
// it presents, anyone with a token could register a key they do not control —
// including a key belonging to somebody else's device. identity_public_key is
// unique, so that is enough to lock a legitimate device out of its own network.
// Signing a server-chosen nonce closes it: the key recorded against a device is
// necessarily a key that device can sign with, which is the same key the control
// channel later authenticates against.
//
// The construction lives in internal/challenge, shared with control-channel
// sessions. The purpose string below is what keeps the two apart: an enrolment
// challenge must never verify a session, or a device that has been revoked could
// use a leftover enrolment challenge to open one.
const challengePurpose = "meshp enrolment challenge v1"

// DefaultChallengeTTL is how long an enrolment challenge remains valid.
const DefaultChallengeTTL = challenge.DefaultTTL

// Challenger issues and verifies enrolment challenges.
type Challenger = challenge.Challenger

// Challenge is what the device signs.
type Challenge = challenge.Challenge

// These are re-exported so the HTTP layer can map them without importing the
// challenge package, and so callers keep one vocabulary for enrolment failures.
var (
	// ErrChallengeInvalid means the challenge was not issued by us, or was altered,
	// or was issued for a different token or key.
	ErrChallengeInvalid = challenge.ErrInvalid

	// ErrChallengeExpired means the challenge was ours but is too old.
	ErrChallengeExpired = challenge.ErrExpired
)

// NewChallenger derives an enrolment challenger from the deployment's master secret.
func NewChallenger(masterSecret []byte, ttl time.Duration, clk clock.Clock) (*Challenger, error) {
	return challenge.New(masterSecret, challengePurpose, ttl, clk)
}

// ParseChallenge decodes a challenge from the wire.
func ParseChallenge(encoded string) ([]byte, error) { return challenge.Parse(encoded) }
