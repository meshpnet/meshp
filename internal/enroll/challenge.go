package enroll

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

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
// channel will later authenticate against.
//
// The challenge carries its own validity rather than living in a table. There is
// nothing to clean up, nothing to replicate between control-plane replicas, and no
// extra round trip to the database on a path that runs before the caller has been
// authenticated at all. It is safe to be stateless here because replaying a whole
// enrolment is already stopped by the token's use count, so a challenge being
// reusable inside its short window buys an attacker nothing.
const (
	challengeNonceLen  = 16
	challengeExpiryLen = 8
	challengeMACLen    = 32
	challengeLen       = challengeNonceLen + challengeExpiryLen + challengeMACLen

	// DefaultChallengeTTL is generous enough for a human scanning a QR code on a
	// slow connection and far too short to be worth capturing.
	DefaultChallengeTTL = 5 * time.Minute

	challengeKeyPurpose = "meshp enrolment challenge v1"
)

var (
	// ErrChallengeInvalid means the challenge was not issued by us, or was altered,
	// or was issued for a different token or key.
	ErrChallengeInvalid = errors.New("enroll: challenge is not valid")

	// ErrChallengeExpired means the challenge was ours but is too old.
	ErrChallengeExpired = errors.New("enroll: challenge has expired")
)

// Challenger issues and verifies enrolment challenges.
type Challenger struct {
	key []byte
	ttl time.Duration
	clk clock.Clock
}

// NewChallenger derives a challenge key from the deployment's master secret.
//
// The key is derived rather than used directly so that this cannot be confused
// with any other use of the same secret: a signature made for one purpose must
// never verify for another.
func NewChallenger(masterSecret []byte, ttl time.Duration, clk clock.Clock) (*Challenger, error) {
	if len(masterSecret) < 16 {
		return nil, fmt.Errorf("enroll: master secret is %d bytes, want at least 16", len(masterSecret))
	}
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	if clk == nil {
		clk = clock.System{}
	}
	key, err := hkdf.Key(sha256.New, masterSecret, nil, challengeKeyPurpose, 32)
	if err != nil {
		return nil, fmt.Errorf("enroll: deriving challenge key: %w", err)
	}
	return &Challenger{key: key, ttl: ttl, clk: clk}, nil
}

// Challenge is what the device signs.
type Challenge struct {
	// Bytes is the challenge itself, signed as-is.
	Bytes []byte
	// ExpiresAt is returned so a client can report something useful rather than
	// simply failing later.
	ExpiresAt time.Time
}

// Encoded renders the challenge for JSON transport.
func (c Challenge) Encoded() string { return base64.StdEncoding.EncodeToString(c.Bytes) }

// Issue mints a challenge bound to one token and one identity key. Binding both
// means a challenge obtained for one enrolment cannot be spent on another.
func (c *Challenger) Issue(tokenHash, identityPublicKey []byte) (Challenge, error) {
	if len(tokenHash) == 0 || len(identityPublicKey) == 0 {
		return Challenge{}, errors.New("enroll: cannot issue a challenge without a token hash and public key")
	}

	out := make([]byte, challengeLen)
	if _, err := rand.Read(out[:challengeNonceLen]); err != nil {
		return Challenge{}, fmt.Errorf("enroll: generating challenge nonce: %w", err)
	}

	expiresAt := c.clk.Now().Add(c.ttl).UTC()
	binary.BigEndian.PutUint64(out[challengeNonceLen:], uint64(expiresAt.Unix()))

	mac := c.mac(out[:challengeNonceLen+challengeExpiryLen], tokenHash, identityPublicKey)
	copy(out[challengeNonceLen+challengeExpiryLen:], mac)

	return Challenge{Bytes: out, ExpiresAt: expiresAt}, nil
}

// Verify checks a challenge came from us, is unexpired, and was issued for this
// token and key.
func (c *Challenger) Verify(challenge, tokenHash, identityPublicKey []byte) error {
	if len(challenge) != challengeLen {
		return fmt.Errorf("%w: %d bytes, want %d", ErrChallengeInvalid, len(challenge), challengeLen)
	}

	header := challenge[:challengeNonceLen+challengeExpiryLen]
	presented := challenge[challengeNonceLen+challengeExpiryLen:]
	expected := c.mac(header, tokenHash, identityPublicKey)

	// Authenticate before looking at the contents. Reading the expiry out of a
	// challenge we have not yet verified would be trusting an attacker's arithmetic.
	if !hmac.Equal(presented, expected) {
		return ErrChallengeInvalid
	}

	expiresAt := time.Unix(int64(binary.BigEndian.Uint64(challenge[challengeNonceLen:])), 0).UTC()
	if !c.clk.Now().Before(expiresAt) {
		return fmt.Errorf("%w at %s", ErrChallengeExpired, expiresAt.Format(time.RFC3339))
	}
	return nil
}

// ParseChallenge decodes a challenge from the wire.
func ParseChallenge(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: not valid base64", ErrChallengeInvalid)
	}
	if len(raw) != challengeLen {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrChallengeInvalid, len(raw), challengeLen)
	}
	return raw, nil
}

// mac binds a challenge to the token and key it was issued for. Every input is
// length-prefixed, so no two different tuples can produce the same byte stream.
func (c *Challenger) mac(header, tokenHash, identityPublicKey []byte) []byte {
	h := hmac.New(sha256.New, c.key)
	writeLengthPrefixed(h, header)
	writeLengthPrefixed(h, tokenHash)
	writeLengthPrefixed(h, identityPublicKey)
	return h.Sum(nil)
}

func writeLengthPrefixed(h interface{ Write([]byte) (int, error) }, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}
