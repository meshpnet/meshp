// Package challenge issues short-lived, self-verifying nonces for a device to sign.
//
// It exists so that anything needing proof of possession — enrolment, and now
// control-channel sessions — uses the same construction rather than two lookalikes
// that drift apart. Getting this wrong once is bad; getting it wrong twice, slightly
// differently, is worse.
//
// A challenge carries its own validity rather than living in a table. There is
// nothing to clean up, nothing to replicate between control-plane replicas, and no
// database round trip on a path that runs before the caller has been authenticated
// at all.
//
// Every challenger is derived from the deployment's master secret with a distinct
// purpose string, so a challenge issued for one use cannot be spent on another. That
// separation is the reason this is a parameter and not a constant: a session
// challenge that verified during enrolment, or the reverse, would be a way to turn
// one credential into another.
package challenge

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
)

const (
	nonceLen  = 16
	expiryLen = 8
	macLen    = 32

	// Len is the size of a challenge on the wire.
	Len = nonceLen + expiryLen + macLen

	// DefaultTTL is generous enough for a human scanning a QR code on a slow
	// connection and far too short to be worth capturing.
	DefaultTTL = 5 * time.Minute
)

var (
	// ErrInvalid means the challenge was not issued by us, or was altered, or was
	// issued for different bindings.
	ErrInvalid = errors.New("challenge: not valid")

	// ErrExpired means the challenge was ours but is too old.
	ErrExpired = errors.New("challenge: expired")
)

// Challenger issues and verifies challenges for one purpose.
type Challenger struct {
	key []byte
	ttl time.Duration
	clk clock.Clock
}

// New derives a challenger for a purpose from the deployment's master secret.
//
// The purpose must be a stable string; changing it invalidates every outstanding
// challenge for that use, which is a deliberate way to revoke them all at once but
// not something to do by accident.
func New(masterSecret []byte, purpose string, ttl time.Duration, clk clock.Clock) (*Challenger, error) {
	if len(masterSecret) < 16 {
		return nil, fmt.Errorf("challenge: master secret is %d bytes, want at least 16", len(masterSecret))
	}
	if purpose == "" {
		return nil, errors.New("challenge: a purpose is required so one use cannot verify another")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if clk == nil {
		clk = clock.System{}
	}
	key, err := hkdf.Key(sha256.New, masterSecret, nil, purpose, 32)
	if err != nil {
		return nil, fmt.Errorf("challenge: deriving key: %w", err)
	}
	return &Challenger{key: key, ttl: ttl, clk: clk}, nil
}

// Challenge is what the device signs.
type Challenge struct {
	// Bytes is the challenge itself, signed as-is.
	Bytes []byte
	// ExpiresAt lets a client report something useful rather than failing later.
	ExpiresAt time.Time
}

// Encoded renders the challenge for JSON transport.
func (c Challenge) Encoded() string { return base64.StdEncoding.EncodeToString(c.Bytes) }

// Issue mints a challenge bound to the given values. A challenge obtained for one set
// of bindings cannot be spent on another.
func (c *Challenger) Issue(bindings ...[]byte) (Challenge, error) {
	if len(bindings) == 0 {
		return Challenge{}, errors.New("challenge: at least one binding is required")
	}
	for i, b := range bindings {
		if len(b) == 0 {
			return Challenge{}, fmt.Errorf("challenge: binding %d is empty", i)
		}
	}

	out := make([]byte, Len)
	if _, err := rand.Read(out[:nonceLen]); err != nil {
		return Challenge{}, fmt.Errorf("challenge: generating nonce: %w", err)
	}

	expiresAt := c.clk.Now().Add(c.ttl).UTC()
	binary.BigEndian.PutUint64(out[nonceLen:], uint64(expiresAt.Unix()))
	copy(out[nonceLen+expiryLen:], c.mac(out[:nonceLen+expiryLen], bindings))

	return Challenge{Bytes: out, ExpiresAt: expiresAt}, nil
}

// Verify checks a challenge came from us, is unexpired, and was issued for exactly
// these bindings in this order.
func (c *Challenger) Verify(ch []byte, bindings ...[]byte) error {
	if len(ch) != Len {
		return fmt.Errorf("%w: %d bytes, want %d", ErrInvalid, len(ch), Len)
	}

	header := ch[:nonceLen+expiryLen]
	presented := ch[nonceLen+expiryLen:]

	// Authenticate before reading the contents. Taking the expiry out of a challenge
	// we have not yet verified would be trusting an attacker's arithmetic.
	if !hmac.Equal(presented, c.mac(header, bindings)) {
		return ErrInvalid
	}

	expiresAt := time.Unix(int64(binary.BigEndian.Uint64(ch[nonceLen:])), 0).UTC()
	if !c.clk.Now().Before(expiresAt) {
		return fmt.Errorf("%w at %s", ErrExpired, expiresAt.Format(time.RFC3339))
	}
	return nil
}

// Parse decodes a challenge from the wire.
func Parse(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: not valid base64", ErrInvalid)
	}
	if len(raw) != Len {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrInvalid, len(raw), Len)
	}
	return raw, nil
}

// mac binds a challenge to its purpose key and its bindings.
//
// Every input is length-prefixed, so no two different tuples can produce the same
// byte stream — without it, bindings ("ab", "c") and ("a", "bc") would authenticate
// each other's challenges.
func (c *Challenger) mac(header []byte, bindings [][]byte) []byte {
	h := hmac.New(sha256.New, c.key)
	writeLengthPrefixed(h, header)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(bindings)))
	_, _ = h.Write(count[:])
	for _, b := range bindings {
		writeLengthPrefixed(h, b)
	}
	return h.Sum(nil)
}

func writeLengthPrefixed(h hash.Hash, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}
