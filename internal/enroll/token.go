// Package enroll turns a one-time token into a device that belongs to a network.
//
// Enrolment is the one moment a machine with no prior relationship to the control
// plane is granted one, so it is deliberately narrow: a token authorises, a
// signature authenticates, and both are checked before a single row is written.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// TokenPrefix marks a meshp enrolment token.
//
// A distinctive, searchable prefix is worth the characters: it makes a leaked
// token recognisable to secret scanners and to a human reading a log or a
// screenshot, and it lets us reject obvious nonsense before touching the database.
const TokenPrefix = "meshp_tok_"

// tokenEntropyBytes is 160 bits. The token is a one-time bearer secret with a
// short life, and 160 random bits is far beyond guessable; more would only make it
// harder to type and to fit in a QR code.
const tokenEntropyBytes = 20

// tokenEncoding is lowercase base32 without padding: no case ambiguity, no
// characters that need escaping in a URL or a shell, and readable aloud.
var tokenEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	// ErrTokenMalformed means the string is not shaped like a token at all. It is
	// returned before any lookup, so a nonsense request costs nothing.
	ErrTokenMalformed = errors.New("enroll: token is malformed")

	// ErrTokenUnknown means the token is well formed but no such token exists.
	ErrTokenUnknown = errors.New("enroll: token not recognised")

	// ErrTokenExpired means the token's validity window has passed.
	ErrTokenExpired = errors.New("enroll: token has expired")

	// ErrTokenRevoked means an administrator withdrew it.
	ErrTokenRevoked = errors.New("enroll: token has been revoked")

	// ErrTokenExhausted means the token has already been used as many times as it
	// was allowed. For the default single-use token, this is what a replay hits.
	ErrTokenExhausted = errors.New("enroll: token has already been used")
)

// Token is a freshly minted enrolment token.
type Token struct {
	// Plaintext is shown to the administrator exactly once and never stored.
	Plaintext string
	// Hash is what goes in the database.
	Hash []byte
}

// NewToken mints a token.
func NewToken() (Token, error) {
	raw := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, fmt.Errorf("enroll: generating token: %w", err)
	}
	plaintext := TokenPrefix + tokenEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))
	return Token{Plaintext: plaintext, Hash: sum[:]}, nil
}

// HashToken validates a presented token's shape and returns the hash to look up.
//
// SHA-256 rather than a password hash is deliberate. Argon2 exists to slow down
// guessing of low-entropy, human-chosen secrets; this is 160 bits of randomness,
// where guessing is hopeless regardless of how fast the hash is. What hashing buys
// here is that a database dump — or a backup, or a log line that captured a row —
// does not yield usable tokens. A slow hash would add startup cost to every
// enrolment and buy nothing.
//
// The lookup is by hash against an indexed column, so no secret is ever compared
// byte by byte and there is no comparison for a timing attack to observe.
func HashToken(plaintext string) ([]byte, error) {
	plaintext = strings.TrimSpace(plaintext)
	if !strings.HasPrefix(plaintext, TokenPrefix) {
		return nil, fmt.Errorf("%w: expected it to start with %q", ErrTokenMalformed, TokenPrefix)
	}
	body := plaintext[len(TokenPrefix):]
	raw, err := tokenEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenMalformed, err)
	}
	if len(raw) != tokenEntropyBytes {
		return nil, fmt.Errorf("%w: carries %d bytes, want %d", ErrTokenMalformed, len(raw), tokenEntropyBytes)
	}
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:], nil
}
