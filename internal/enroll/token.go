// Package enroll turns a one-time token into a device that belongs to a network.
//
// Enrolment is the one moment a machine with no prior relationship to the control
// plane is granted one, so it is deliberately narrow: a token authorises, a
// signature authenticates, and both are checked before a single row is written.
package enroll

import (
	"errors"

	"github.com/meshpnet/meshp/internal/secret"
)

// TokenPrefix marks a meshp enrolment token.
//
// A distinctive, searchable prefix is worth the characters: it makes a leaked
// token recognisable to secret scanners and to a human reading a log or a
// screenshot, and it lets us reject obvious nonsense before touching the database.
const TokenPrefix = "meshp_tok_"

var (
	// ErrTokenMalformed means the string is not shaped like a token at all. It is
	// returned before any lookup, so a nonsense request costs nothing.
	//
	// The same value as secret.ErrMalformed rather than a second sentinel wrapping it.
	// They are one condition, and two sentinels for one condition means every caller has
	// to know which of them a given code path produces — while re-wrapping would double
	// the text of every message ("token is malformed: token is malformed: ...").
	ErrTokenMalformed = secret.ErrMalformed

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
	tok, err := secret.New(TokenPrefix)
	if err != nil {
		return Token{}, err
	}
	return Token{Plaintext: tok.Plaintext, Hash: tok.Hash}, nil
}

// HashToken validates a presented token's shape and returns the hash to look up.
//
// The shape, the entropy and the hashing all live in internal/secret, which the API tokens
// of ADR-0024 §2 use as well — a bearer secret written twice is one whose second copy nobody
// is looking at. What stays here is the vocabulary: a device presenting nonsense is told its
// enrolment token is malformed, in this package's words rather than that one's.
func HashToken(plaintext string) ([]byte, error) {
	return secret.Hash(TokenPrefix, plaintext)
}
