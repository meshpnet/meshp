// Package secret mints and recognises bearer tokens.
//
// Two things in this control plane hand somebody a string that is later presented back as
// proof: an enrolment token, which gets a device onto a network, and an API token, which
// gets a machine onto the API. They want identical properties, and having written the first
// one twice would mean maintaining a security primitive in two places — where the copy that
// is not being looked at is the one that goes wrong.
//
// What a token here is: a distinctive prefix, 160 bits of randomness, lowercase base32, and
// only the SHA-256 ever stored.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// entropyBytes is 160 bits. These are bearer secrets, so guessing has to be hopeless; 160
// random bits is far beyond that, and more would only make them harder to type and to fit
// in a QR code.
const entropyBytes = 20

// encoding is lowercase base32 without padding: no case ambiguity, no characters that need
// escaping in a URL or a shell, and readable aloud.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrMalformed means the string is not shaped like a token at all.
//
// Returned before any lookup, so a nonsense request costs nothing. Callers wrap it in
// whatever their own vocabulary is — a device is told its enrolment token is malformed, and
// neither caller wants this package's wording in an API response.
var ErrMalformed = errors.New("secret: token is malformed")

// Token is a freshly minted secret.
type Token struct {
	// Plaintext is shown once and never stored.
	Plaintext string

	// Hash is what goes in the database.
	Hash []byte
}

// New mints a token carrying the given prefix.
//
// The prefix is worth its characters: it makes a leaked token recognisable to a secret
// scanner and to a person reading a log or a screenshot, and it lets a caller reject obvious
// nonsense before touching the database. It also tells two kinds of credential apart when
// both arrive in the same header.
func New(prefix string) (Token, error) {
	raw := make([]byte, entropyBytes)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, fmt.Errorf("secret: generating a token: %w", err)
	}
	plaintext := prefix + encoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))
	return Token{Plaintext: plaintext, Hash: sum[:]}, nil
}

// Hash validates a presented token's shape and returns the hash to look it up by.
//
// SHA-256 rather than a password hash, deliberately. Argon2 exists to slow down guessing of
// low-entropy, human-chosen secrets; this is 160 bits of randomness, where guessing is
// hopeless however fast the hash is. What hashing buys is that a database dump — or a
// backup, or a log line that captured a row — does not yield usable tokens. A slow hash
// would add cost to every request and buy nothing.
//
// The lookup is by hash against an indexed column, so no secret is ever compared byte by
// byte and there is no comparison for a timing attack to observe.
func Hash(prefix, plaintext string) ([]byte, error) {
	plaintext = strings.TrimSpace(plaintext)
	if !strings.HasPrefix(plaintext, prefix) {
		return nil, fmt.Errorf("%w: expected it to start with %q", ErrMalformed, prefix)
	}
	raw, err := encoding.DecodeString(plaintext[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(raw) != entropyBytes {
		return nil, fmt.Errorf("%w: carries %d bytes, want %d", ErrMalformed, len(raw), entropyBytes)
	}
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:], nil
}

// LooksLike reports whether a string claims to be a token with this prefix.
//
// Shape only, and no lookup: it is how a caller holding one Authorization header decides
// which kind of credential it is looking at before spending a query on it.
func LooksLike(prefix, presented string) bool {
	return strings.HasPrefix(strings.TrimSpace(presented), prefix)
}
