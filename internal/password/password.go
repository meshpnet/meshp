// Package password hashes and verifies the one secret this project stores on a person's
// behalf.
//
// Argon2id, with the parameters encoded into the hash rather than compiled in. That is what
// makes them changeable: a deployment that raises the cost tomorrow can still verify every
// password stored today, and each of those is rehashed at the next successful sign-in
// rather than being invalidated.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// The cost of one hash. OWASP's Argon2id guidance is a family of equivalent points on a
// memory-versus-time curve rather than one answer; this is the memory-heavy end, which is
// the side that costs an attacker with parallel hardware the most.
//
// Encoded into every hash, so changing these does not invalidate anything already stored.
const (
	defaultMemoryKiB = 64 * 1024 // 64 MiB
	defaultTime      = 2
	defaultThreads   = 1
	keyLength        = 32
	saltLength       = 16
)

// ErrMismatch means the password is wrong.
//
// Deliberately not distinguishable by the caller from a stored hash that will not parse:
// both mean "do not sign this person in", and a caller that could tell them apart would
// eventually report which.
var ErrMismatch = errors.New("password: does not match")

// Hash returns an encoded Argon2id hash in the standard PHC string format.
//
// The format is the reason to use it rather than a bare digest: it carries the algorithm,
// its version and its parameters, so a stored hash stays verifiable after the cost is
// retuned, and a future maintainer can read what a row actually is.
func Hash(plain string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: reading randomness: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, defaultTime, defaultMemoryKiB, defaultThreads, keyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, defaultMemoryKiB, defaultTime, defaultThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether plain produced encoded.
//
// Constant time over the digest, for the usual reason. What it cannot hide is the work: a
// stored hash takes longer to check than a malformed one, so a caller must not let "how long
// did this take" become a signal — which is why an unknown email is still made to do the
// work at the call site.
func Verify(encoded, plain string) error {
	memory, time, threads, salt, want, err := parse(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(plain), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// NeedsRehash reports whether a stored hash was made with weaker parameters than are
// current, so a successful sign-in can quietly upgrade it.
func NeedsRehash(encoded string) bool {
	memory, time, threads, _, _, err := parse(encoded)
	if err != nil {
		// Unreadable counts as needing one. Whatever it is, it is not what this produces.
		return true
	}
	return memory != defaultMemoryKiB || time != defaultTime || threads != defaultThreads
}

func parse(encoded string) (memory, time uint32, threads uint8, salt, key []byte, err error) {
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, key
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, ErrMismatch
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		// A hash from another version of the algorithm is not one this build can check.
		// Refused rather than guessed at.
		return 0, 0, 0, nil, nil, ErrMismatch
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return 0, 0, 0, nil, nil, ErrMismatch
	}

	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, ErrMismatch
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, ErrMismatch
	}
	if len(salt) == 0 || len(key) == 0 {
		return 0, 0, 0, nil, nil, ErrMismatch
	}
	return memory, time, threads, salt, key, nil
}
