package password

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestAPasswordVerifiesAgainstItsOwnHash(t *testing.T) {
	encoded, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(encoded, "correct horse battery staple"); err != nil {
		t.Errorf("the right password did not verify: %v", err)
	}
	if err := Verify(encoded, "correct horse battery stapler"); !errors.Is(err, ErrMismatch) {
		t.Errorf("a wrong password gave %v, want ErrMismatch", err)
	}
}

// Two hashes of the same password differ, because each carries its own salt. Without that,
// a stolen database tells an attacker which accounts share a password.
func TestTheSamePasswordHashesDifferentlyEachTime(t *testing.T) {
	first, _ := Hash("hunter2")
	second, _ := Hash("hunter2")
	if first == second {
		t.Error("two hashes of one password are identical, so the salt is not doing anything")
	}
}

// The parameters travel with the hash. That is what lets a deployment raise the cost without
// invalidating every password already stored.
func TestTheHashCarriesItsParameters(t *testing.T) {
	encoded, _ := Hash("hunter2")
	for _, want := range []string{"$argon2id$", "m=65536", "t=2", "p=1"} {
		if !strings.Contains(encoded, want) {
			t.Errorf("hash %q does not carry %q", encoded, want)
		}
	}
	if NeedsRehash(encoded) {
		t.Error("a hash made with the current parameters wants rehashing")
	}
}

// Anything that is not one of ours is refused rather than interpreted, and refused as a
// mismatch: a caller must not be able to tell "wrong password" from "corrupt row", because
// a caller that can will eventually say which.
func TestAnythingElseIsAMismatchAndWantsRehashing(t *testing.T) {
	for _, encoded := range []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=2,p=1$c2FsdA$a2V5",  // a different algorithm
		"$argon2id$v=16$m=65536,t=2,p=1$c2FsdA$a2V5", // a different version
		"$argon2id$v=19$m=x,t=2,p=1$c2FsdA$a2V5",     // unreadable parameters
		"$argon2id$v=19$m=65536,t=2,p=1$$a2V5",       // no salt
		"$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$",     // no key
	} {
		if err := Verify(encoded, "hunter2"); !errors.Is(err, ErrMismatch) {
			t.Errorf("Verify(%q) = %v, want ErrMismatch", encoded, err)
		}
		if !NeedsRehash(encoded) {
			t.Errorf("NeedsRehash(%q) = false, want true", encoded)
		}
	}
}

// A hash made when the cost was lower still verifies, and says it wants upgrading. Without
// both halves, retuning the parameters would either lock everybody out or never take effect.
func TestAWeakerHashStillVerifiesAndWantsUpgrading(t *testing.T) {
	// What Hash would have produced with cheaper settings, built here so the test does not
	// depend on the constants staying where they are.
	weak := "$argon2id$v=19$m=8192,t=1,p=1$" + saltOf(t) + "$" + keyOf(t, "hunter2", 8192, 1, 1)
	if err := Verify(weak, "hunter2"); err != nil {
		t.Fatalf("a hash with older parameters did not verify: %v", err)
	}
	if !NeedsRehash(weak) {
		t.Error("a hash with older parameters does not want upgrading")
	}
}

// saltOf and keyOf build a hash at chosen parameters, so the test above describes an older
// deployment rather than whatever the constants happen to be today.
func saltOf(t *testing.T) string {
	t.Helper()
	return base64.RawStdEncoding.EncodeToString([]byte("sixteen-byte-slt"))
}

func keyOf(t *testing.T, plain string, memory, time uint32, threads uint8) string {
	t.Helper()
	key := argon2.IDKey([]byte(plain), []byte("sixteen-byte-slt"), time, memory, threads, keyLength)
	return base64.RawStdEncoding.EncodeToString(key)
}
