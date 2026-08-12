package enroll

import (
	"errors"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/keys"
)

func newTestChallenger(t *testing.T) (*Challenger, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake()
	c, err := NewChallenger([]byte("a-master-secret-of-adequate-length"), DefaultChallengeTTL, clk)
	if err != nil {
		t.Fatal(err)
	}
	return c, clk
}

func TestChallengeRoundTrip(t *testing.T) {
	c, _ := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()

	ch, err := c.Issue(tokenHash, id.Public)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Bytes) != challengeLen {
		t.Fatalf("challenge is %d bytes, want %d", len(ch.Bytes), challengeLen)
	}
	if err := c.Verify(ch.Bytes, tokenHash, id.Public); err != nil {
		t.Errorf("Verify on a fresh challenge: %v", err)
	}

	// It survives the wire.
	parsed, err := ParseChallenge(ch.Encoded())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(parsed, tokenHash, id.Public); err != nil {
		t.Errorf("Verify after a base64 round trip: %v", err)
	}
}

// The binding is the point. A challenge issued for one enrolment must be useless
// for another, or an attacker could collect a challenge and spend it elsewhere.
func TestChallengeIsBoundToItsTokenAndKey(t *testing.T) {
	c, _ := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()
	other, _ := keys.NewIdentity()

	ch, err := c.Issue(tokenHash, id.Public)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Verify(ch.Bytes, []byte("a-different-token"), id.Public); !errors.Is(err, ErrChallengeInvalid) {
		t.Errorf("with a different token: got %v, want ErrChallengeInvalid", err)
	}
	if err := c.Verify(ch.Bytes, tokenHash, other.Public); !errors.Is(err, ErrChallengeInvalid) {
		t.Errorf("with a different key: got %v, want ErrChallengeInvalid", err)
	}
}

func TestChallengeRejectsTampering(t *testing.T) {
	c, _ := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()
	ch, _ := c.Issue(tokenHash, id.Public)

	// Every byte matters: nonce, expiry and tag alike.
	for _, pos := range []int{0, challengeNonceLen - 1, challengeNonceLen, challengeLen - 1} {
		tampered := append([]byte(nil), ch.Bytes...)
		tampered[pos] ^= 0xff
		if err := c.Verify(tampered, tokenHash, id.Public); err == nil {
			t.Errorf("flipping byte %d still verified", pos)
		}
	}
}

// Extending the expiry must not work. The expiry lives inside the authenticated
// blob precisely so a client cannot choose its own.
func TestChallengeExpiryCannotBeExtendedByTheClient(t *testing.T) {
	c, clk := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()
	ch, _ := c.Issue(tokenHash, id.Public)

	forged := append([]byte(nil), ch.Bytes...)
	// Rewrite the expiry to a century from now.
	far := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	for i := range 8 {
		forged[challengeNonceLen+7-i] = byte(far >> (8 * i))
	}

	clk.Advance(DefaultChallengeTTL * 2)
	if err := c.Verify(forged, tokenHash, id.Public); !errors.Is(err, ErrChallengeInvalid) {
		t.Errorf("a rewritten expiry was accepted: %v", err)
	}
}

func TestChallengeExpires(t *testing.T) {
	c, clk := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()
	ch, _ := c.Issue(tokenHash, id.Public)

	clk.Advance(DefaultChallengeTTL - time.Second)
	if err := c.Verify(ch.Bytes, tokenHash, id.Public); err != nil {
		t.Errorf("one second before expiry: %v", err)
	}

	clk.Advance(2 * time.Second)
	if err := c.Verify(ch.Bytes, tokenHash, id.Public); !errors.Is(err, ErrChallengeExpired) {
		t.Errorf("after expiry: got %v, want ErrChallengeExpired", err)
	}
}

// A challenge from one deployment must not verify against another, which is what
// makes it safe for the secret to be the only thing separating them.
func TestChallengeIsSpecificToTheDeploymentSecret(t *testing.T) {
	clk := clock.NewFake()
	a, err := NewChallenger([]byte("first-secret-of-adequate-length"), DefaultChallengeTTL, clk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewChallenger([]byte("second-secret-of-adequate-length"), DefaultChallengeTTL, clk)
	if err != nil {
		t.Fatal(err)
	}

	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()
	ch, _ := a.Issue(tokenHash, id.Public)

	if err := b.Verify(ch.Bytes, tokenHash, id.Public); !errors.Is(err, ErrChallengeInvalid) {
		t.Errorf("a challenge from one deployment verified against another: %v", err)
	}
}

func TestNewChallengerRejectsAWeakSecret(t *testing.T) {
	// A deployment that forgot to set MESHP_SECRET_KEY must fail at startup rather
	// than issue forgeable challenges.
	for _, secret := range []string{"", "short", "fifteen-chars-x"} {
		if _, err := NewChallenger([]byte(secret), 0, clock.NewFake()); err == nil {
			t.Errorf("accepted a %d-byte secret", len(secret))
		}
	}
}

func TestChallengesAreUnique(t *testing.T) {
	c, _ := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()

	seen := map[string]bool{}
	for range 200 {
		ch, err := c.Issue(tokenHash, id.Public)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(ch.Bytes)] {
			t.Fatal("Issue returned a duplicate challenge")
		}
		seen[string(ch.Bytes)] = true
	}
}

func TestVerifyRejectsWrongLength(t *testing.T) {
	c, _ := newTestChallenger(t)
	for _, n := range []int{0, 1, challengeLen - 1, challengeLen + 1, 1000} {
		if err := c.Verify(make([]byte, n), []byte("t"), []byte("k")); !errors.Is(err, ErrChallengeInvalid) {
			t.Errorf("a %d-byte challenge: got %v, want ErrChallengeInvalid", n, err)
		}
	}
}

// The signed message is what the device actually signs, so it has to be exactly
// the bytes the server verifies against.
func TestSignedChallengeVerifiesEndToEnd(t *testing.T) {
	c, _ := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()

	ch, _ := c.Issue(tokenHash, id.Public)
	sig := id.Sign(ch.Bytes)

	if err := c.Verify(ch.Bytes, tokenHash, id.Public); err != nil {
		t.Fatalf("server-side challenge check: %v", err)
	}
	if err := keys.VerifyIdentity(id.Public, ch.Bytes, sig); err != nil {
		t.Fatalf("proof of possession: %v", err)
	}
}

func FuzzVerifyChallenge(f *testing.F) {
	c, _ := NewChallenger([]byte("a-master-secret-of-adequate-length"), DefaultChallengeTTL, clock.NewFake())
	id, _ := keys.NewIdentity()
	ch, _ := c.Issue([]byte("t"), id.Public)
	f.Add(ch.Bytes, []byte("t"), []byte(id.Public))
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, challenge, tokenHash, pub []byte) {
		// Unauthenticated input from the network. It must never panic, and it must
		// never accept something we did not issue.
		if err := c.Verify(challenge, tokenHash, pub); err == nil {
			if len(challenge) != challengeLen {
				t.Fatalf("accepted a %d-byte challenge", len(challenge))
			}
		}
	})
}
