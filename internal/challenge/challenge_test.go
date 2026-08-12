package challenge

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
	c, err := New([]byte("a-master-secret-of-adequate-length"), "test purpose v1", DefaultTTL, clk)
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
	if len(ch.Bytes) != Len {
		t.Fatalf("challenge is %d bytes, want %d", len(ch.Bytes), Len)
	}
	if err := c.Verify(ch.Bytes, tokenHash, id.Public); err != nil {
		t.Errorf("Verify on a fresh challenge: %v", err)
	}

	// It survives the wire.
	parsed, err := Parse(ch.Encoded())
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

	if err := c.Verify(ch.Bytes, []byte("a-different-token"), id.Public); !errors.Is(err, ErrInvalid) {
		t.Errorf("with a different token: got %v, want ErrInvalid", err)
	}
	if err := c.Verify(ch.Bytes, tokenHash, other.Public); !errors.Is(err, ErrInvalid) {
		t.Errorf("with a different key: got %v, want ErrInvalid", err)
	}
}

func TestChallengeRejectsTampering(t *testing.T) {
	c, _ := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()
	ch, _ := c.Issue(tokenHash, id.Public)

	// Every byte matters: nonce, expiry and tag alike.
	for _, pos := range []int{0, nonceLen - 1, nonceLen, Len - 1} {
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
		forged[nonceLen+7-i] = byte(far >> (8 * i))
	}

	clk.Advance(DefaultTTL * 2)
	if err := c.Verify(forged, tokenHash, id.Public); !errors.Is(err, ErrInvalid) {
		t.Errorf("a rewritten expiry was accepted: %v", err)
	}
}

func TestChallengeExpires(t *testing.T) {
	c, clk := newTestChallenger(t)
	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()
	ch, _ := c.Issue(tokenHash, id.Public)

	clk.Advance(DefaultTTL - time.Second)
	if err := c.Verify(ch.Bytes, tokenHash, id.Public); err != nil {
		t.Errorf("one second before expiry: %v", err)
	}

	clk.Advance(2 * time.Second)
	if err := c.Verify(ch.Bytes, tokenHash, id.Public); !errors.Is(err, ErrExpired) {
		t.Errorf("after expiry: got %v, want ErrExpired", err)
	}
}

// A challenge from one deployment must not verify against another, which is what
// makes it safe for the secret to be the only thing separating them.
func TestChallengeIsSpecificToTheDeploymentSecret(t *testing.T) {
	clk := clock.NewFake()
	a, err := New([]byte("first-secret-of-adequate-length"), "test purpose v1", DefaultTTL, clk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([]byte("second-secret-of-adequate-length"), "test purpose v1", DefaultTTL, clk)
	if err != nil {
		t.Fatal(err)
	}

	tokenHash := []byte("token-hash")
	id, _ := keys.NewIdentity()
	ch, _ := a.Issue(tokenHash, id.Public)

	if err := b.Verify(ch.Bytes, tokenHash, id.Public); !errors.Is(err, ErrInvalid) {
		t.Errorf("a challenge from one deployment verified against another: %v", err)
	}
}

func TestNewChallengerRejectsAWeakSecret(t *testing.T) {
	// A deployment that forgot to set MESHP_SECRET_KEY must fail at startup rather
	// than issue forgeable challenges.
	for _, secret := range []string{"", "short", "fifteen-chars-x"} {
		if _, err := New([]byte(secret), "test purpose v1", 0, clock.NewFake()); err == nil {
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
	for _, n := range []int{0, 1, Len - 1, Len + 1, 1000} {
		if err := c.Verify(make([]byte, n), []byte("t"), []byte("k")); !errors.Is(err, ErrInvalid) {
			t.Errorf("a %d-byte challenge: got %v, want ErrInvalid", n, err)
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
	c, _ := New([]byte("a-master-secret-of-adequate-length"), "test purpose v1", DefaultTTL, clock.NewFake())
	id, _ := keys.NewIdentity()
	ch, _ := c.Issue([]byte("t"), id.Public)
	f.Add(ch.Bytes, []byte("t"), []byte(id.Public))
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, challenge, tokenHash, pub []byte) {
		// Unauthenticated input from the network. It must never panic, and it must
		// never accept something we did not issue.
		if err := c.Verify(challenge, tokenHash, pub); err == nil {
			if len(challenge) != Len {
				t.Fatalf("accepted a %d-byte challenge", len(challenge))
			}
		}
	})
}

// The reason purpose is a parameter and not a constant. Two challengers derived from
// the same master secret must not verify each other's challenges: a session challenge
// that passed during enrolment, or an enrolment challenge that opened a session, would
// be a way to turn one credential into another.
func TestPurposeSeparation(t *testing.T) {
	secret := []byte("one-master-secret-for-both-uses")
	clk := clock.NewFake()

	enrolment, err := New(secret, "meshp enrolment challenge v1", DefaultTTL, clk)
	if err != nil {
		t.Fatal(err)
	}
	session, err := New(secret, "meshp session challenge v1", DefaultTTL, clk)
	if err != nil {
		t.Fatal(err)
	}

	binding := []byte("the same bindings in both cases")

	fromEnrolment, err := enrolment.Issue(binding)
	if err != nil {
		t.Fatal(err)
	}
	fromSession, err := session.Issue(binding)
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Verify(fromEnrolment.Bytes, binding); !errors.Is(err, ErrInvalid) {
		t.Errorf("an enrolment challenge verified as a session: %v", err)
	}
	if err := enrolment.Verify(fromSession.Bytes, binding); !errors.Is(err, ErrInvalid) {
		t.Errorf("a session challenge verified as an enrolment: %v", err)
	}

	// Each still verifies its own, so the separation is not simply breaking both.
	if err := enrolment.Verify(fromEnrolment.Bytes, binding); err != nil {
		t.Errorf("enrolment challenge failed its own verification: %v", err)
	}
	if err := session.Verify(fromSession.Bytes, binding); err != nil {
		t.Errorf("session challenge failed its own verification: %v", err)
	}
}

func TestNewRejectsAnEmptyPurpose(t *testing.T) {
	// Without a purpose there is no separation, so this is a programming mistake worth
	// failing on rather than defaulting past.
	if _, err := New([]byte("a-master-secret-of-adequate-length"), "", DefaultTTL, clock.NewFake()); err == nil {
		t.Error("New accepted an empty purpose")
	}
}

// Bindings are length-prefixed and counted, so no two different tuples can produce the
// same authenticated byte stream.
func TestBindingsAreUnambiguous(t *testing.T) {
	c, _ := New([]byte("a-master-secret-of-adequate-length"), "test purpose v1", DefaultTTL, clock.NewFake())

	ch, err := c.Issue([]byte("ab"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	// The concatenation is identical; the tuple is not.
	if err := c.Verify(ch.Bytes, []byte("a"), []byte("bc")); !errors.Is(err, ErrInvalid) {
		t.Errorf("(\"ab\",\"c\") verified against (\"a\",\"bc\"): %v", err)
	}
	// Nor may a different arity pass.
	if err := c.Verify(ch.Bytes, []byte("abc")); !errors.Is(err, ErrInvalid) {
		t.Errorf("two bindings verified against one: %v", err)
	}
	// Nor a different order.
	if err := c.Verify(ch.Bytes, []byte("c"), []byte("ab")); !errors.Is(err, ErrInvalid) {
		t.Errorf("bindings verified in the wrong order: %v", err)
	}
}

func TestIssueRejectsEmptyBindings(t *testing.T) {
	c, _ := New([]byte("a-master-secret-of-adequate-length"), "test purpose v1", DefaultTTL, clock.NewFake())
	if _, err := c.Issue(); err == nil {
		t.Error("Issue accepted no bindings, which would make the challenge unbound")
	}
	if _, err := c.Issue([]byte("ok"), nil); err == nil {
		t.Error("Issue accepted an empty binding")
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	c, _ := New([]byte("a-master-secret-of-adequate-length"), "test purpose v1", DefaultTTL, clock.NewFake())
	ch, err := c.Issue([]byte("binding"))
	if err != nil {
		t.Fatal(err)
	}

	// The wire form is attacker-controlled, so every rejection path matters.
	tests := []struct{ name, input string }{
		{"empty", ""},
		{"not base64", "!!! not base64 !!!"},
		{"base64 but too short", "AAAA"},
		{"base64 but too long", ch.Encoded() + "AAAA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.input); !errors.Is(err, ErrInvalid) {
				t.Errorf("Parse(%q) error = %v, want ErrInvalid", tt.input, err)
			}
		})
	}

	// And the good case still round-trips.
	back, err := Parse(ch.Encoded())
	if err != nil {
		t.Fatalf("Parse on a valid challenge: %v", err)
	}
	if err := c.Verify(back, []byte("binding")); err != nil {
		t.Errorf("a parsed challenge failed verification: %v", err)
	}
}

func TestNewDefaultsAndValidation(t *testing.T) {
	secret := []byte("a-master-secret-of-adequate-length")

	// A zero or negative TTL falls back to the default rather than issuing challenges
	// that are already expired.
	c, err := New(secret, "test purpose v1", 0, clock.NewFake())
	if err != nil {
		t.Fatal(err)
	}
	ch, err := c.Issue([]byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ch.Bytes, []byte("b")); err != nil {
		t.Errorf("a challenge issued with a defaulted TTL did not verify: %v", err)
	}

	// A nil clock means the real one, so a caller that forgets gets correct behaviour
	// rather than a panic.
	if _, err := New(secret, "test purpose v1", DefaultTTL, nil); err != nil {
		t.Errorf("New with a nil clock: %v", err)
	}
}
