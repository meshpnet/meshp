package relaytoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/relayproto"
)

func pair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func key(b byte) relayproto.Key {
	var k relayproto.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func network(b byte) [networkIDLen]byte {
	var n [networkIDLen]byte
	for i := range n {
		n[i] = b
	}
	return n
}

var now = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func TestATokenGrantsWhatItWasIssuedFor(t *testing.T) {
	pub, priv := pair(t)
	tok, err := Issue(priv, key(7), network(3), now.Add(DefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != Size {
		t.Errorf("token is %d bytes, want %d", len(tok), Size)
	}

	grant, err := Verify(pub, tok, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if grant.Key != key(7) {
		t.Error("the granted key is not the one issued")
	}
	if grant.NetworkID != network(3) {
		t.Error("the granted network is not the one issued")
	}
	if !grant.ExpiresAt.Equal(now.Add(DefaultTTL)) {
		t.Errorf("expiry is %s, want %s", grant.ExpiresAt, now.Add(DefaultTTL))
	}
	if got := grant.Network(); len(got) != 36 {
		t.Errorf("network renders as %q, want a UUID", got)
	}
}

// The whole point of signing rather than sharing a secret: a relay holds only the public key,
// so a compromised relay cannot mint access to a network it was never given (ADR-0016).
func TestAPublicKeyCannotIssue(t *testing.T) {
	pub, _ := pair(t)
	if _, err := Issue(ed25519.PrivateKey(pub), key(1), network(1), now.Add(time.Hour)); err == nil {
		t.Error("a public key was accepted as a signing key")
	}
}

func TestATokenFromAnotherIssuerIsRefused(t *testing.T) {
	_, mine := pair(t)
	theirs, _ := pair(t)

	tok, err := Issue(mine, key(1), network(1), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(theirs, tok, now); !errors.Is(err, ErrSignature) {
		t.Errorf("verified against the wrong public key with %v, want ErrSignature", err)
	}
}

// Every single-bit change must be caught, or the signature is decoration. Sweeping every byte
// of the signed region and the signature itself is cheap and complete.
func TestEveryByteIsCoveredByTheSignature(t *testing.T) {
	pub, priv := pair(t)
	tok, err := Issue(priv, key(1), network(1), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	for i := range tok {
		tampered := make([]byte, len(tok))
		copy(tampered, tok)
		tampered[i] ^= 0x01

		_, err := Verify(pub, tampered, now)
		if err == nil {
			t.Errorf("flipping a bit in byte %d was accepted", i)
			continue
		}
		// A flip in the version byte is caught by the version check first, which is the
		// better error for the operator anyway.
		if i == 0 {
			if !errors.Is(err, ErrVersion) && !errors.Is(err, ErrSignature) {
				t.Errorf("byte %d gave %v, want a version or signature error", i, err)
			}
			continue
		}
		if !errors.Is(err, ErrSignature) {
			t.Errorf("byte %d gave %v, want ErrSignature", i, err)
		}
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	pub, priv := pair(t)
	tok, err := Issue(priv, key(1), network(1), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(pub, tok, now.Add(30*time.Second)); err != nil {
		t.Errorf("a token inside its lifetime was refused: %v", err)
	}
	if _, err := Verify(pub, tok, now.Add(2*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Errorf("an expired token gave %v, want ErrExpired", err)
	}
	// Exactly at the expiry is still valid — the boundary has to be somewhere, and refusing
	// on the same second a token was minted for would make short TTLs unusable.
	if _, err := Verify(pub, tok, now.Add(time.Minute)); err != nil {
		t.Errorf("a token exactly at its expiry was refused: %v", err)
	}
}

// A forgery must not learn that it parsed. The signature is checked before the expiry so an
// attacker cannot use "expired" as confirmation that everything else was right.
func TestAForgeryIsNotToldItExpired(t *testing.T) {
	pub, _ := pair(t)

	forged := make([]byte, Size)
	forged[0] = Version
	// An expiry far in the past, so an implementation checking expiry first would say so.
	for i := range forged[signedLen-expiryLen : signedLen] {
		forged[signedLen-expiryLen+i] = 0
	}

	_, err := Verify(pub, forged, now)
	if errors.Is(err, ErrExpired) {
		t.Error("a forgery was told it expired, which confirms the rest of it parsed")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("got %v, want ErrSignature", err)
	}
}

func TestMalformedTokensAreRefused(t *testing.T) {
	pub, priv := pair(t)
	good, err := Issue(priv, key(1), network(1), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":        {},
		"one byte":     {Version},
		"a byte short": good[:len(good)-1],
		"a byte long":  append(append([]byte{}, good...), 0),
		"all zeroes":   make([]byte, Size),
	}
	for name, tok := range cases {
		if _, err := Verify(pub, tok, now); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A newer control plane must produce a clear complaint from an older relay, not a confusing
// signature failure that sends someone hunting for a key mismatch.
func TestAFutureVersionSaysSo(t *testing.T) {
	pub, priv := pair(t)
	tok, err := Issue(priv, key(1), network(1), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	tok[0] = Version + 1

	_, err = Verify(pub, tok, now)
	if !errors.Is(err, ErrVersion) {
		t.Errorf("a future version gave %v, want ErrVersion", err)
	}
}

func TestATokenWithoutAnExpiryIsRefused(t *testing.T) {
	_, priv := pair(t)
	if _, err := Issue(priv, key(1), network(1), time.Time{}); err == nil {
		t.Error("a token with no expiry was issued, which is a permanent credential")
	}
}

func TestTheTextFormRoundTrips(t *testing.T) {
	pub, priv := pair(t)
	tok, err := Issue(priv, key(9), network(9), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	back, err := Decode(Encode(tok))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub, back, now); err != nil {
		t.Errorf("a token did not survive the text form: %v", err)
	}
	if _, err := Decode("not base64 !!!"); !errors.Is(err, ErrMalformed) {
		t.Error("garbage decoded")
	}
}

// Verify faces whatever a relay is sent, so it must not panic on any input — and must never
// accept anything that was not signed by the key it was given.
func FuzzVerify(f *testing.F) {
	pub, priv := pair(&testing.T{})
	good, _ := Issue(priv, key(1), network(1), now.Add(time.Hour))

	f.Add([]byte{})
	f.Add(make([]byte, Size))
	f.Add(good)
	tampered := append([]byte{}, good...)
	tampered[10] ^= 0xFF
	f.Add(tampered)

	f.Fuzz(func(t *testing.T, data []byte) {
		grant, err := Verify(pub, data, now)
		if err != nil {
			return
		}
		// Anything accepted must be exactly a token this issuer would have produced, and
		// re-issuing its contents must reproduce it byte for byte. A verifier that accepts
		// something it could not have written is a forgery it did not notice.
		again, issueErr := Issue(priv, grant.Key, grant.NetworkID, grant.ExpiresAt)
		if issueErr != nil {
			t.Fatalf("a verified grant could not be reissued: %v", issueErr)
		}
		if string(again) != string(data) {
			t.Fatalf("Verify accepted a token this issuer would not produce:\n got %x\nwant %x",
				data, again)
		}
	})
}
