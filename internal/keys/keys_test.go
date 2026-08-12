package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestIdentitySignAndVerify(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("challenge bytes")
	sig := id.Sign(msg)

	if err := VerifyIdentity(id.Public, msg, sig); err != nil {
		t.Errorf("VerifyIdentity on a good signature: %v", err)
	}

	// The three ways this must fail, since enrolment's proof of possession rests
	// entirely on it.
	if err := VerifyIdentity(id.Public, []byte("different message"), sig); err == nil {
		t.Error("a signature verified against the wrong message")
	}
	other, _ := NewIdentity()
	if err := VerifyIdentity(other.Public, msg, sig); err == nil {
		t.Error("a signature verified against the wrong public key")
	}
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if err := VerifyIdentity(id.Public, msg, tampered); err == nil {
		t.Error("a tampered signature verified")
	}
}

func TestVerifyIdentityRejectsMalformedInput(t *testing.T) {
	id, _ := NewIdentity()
	msg := []byte("m")
	sig := id.Sign(msg)

	tests := []struct {
		name string
		pub  []byte
		sig  []byte
	}{
		{"empty public key", nil, sig},
		{"short public key", id.Public[:16], sig},
		{"long public key", append(append([]byte(nil), id.Public...), 0), sig},
		{"empty signature", id.Public, nil},
		{"short signature", id.Public, sig[:32]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// ed25519.Verify panics on a wrong-sized public key, so these have to be
			// rejected before reaching it. A panic in an enrolment handler is a
			// remote crash triggered by anyone who can reach the endpoint.
			if err := VerifyIdentity(tt.pub, msg, tt.sig); err == nil {
				t.Error("accepted malformed input")
			}
		})
	}
}

func TestIdentityKeysAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		id, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		k := string(id.Public)
		if seen[k] {
			t.Fatal("NewIdentity returned a duplicate key")
		}
		seen[k] = true
		if len(id.Public) != ed25519.PublicKeySize {
			t.Fatalf("public key is %d bytes", len(id.Public))
		}
	}
}

func TestWireGuardPair(t *testing.T) {
	pair, err := NewWireGuardPair()
	if err != nil {
		t.Fatal(err)
	}
	if pair.Private.IsZero() || pair.Public.IsZero() {
		t.Fatal("generated a zero key")
	}
	if pair.Private == pair.Public {
		t.Fatal("public and private key are identical")
	}

	// Clamped exactly as `wg genkey` clamps, so keys round-trip through the
	// reference tooling byte for byte.
	if pair.Private[0]&7 != 0 {
		t.Errorf("private[0] = %#x: low three bits must be clear", pair.Private[0])
	}
	if pair.Private[31]&128 != 0 {
		t.Errorf("private[31] = %#x: high bit must be clear", pair.Private[31])
	}
	if pair.Private[31]&64 == 0 {
		t.Errorf("private[31] = %#x: second-highest bit must be set", pair.Private[31])
	}
}

func TestWireGuardKeyEncoding(t *testing.T) {
	pair, err := NewWireGuardPair()
	if err != nil {
		t.Fatal(err)
	}

	// Standard base64 with padding, so a key can be pasted into a wg config or
	// compared against `wg show` output without reformatting.
	encoded := pair.Public.String()
	if len(encoded) != 44 || !strings.HasSuffix(encoded, "=") {
		t.Errorf("encoded key = %q, want 44 chars of padded base64", encoded)
	}
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		t.Errorf("not valid standard base64: %v", err)
	}

	back, err := ParseWireGuardKey(encoded)
	if err != nil {
		t.Fatalf("ParseWireGuardKey: %v", err)
	}
	if back != pair.Public {
		t.Error("key did not survive a round trip")
	}
}

func TestParseWireGuardKeyRejectsMalformedInput(t *testing.T) {
	tests := []struct{ name, input string }{
		{"empty", ""},
		{"not base64", "!!!!not base64!!!!"},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 64))},
		{"base64url instead of standard", strings.ReplaceAll(base64.StdEncoding.EncodeToString(make([]byte, 32)), "=", "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseWireGuardKey(tt.input); err == nil {
				t.Errorf("accepted %q", tt.input)
			}
		})
	}
}

func TestWireGuardKeysAreDistinct(t *testing.T) {
	seen := map[WireGuardKey]bool{}
	for range 50 {
		pair, err := NewWireGuardPair()
		if err != nil {
			t.Fatal(err)
		}
		if seen[pair.Private] {
			t.Fatal("NewWireGuardPair returned a duplicate private key")
		}
		seen[pair.Private] = true
	}
}

func FuzzParseWireGuardKey(f *testing.F) {
	f.Add("")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	f.Add("not base64 at all")

	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParseWireGuardKey(s)
		if err != nil {
			return
		}
		// Anything accepted must round-trip, or two parts of the system will
		// disagree about the same key.
		if got := k.String(); got != s {
			t.Fatalf("accepted %q but re-encodes as %q", s, got)
		}
	})
}

func FuzzVerifyIdentityDoesNotPanic(f *testing.F) {
	id, _ := NewIdentity()
	f.Add([]byte(id.Public), []byte("msg"), id.Sign([]byte("msg")))
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, pub, msg, sig []byte) {
		// The only requirement is that it never panics: this is reachable by
		// anyone who can post to the enrolment endpoint.
		_ = VerifyIdentity(pub, msg, sig)
	})
}
