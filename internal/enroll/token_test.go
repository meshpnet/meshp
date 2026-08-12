package enroll

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestNewToken(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Plaintext, TokenPrefix) {
		t.Errorf("token %q does not carry the prefix", tok.Plaintext)
	}
	if len(tok.Hash) != sha256.Size {
		t.Errorf("hash is %d bytes, want %d", len(tok.Hash), sha256.Size)
	}

	// The hash stored must be the hash of what the administrator was shown, or the
	// token will never be redeemable.
	got, err := HashToken(tok.Plaintext)
	if err != nil {
		t.Fatalf("HashToken on a freshly minted token: %v", err)
	}
	if !bytes.Equal(got, tok.Hash) {
		t.Error("HashToken disagrees with NewToken about the same token")
	}
}

func TestTokensAreDistinctAndTypeable(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		tok, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.Plaintext] {
			t.Fatal("NewToken returned a duplicate")
		}
		seen[tok.Plaintext] = true

		body := strings.TrimPrefix(tok.Plaintext, TokenPrefix)
		// Lowercase base32 with no padding: nothing that needs escaping in a URL or
		// a shell, no case ambiguity when read aloud or retyped.
		if body != strings.ToLower(body) {
			t.Fatalf("token body %q is not lowercase", body)
		}
		if strings.ContainsAny(body, "=+/018") {
			t.Fatalf("token body %q contains an ambiguous or unsafe character", body)
		}
	}
}

func TestHashTokenRejectsMalformedInput(t *testing.T) {
	valid, _ := NewToken()

	tests := []struct{ name, input string }{
		{"empty", ""},
		{"no prefix", strings.TrimPrefix(valid.Plaintext, TokenPrefix)},
		{"wrong prefix", "github_pat_" + strings.TrimPrefix(valid.Plaintext, TokenPrefix)},
		{"prefix only", TokenPrefix},
		{"truncated body", valid.Plaintext[:len(valid.Plaintext)-4]},
		{"extra characters", valid.Plaintext + "aaaa"},
		{"uppercase", strings.ToUpper(valid.Plaintext)},
		{"invalid base32 alphabet", TokenPrefix + strings.Repeat("1", 32)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Rejecting shape before any lookup means a flood of nonsense costs no
			// database work.
			_, err := HashToken(tt.input)
			if !errors.Is(err, ErrTokenMalformed) {
				t.Errorf("HashToken(%q) error = %v, want ErrTokenMalformed", tt.input, err)
			}
		})
	}
}

func TestHashTokenToleratesSurroundingWhitespace(t *testing.T) {
	// Tokens get copied out of terminals and chat windows, which is where the
	// stray newline comes from.
	tok, _ := NewToken()
	want, _ := HashToken(tok.Plaintext)

	for _, padded := range []string{
		" " + tok.Plaintext,
		tok.Plaintext + "\n",
		"\t" + tok.Plaintext + "  \r\n",
	} {
		got, err := HashToken(padded)
		if err != nil {
			t.Errorf("HashToken(%q): %v", padded, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("HashToken(%q) produced a different hash", padded)
		}
	}
}

func TestHashTokenIsDeterministicAndSpecific(t *testing.T) {
	a, _ := NewToken()
	b, _ := NewToken()

	h1, _ := HashToken(a.Plaintext)
	h2, _ := HashToken(a.Plaintext)
	if !bytes.Equal(h1, h2) {
		t.Error("HashToken is not deterministic")
	}
	hb, _ := HashToken(b.Plaintext)
	if bytes.Equal(h1, hb) {
		t.Error("two different tokens hash to the same value")
	}
}

// The stored hash must not be reversible to the token, which is the entire reason
// the plaintext is never persisted.
func TestStoredHashDoesNotContainTheToken(t *testing.T) {
	tok, _ := NewToken()
	if bytes.Contains(tok.Hash, []byte(tok.Plaintext)) {
		t.Fatal("the hash contains the plaintext")
	}
	body := strings.TrimPrefix(tok.Plaintext, TokenPrefix)
	if bytes.Contains(tok.Hash, []byte(body[:8])) {
		t.Fatal("the hash contains a prefix of the token body")
	}
}

func FuzzHashToken(f *testing.F) {
	valid, _ := NewToken()
	f.Add(valid.Plaintext)
	f.Add("")
	f.Add(TokenPrefix)
	f.Add("meshp_tok_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	f.Fuzz(func(t *testing.T, s string) {
		hash, err := HashToken(s)
		if err != nil {
			return
		}
		// Anything accepted must produce a full-length hash and must be stable, or
		// a token could hash differently on two control-plane replicas.
		if len(hash) != sha256.Size {
			t.Fatalf("accepted %q and produced a %d-byte hash", s, len(hash))
		}
		again, err := HashToken(s)
		if err != nil || !bytes.Equal(hash, again) {
			t.Fatalf("HashToken(%q) is not stable", s)
		}
	})
}
