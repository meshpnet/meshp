package secret

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

const testPrefix = "meshp_test_"

// What is stored must be the hash of what the holder was shown, or the token can never be
// presented successfully.
func TestTheHashMatchesWhatWasShown(t *testing.T) {
	tok, err := New(testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Plaintext, testPrefix) {
		t.Errorf("token %q does not carry the prefix", tok.Plaintext)
	}
	if len(tok.Hash) != sha256.Size {
		t.Errorf("hash is %d bytes, want %d", len(tok.Hash), sha256.Size)
	}

	got, err := Hash(testPrefix, tok.Plaintext)
	if err != nil {
		t.Fatalf("hashing a freshly minted token: %v", err)
	}
	if !bytes.Equal(got, tok.Hash) {
		t.Error("Hash disagrees with New about the same token")
	}
}

// Distinct, and typeable. A token gets read aloud, retyped from a screenshot and pasted into
// shells, so the alphabet matters as much as the entropy.
func TestTokensAreDistinctAndTypeable(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		tok, err := New(testPrefix)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.Plaintext] {
			t.Fatal("New returned a duplicate")
		}
		seen[tok.Plaintext] = true

		body := strings.TrimPrefix(tok.Plaintext, testPrefix)
		if body != strings.ToLower(body) {
			t.Fatalf("token body %q is not lowercase", body)
		}
		if strings.ContainsAny(body, "=+/018") {
			t.Fatalf("token body %q contains an ambiguous or unsafe character", body)
		}
	}
}

// A token minted for one purpose does not hash as a token of another.
//
// The prefix is what tells two kinds of credential apart when both arrive in the same
// Authorization header, so it has to be part of what is checked rather than decoration on
// the front. It is also part of what is hashed: two tokens with the same random body and
// different prefixes are different secrets.
func TestAPrefixIsNotDecoration(t *testing.T) {
	tok, err := New("meshp_tok_")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Hash("meshp_api_", tok.Plaintext); !errors.Is(err, ErrMalformed) {
		t.Errorf("hashing an enrolment token as an API token = %v, want ErrMalformed", err)
	}
	if LooksLike("meshp_api_", tok.Plaintext) {
		t.Error("an enrolment token looks like an API token")
	}
	if !LooksLike("meshp_tok_", tok.Plaintext) {
		t.Error("an enrolment token does not look like one")
	}
}

// Nonsense is refused on shape, before any lookup, so an endpoint that is hammered with
// rubbish costs nothing but the parse.
func TestMalformedInputIsRefusedOnShape(t *testing.T) {
	valid, _ := New(testPrefix)

	for _, tc := range []struct {
		name      string
		presented string
	}{
		{"empty", ""},
		{"no prefix", strings.TrimPrefix(valid.Plaintext, testPrefix)},
		{"another prefix", "meshp_other_" + strings.TrimPrefix(valid.Plaintext, testPrefix)},
		{"not base32", testPrefix + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"},
		{"too short", testPrefix + "aaaa"},
		{"too long", valid.Plaintext + "aaaaaaaa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Hash(testPrefix, tc.presented); !errors.Is(err, ErrMalformed) {
				t.Errorf("Hash(%q) = %v, want ErrMalformed", tc.presented, err)
			}
		})
	}
}

// Surrounding whitespace is forgiven, because a token arrives having been copied out of a
// terminal and pasted into one. Nothing else is.
func TestWhitespaceAroundATokenIsForgiven(t *testing.T) {
	tok, _ := New(testPrefix)
	got, err := Hash(testPrefix, "  "+tok.Plaintext+"\n")
	if err != nil {
		t.Fatalf("a pasted token was refused: %v", err)
	}
	if !bytes.Equal(got, tok.Hash) {
		t.Error("trimming changed the hash")
	}
	if !LooksLike(testPrefix, "  "+tok.Plaintext) {
		t.Error("a pasted token does not look like one")
	}
}
