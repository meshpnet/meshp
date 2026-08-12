// Package keys generates and encodes the two kinds of key a meshp device holds.
//
// They are deliberately separate (ADR-0006):
//
//   - A device identity is a long-lived Ed25519 keypair. It is what the device
//     authenticates its control-plane session with, by signing a challenge, and it
//     is the device's stable name for its whole life.
//   - A WireGuard keypair is X25519 and rotatable, one per network membership.
//     Reusing one across customer networks would let those networks correlate the
//     device (Invariant 19).
//
// Both private keys are generated on the device and never leave it (Invariant 1).
// Nothing in this package sends a private key anywhere, and nothing in it accepts
// one from the wire.
package keys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// WireGuardKeyLen is the size of a WireGuard key in bytes.
const WireGuardKeyLen = 32

// Identity is a device's long-lived signing keypair.
type Identity struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// NewIdentity generates a device identity.
func NewIdentity() (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("keys: generating identity: %w", err)
	}
	return Identity{Public: pub, Private: priv}, nil
}

// Sign signs a message with the identity key.
func (i Identity) Sign(message []byte) []byte {
	return ed25519.Sign(i.Private, message)
}

// VerifyIdentity checks a signature made by an identity public key. It returns an
// error rather than a bool so a caller cannot accidentally treat the zero value as
// success.
func VerifyIdentity(pub []byte, message, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("keys: identity public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("keys: signature is %d bytes, want %d", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), message, signature) {
		return errors.New("keys: signature does not verify")
	}
	return nil
}

// WireGuardKey is a raw 32-byte WireGuard key, public or private.
type WireGuardKey [WireGuardKeyLen]byte

// WireGuardPair is a WireGuard keypair.
type WireGuardPair struct {
	Public  WireGuardKey
	Private WireGuardKey
}

// NewWireGuardPair generates a WireGuard keypair.
//
// The private key is clamped exactly as `wg genkey` clamps it. X25519 clamps
// internally too, so an unclamped key would still work — but a key that does not
// round-trip byte-for-byte through the reference tooling is the kind of difference
// that surfaces much later as an interoperability problem nobody can reproduce.
//
// crypto/ecdh rather than golang.org/x/crypto/curve25519: the standard library
// covers this now, and dropping the dependency removes a module whose openpgp
// subpackage carries a permanent advisory we would otherwise have to explain to
// every reader of a vulnerability report. Verified against the x/crypto derivation
// over 200 clamped scalars before the swap — identical public keys, and the stored
// scalar unchanged.
func NewWireGuardPair() (WireGuardPair, error) {
	var priv WireGuardKey
	if _, err := rand.Read(priv[:]); err != nil {
		return WireGuardPair{}, fmt.Errorf("keys: generating WireGuard key: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return WireGuardPair{}, fmt.Errorf("keys: deriving WireGuard public key: %w", err)
	}
	var pub WireGuardKey
	copy(pub[:], key.PublicKey().Bytes())
	return WireGuardPair{Public: pub, Private: priv}, nil
}

// String renders a key the way WireGuard does, as standard base64 with padding, so
// it can be pasted straight into a wg config or compared with `wg show` output.
func (k WireGuardKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// ParseWireGuardKey decodes a base64 WireGuard key.
func ParseWireGuardKey(s string) (WireGuardKey, error) {
	var k WireGuardKey
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("keys: WireGuard key is not valid base64: %w", err)
	}
	if len(raw) != WireGuardKeyLen {
		return k, fmt.Errorf("keys: WireGuard key is %d bytes, want %d", len(raw), WireGuardKeyLen)
	}
	copy(k[:], raw)
	return k, nil
}

// IsZero reports whether the key is all zeroes, which is never a real key and is
// what an uninitialised struct looks like.
func (k WireGuardKey) IsZero() bool {
	var zero WireGuardKey
	return k == zero
}
