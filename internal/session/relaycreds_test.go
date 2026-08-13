package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/relayproto"
	"github.com/meshpnet/meshp/internal/relaytoken"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// withRelayIssuer gives the fixture's server a signing key, as a deployment that has
// configured relaying would have.
func (f *fixture) withRelayIssuer(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewRelayIssuer(priv, relaytoken.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.relay = issuer
	return pub
}

// askForToken drives the handler as the read loop would and returns what the agent receives.
func (f *fixture) askForToken(t *testing.T, membershipID uuid.UUID) *meshpv1.RelayToken {
	t.Helper()
	sess := newSession("test", membershipID, f.netID, uuid.New(), f.clk.Now())
	f.srv.handleRelayTokenRequest(f.ctx, sess)

	select {
	case msg := <-sess.send:
		token := msg.GetRelayToken()
		if token == nil {
			t.Fatalf("the server sent %T, want a relay token", msg.Payload)
		}
		return token
	default:
		t.Fatal("the server sent nothing at all, which an agent would wait on forever")
		return nil
	}
}

func TestARelayTokenNamesTheDevicesOwnKeyAndNetwork(t *testing.T) {
	f := newFixture(t)
	pub := f.withRelayIssuer(t)
	alice := f.enrolDevice("alice")

	msg := f.askForToken(t, alice.membershipID)
	if msg.GetError() != "" {
		t.Fatalf("refused: %s", msg.GetError())
	}

	grant, err := relaytoken.Verify(pub, msg.GetToken(), f.clk.Now())
	if err != nil {
		t.Fatalf("the issued token does not verify against the deployment's key: %v", err)
	}

	// The key comes from the session's membership, never from the request, so a device can
	// only be issued a token for the key it authenticated as.
	stored, err := f.store.Queries().GetWireGuardKeyForMembership(f.ctx, alice.membershipID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := relayKeyOf(stored)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Key != want {
		t.Error("the token names a key other than this membership's")
	}
	if grant.Network() != f.netID.String() {
		t.Errorf("the token names network %s, want %s", grant.Network(), f.netID)
	}
	if msg.GetExpiresAtUnix() != grant.ExpiresAt.Unix() {
		t.Error("the reported expiry disagrees with the token's own")
	}
}

// Asking again while the current token is comfortably valid returns the same one. Otherwise a
// retry loop costs a signature per attempt and a device accumulates live credentials.
func TestAskingAgainReturnsTheSameTokenWhileItIsValid(t *testing.T) {
	f := newFixture(t)
	f.withRelayIssuer(t)
	alice := f.enrolDevice("alice")

	sess := newSession("s", alice.membershipID, f.netID, uuid.New(), f.clk.Now())
	first, expires, err := f.srv.relayTokenFor(f.ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	again, expiresAgain, err := f.srv.relayTokenFor(f.ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(again) || !expires.Equal(expiresAgain) {
		t.Error("a second request minted a new token although the first was still good")
	}

	// Close to expiry it is replaced, or an agent would be handed something about to die.
	f.clk.Advance(relaytoken.DefaultTTL - time.Minute)
	fresh, _, err := f.srv.relayTokenFor(f.ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	if string(fresh) == string(first) {
		t.Error("a token near expiry was handed out again rather than replaced")
	}
}

// A deployment that has not configured relaying still enrols devices and carries state. An
// agent asking is told, rather than met with silence it would retry against forever.
func TestADeploymentWithoutARelayKeySaysSo(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	msg := f.askForToken(t, alice.membershipID)
	if msg.GetError() == "" {
		t.Error("a deployment with no signing key issued a token")
	}
	if len(msg.GetToken()) != 0 {
		t.Error("a refusal carried a token anyway")
	}
}

// An agent whose membership has vanished must be refused rather than crash the read loop.
func TestAnUnknownMembershipIsRefused(t *testing.T) {
	f := newFixture(t)
	f.withRelayIssuer(t)

	msg := f.askForToken(t, uuid.New())
	if msg.GetError() == "" {
		t.Error("a token was issued for a membership that does not exist")
	}
}

func TestAnIssuerRefusesAMalformedSigningKey(t *testing.T) {
	if _, err := NewRelayIssuer(ed25519.PrivateKey("short"), time.Minute); err == nil {
		t.Error("a malformed signing key was accepted")
	}
	issuer, err := NewRelayIssuer(nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if issuer != nil {
		t.Error("no signing key should mean no issuer")
	}
	if issuer.PublicKey() != nil {
		t.Error("a nil issuer reported a public key")
	}
}

// The relay is configured with exactly what PublicKey returns, so it had better be the half
// that verifies this issuer's tokens.
func TestTheReportedPublicKeyIsTheOneThatVerifies(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewRelayIssuer(priv, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	var key relayproto.Key
	key[0] = 1
	tok, err := relaytoken.Issue(priv, key, [16]byte{}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relaytoken.Verify(issuer.PublicKey(), tok, time.Now()); err != nil {
		t.Errorf("the reported public key does not verify this issuer's tokens: %v", err)
	}
}
