package enroll

import (
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/keys"
)

// joinNamed enrols a fresh device under a chosen display name.
func (f *fixture) joinNamed(name string) string {
	f.t.Helper()
	tok, _ := f.mintToken(1, time.Hour)

	identity, err := keys.NewIdentity()
	if err != nil {
		f.t.Fatal(err)
	}
	wg, err := keys.NewWireGuardPair()
	if err != nil {
		f.t.Fatal(err)
	}
	resp, err := f.svc.IssueChallenge(f.ctx, ChallengeRequest{
		Token: tok.Plaintext, IdentityPublicKey: identity.Public,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	challenge, err := ParseChallenge(resp.Challenge)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.svc.Redeem(f.ctx, RedeemRequest{
		Token:              tok.Plaintext,
		IdentityPublicKey:  identity.Public,
		Challenge:          challenge,
		Signature:          identity.Sign(challenge),
		WireGuardPublicKey: wg.Public.String(),
		Name:               name,
		OS:                 "linux",
	}); err != nil {
		f.t.Fatalf("joining as %q: %v", name, err)
	}

	var label string
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT m.dns_label FROM device_network_memberships m
		 JOIN devices d ON d.id = m.device_id
		 WHERE d.name = $1 ORDER BY m.joined_at DESC LIMIT 1`, name).Scan(&label); err != nil {
		f.t.Fatalf("reading the label for %q: %v", name, err)
	}
	return label
}

// The rule that decides whether this is a better product or a worse one.
//
// A fleet imaged with one hostname must all enrol. Refusing the second would produce one
// success and forty-nine failures, for a reason the person running the installer can
// neither see nor fix (ADR-0021).
func TestACollidingNameIsSuffixedNotRefused(t *testing.T) {
	f := newFixture(t)

	first := f.joinNamed("fileserver")
	second := f.joinNamed("fileserver")
	third := f.joinNamed("fileserver")

	if first != "fileserver" {
		t.Errorf("the first device got %q, want the unsuffixed name", first)
	}
	if second != "fileserver-2" {
		t.Errorf("the second got %q, want fileserver-2", second)
	}
	if third != "fileserver-3" {
		t.Errorf("the third got %q, want fileserver-3", third)
	}
}

// Case and punctuation are normalised, so two devices a person would call the same thing
// do not both claim the plain label.
func TestNamesAreNormalisedBeforeTheyCollide(t *testing.T) {
	f := newFixture(t)

	if got := f.joinNamed("FileServer"); got != "fileserver" {
		t.Fatalf("got %q", got)
	}
	if got := f.joinNamed("file server"); got != "file-server" {
		t.Errorf("got %q, want file-server", got)
	}
	if got := f.joinNamed("FILESERVER"); got != "fileserver-2" {
		t.Errorf("got %q, want fileserver-2 — case must not dodge the collision", got)
	}
}

// A display name with nothing usable in it still enrols. Every membership needs a label,
// and an opaque one beats a device that cannot join.
func TestAnUnusableNameStillEnrols(t *testing.T) {
	f := newFixture(t)

	got := f.joinNamed("!!!")
	if got == "" {
		t.Fatal("a device with an unusable name got no label")
	}
	if len(got) < len("device-") || got[:len("device-")] != "device-" {
		t.Errorf("label = %q, want one derived from the device id", got)
	}
}

// The display name is untouched. `Dave's laptop (spare)` survives for a person to read;
// the label is a second, machine-shaped name beside it. ADR-0021 called this cost
// unavoidable and it turned out not to be.
func TestTheDisplayNameSurvives(t *testing.T) {
	f := newFixture(t)

	label := f.joinNamed("Dave's laptop (spare)")
	if label != "dave-s-laptop-spare" {
		t.Errorf("label = %q", label)
	}

	var stored string
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT name FROM devices WHERE name = $1`, "Dave's laptop (spare)").Scan(&stored); err != nil {
		t.Fatalf("the display name did not survive: %v", err)
	}
}
