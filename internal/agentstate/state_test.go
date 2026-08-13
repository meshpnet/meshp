package agentstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/keys"
)

func TestLoadWithoutStateSaysNotEnrolled(t *testing.T) {
	_, err := Load(t.TempDir())
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("error = %v, want ErrNotEnrolled", err)
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()

	identity, err := keys.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wg, err := keys.NewWireGuardPair()
	if err != nil {
		t.Fatal(err)
	}

	networkID := uuid.New()
	state := &State{}
	state.SetIdentity(identity)
	state.AddMembership(Membership{
		MembershipID:        uuid.New(),
		NetworkID:           networkID,
		DeviceID:            uuid.New(),
		ControlURL:          "https://control.example.test",
		InterfaceName:       "meshp0",
		AddressV4:           "100.90.0.7",
		AddressV6:           "fd7c::7",
		WireGuardPrivateKey: wg.Private.String(),
		WireGuardPublicKey:  wg.Public.String(),
	})

	if err := Save(dir, state); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The identity has to survive exactly, or the device can no longer prove who it
	// is and has to be revoked and enrolled again.
	back, err := loaded.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if !back.Public.Equal(identity.Public) {
		t.Error("identity public key did not survive the round trip")
	}
	if string(back.Private) != string(identity.Private) {
		t.Error("identity private key did not survive the round trip")
	}

	m, ok := loaded.FindMembership(networkID)
	if !ok {
		t.Fatal("membership was lost")
	}
	if m.WireGuardPrivateKey != wg.Private.String() || m.AddressV4 != "100.90.0.7" {
		t.Errorf("membership came back changed: %+v", m)
	}
	if loaded.CreatedAt.IsZero() || loaded.UpdatedAt.IsZero() {
		t.Error("timestamps were not recorded")
	}
}

// The file holds private keys, so the permissions are part of the contract.
func TestSaveUsesRestrictivePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")

	state := &State{}
	if err := Save(dir, state); err != nil {
		t.Fatal(err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory is %04o, want 0700", perm)
	}

	fileInfo, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file is %04o, want 0600", perm)
	}
}

// Checked on read as well as write: a file chmodded after it was written is exactly
// the case a write-time check cannot see, and it means the keys have been exposed.
func TestLoadRefusesAPermissiveFile(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, &State{}); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		if err := os.Chmod(Path(dir), mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(dir)
		if !errors.Is(err, ErrPermissive) {
			t.Errorf("mode %04o: error = %v, want ErrPermissive", mode, err)
		}
		// The message has to name the file and the mode, since fixing it means running
		// chmod on something specific.
		if err != nil && !strings.Contains(err.Error(), FileName) {
			t.Errorf("mode %04o: error does not name the file: %v", mode, err)
		}
	}
}

func TestAddMembershipReplacesTheSameNetwork(t *testing.T) {
	networkID := uuid.New()
	s := &State{}
	s.AddMembership(Membership{NetworkID: networkID, InterfaceName: "meshp0", AddressV4: "100.90.0.1"})
	s.AddMembership(Membership{NetworkID: networkID, InterfaceName: "meshp0", AddressV4: "100.90.0.2"})

	if len(s.Memberships) != 1 {
		t.Fatalf("%d memberships, want 1", len(s.Memberships))
	}
	if s.Memberships[0].AddressV4 != "100.90.0.2" {
		t.Errorf("address = %s, want the replacement", s.Memberships[0].AddressV4)
	}
}

// One device, several networks — the shape ADR-0004 requires.
func TestSeveralMembershipsCoexist(t *testing.T) {
	dir := t.TempDir()
	s := &State{}
	a, b := uuid.New(), uuid.New()
	s.AddMembership(Membership{NetworkID: a, InterfaceName: "meshp0", WireGuardPublicKey: "key-a"})
	s.AddMembership(Membership{NetworkID: b, InterfaceName: "meshp1", WireGuardPublicKey: "key-b"})

	if err := Save(dir, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Memberships) != 2 {
		t.Fatalf("%d memberships, want 2", len(loaded.Memberships))
	}
	first, _ := loaded.FindMembership(a)
	second, _ := loaded.FindMembership(b)
	// Distinct interfaces, because the two networks' address space may overlap, and
	// distinct keys so neither network can recognise the device in the other.
	if first.InterfaceName == second.InterfaceName {
		t.Error("both memberships claim the same interface")
	}
	if first.WireGuardPublicKey == second.WireGuardPublicKey {
		t.Error("both memberships share a WireGuard key")
	}
}

// Written to a temporary file and renamed, so a crash midway cannot leave a device
// holding half a state file.
func TestSaveLeavesNoTemporaryFilesBehind(t *testing.T) {
	dir := t.TempDir()
	for range 5 {
		if err := Save(dir, &State{}); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != FileName {
			t.Errorf("left behind %q", e.Name())
		}
	}
}

func TestSaveOverwritesAtomically(t *testing.T) {
	dir := t.TempDir()
	first := &State{}
	first.AddMembership(Membership{NetworkID: uuid.New(), InterfaceName: "meshp0"})
	if err := Save(dir, first); err != nil {
		t.Fatal(err)
	}

	second := &State{}
	second.AddMembership(Membership{NetworkID: uuid.New(), InterfaceName: "meshp9"})
	if err := Save(dir, second); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Memberships) != 1 || loaded.Memberships[0].InterfaceName != "meshp9" {
		t.Errorf("state after overwrite = %+v", loaded.Memberships)
	}
	// Permissions must survive a rewrite, not only the first write.
	info, _ := os.Stat(Path(dir))
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file is %04o after rewrite, want 0600", perm)
	}
}

func TestLoadRejectsCorruptState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(Path(dir), []byte("this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load accepted a corrupt state file")
	}
	if errors.Is(err, ErrNotEnrolled) {
		t.Error("corrupt state was reported as not enrolled, which would silently discard the keys")
	}
}

func TestIdentityRejectsCorruptKeys(t *testing.T) {
	s := &State{IdentityPrivateKey: "!!!not base64!!!", IdentityPublicKey: "also not"}
	if _, err := s.Identity(); err == nil {
		t.Error("Identity accepted unparseable keys")
	}
}

// A revoked membership is forgotten, and only that one: a device may belong to several
// networks (ADR-0004), and one revoking it says nothing about the others.
func TestRemoveMembershipTakesOnlyTheOneNamed(t *testing.T) {
	s := &State{}
	keep, drop := uuid.New(), uuid.New()
	s.AddMembership(Membership{MembershipID: keep, NetworkID: uuid.New(),
		InterfaceName: "meshp0", WireGuardPrivateKey: "keep-key"})
	s.AddMembership(Membership{MembershipID: drop, NetworkID: uuid.New(),
		InterfaceName: "meshp1", WireGuardPrivateKey: "drop-key"})

	if !s.RemoveMembership(drop) {
		t.Fatal("removing a membership that exists reported nothing to do")
	}
	if len(s.Memberships) != 1 || s.Memberships[0].MembershipID != keep {
		t.Fatalf("memberships = %+v, want only the kept one", s.Memberships)
	}
	// The key went with it. Keys are per membership and never shared (Invariant 19), so
	// leaving one behind would keep material for a network this device is out of.
	for _, m := range s.Memberships {
		if m.WireGuardPrivateKey == "drop-key" {
			t.Error("the revoked membership's key survived")
		}
	}

	if s.RemoveMembership(drop) {
		t.Error("removing the same membership twice reported that it did something")
	}
	if s.RemoveMembership(uuid.New()) {
		t.Error("removing an unknown membership reported that it did something")
	}
}

// The identity names this device to every network it has joined (ADR-0006), so it survives
// one network revoking the device. Only an explicit wipe, once nothing is left, discards it.
func TestRemoveMembershipKeepsTheIdentity(t *testing.T) {
	s := &State{}
	id, err := keys.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s.SetIdentity(id)
	membershipID := uuid.New()
	s.AddMembership(Membership{MembershipID: membershipID, NetworkID: uuid.New(), InterfaceName: "meshp0"})

	s.RemoveMembership(membershipID)
	if s.IdentityPublicKey == "" {
		t.Fatal("removing a membership discarded the device's identity")
	}
	if _, err := s.Identity(); err != nil {
		t.Fatalf("the identity is no longer usable: %v", err)
	}

	s.ForgetIdentity()
	if s.IdentityPublicKey != "" || s.IdentityPrivateKey != "" {
		t.Error("ForgetIdentity left key material behind")
	}
	if _, err := s.Identity(); err == nil {
		t.Error("a forgotten identity still loads")
	}
}
