package clicred

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The round trip, and the only thing every noun command depends on.
func TestACredentialSurvivesBeingWritten(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	want := Credential{
		ControlURL: "https://control.example.com",
		Token:      "mp_secret",
		TokenID:    "0f4b",
		Email:      "someone@example.com",
	}
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("loaded %+v, saved %+v", got, want)
	}
}

// Nothing stored is a named condition, not a file-not-found. Every noun hits it, and what
// somebody needs to be told is "run meshp login" rather than a path.
func TestNothingStoredIsNotSignedIn(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, err := Load(); !errors.Is(err, ErrNotSignedIn) {
		t.Errorf("err = %v, want ErrNotSignedIn", err)
	}
}

// A token is a secret on a machine other people may log into.
func TestTheCredentialIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := Save(Credential{ControlURL: "https://c", Token: "mp_secret"}); err != nil {
		t.Fatal(err)
	}

	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the credential is mode %o, want 600 — it is a token, on a machine several "+
			"people may log into", perm)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := parent.Mode().Perm(); perm != 0o700 {
		t.Errorf("the directory holding it is mode %o, want 700", perm)
	}
}

// A file that will not parse holds a token somebody may still need to revoke. Replacing it
// silently would take that away.
func TestAnUnreadableFileIsRefusedRatherThanReplaced(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Load()
	if err == nil {
		t.Fatal("a corrupt credential file loaded successfully")
	}
	if errors.Is(err, ErrNotSignedIn) {
		t.Error("a corrupt file was reported as not being signed in, which invites somebody " +
			"to log in again over a token they can no longer revoke")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not say which file is unreadable: %v", err)
	}
}

// Logging out twice is not an error.
func TestForgettingWhatIsNotThereIsSuccess(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := Forget(); err != nil {
		t.Errorf("forgetting an absent credential failed: %v", err)
	}
	if err := Save(Credential{ControlURL: "https://c", Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := Forget(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); !errors.Is(err, ErrNotSignedIn) {
		t.Errorf("after forgetting, Load returned %v", err)
	}
	if err := Forget(); err != nil {
		t.Errorf("forgetting twice failed: %v", err)
	}
}

// Saving replaces rather than appends, or a person who signs in twice keeps a token they can
// no longer see.
func TestSigningInAgainReplacesTheCredential(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := Save(Credential{ControlURL: "https://one", Token: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := Save(Credential{ControlURL: "https://two", Token: "second"}); err != nil {
		t.Fatal(err)
	}

	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "second" {
		t.Errorf("loaded %q, want the most recent credential", got.Token)
	}

	raw, err := os.ReadFile(mustPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "first") {
		t.Error("the previous token is still in the file, where nothing will ever use it " +
			"and nobody will think to revoke it")
	}
}

func mustPath(t *testing.T) string {
	t.Helper()
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	return path
}
