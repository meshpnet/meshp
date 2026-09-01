// Package clicred is where a person's CLI credential lives.
//
// Not the daemon's. meshpd runs as root and holds this device's identity and key material,
// and its socket is owner-only because anything reaching it can enrol the machine and decide
// where its traffic goes. This is the other thing entirely: what the person at the keyboard
// may do to a control plane, on a machine several people may log into (ADR-0031 §2).
package clicred

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotSignedIn is returned when there is nothing stored.
//
// A named error rather than a bare "file not found", because every noun command hits it and
// the answer somebody needs is "run meshp login", not a path.
var ErrNotSignedIn = errors.New("clicred: not signed in")

// File is what is on disk.
//
// A list of one, so that a second control plane later is a longer list rather than a
// migration. An MSP holding forty customers is the product, and the day that arrives this
// should not be a format change (ADR-0031 §3).
type File struct {
	Credentials []Credential `json:"credentials"`
}

// Credential is one person's access to one control plane.
type Credential struct {
	ControlURL string `json:"control_url"`
	Token      string `json:"token"`
	// TokenID is what `meshp logout` revokes and what a person sees in `meshp token list`.
	// Kept because a token is a secret that cannot be looked up by its own value.
	TokenID string `json:"token_id,omitempty"`
	// Email is who this is, for the CLI to say so without asking the control plane.
	Email string `json:"email,omitempty"`
}

// Path is where the credential lives.
//
// Under XDG_CONFIG_HOME where somebody has set it, because a person who has moved their
// configuration has said where they want it.
func Path() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("clicred: finding your home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "meshp", "credentials.json"), nil
}

// Load reads the stored credential, or ErrNotSignedIn.
func Load() (Credential, error) {
	path, err := Path()
	if err != nil {
		return Credential{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, ErrNotSignedIn
	}
	if err != nil {
		return Credential{}, fmt.Errorf("clicred: reading %s: %w", path, err)
	}

	var file File
	if err := json.Unmarshal(raw, &file); err != nil {
		// Refused rather than repaired. A file that will not parse may hold a token
		// somebody still needs to revoke, and silently replacing it would take that away.
		return Credential{}, fmt.Errorf("clicred: %s is not readable as credentials: %w", path, err)
	}
	if len(file.Credentials) == 0 {
		return Credential{}, ErrNotSignedIn
	}
	return file.Credentials[0], nil
}

// Save writes the credential, replacing whatever was there.
//
// Owner-only, and the directory too. Written to a temporary file and renamed, so an
// interrupted write leaves the previous credential rather than half of a new one — losing a
// token that is still valid on the server means a person cannot revoke what they no longer
// hold.
func Save(cred Credential) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("clicred: preparing %s: %w", filepath.Dir(path), err)
	}

	encoded, err := json.MarshalIndent(File{Credentials: []Credential{cred}}, "", "  ")
	if err != nil {
		return fmt.Errorf("clicred: encoding the credential: %w", err)
	}
	encoded = append(encoded, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return fmt.Errorf("clicred: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("clicred: replacing %s: %w", path, err)
	}
	return nil
}

// Forget removes the stored credential. Absent is success: `meshp logout` twice is not an
// error, and somebody who has already deleted the file has got what they wanted.
func Forget() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clicred: removing %s: %w", path, err)
	}
	return nil
}
