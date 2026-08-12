// Package agentstate persists what a device needs to keep between runs.
//
// This file holds private keys, so the permissions on it are part of the contract
// rather than a detail: the directory is 0700 and the file is 0600, checked on read
// as well as write. A state file that has become world-readable is a compromised
// device, and noticing is worth more than continuing.
//
// It also has to survive the control plane being unreachable (Invariant 15), which
// is why the assigned addresses and interface name are stored alongside the keys
// rather than fetched at start-up.
//
// Today `meshp join` writes this directly. Once meshpd owns a local socket, joining
// becomes a request to the daemon and this file stops being written by an
// unprivileged command — the keys belong to the privileged process, not to whoever
// happens to run the CLI.
package agentstate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/keys"
)

// FileName is the state file's name inside the state directory.
const FileName = "state.json"

const (
	dirPerm  fs.FileMode = 0o700
	filePerm fs.FileMode = 0o600
)

// ErrNotEnrolled means there is no state yet.
var ErrNotEnrolled = errors.New("agentstate: this device is not enrolled")

// ErrPermissive means the state file is readable by more than its owner.
var ErrPermissive = errors.New("agentstate: state file permissions are too open")

// State is everything the agent keeps.
type State struct {
	// Identity is the device's long-lived signing key. One per device, shared by
	// every membership — it is the device's name (ADR-0006).
	IdentityPrivateKey string `json:"identity_private_key"` // base64
	IdentityPublicKey  string `json:"identity_public_key"`  // base64

	Memberships []Membership `json:"memberships"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Membership is one network this device belongs to.
type Membership struct {
	MembershipID uuid.UUID `json:"membership_id"`
	NetworkID    uuid.UUID `json:"network_id"`
	DeviceID     uuid.UUID `json:"device_id"`
	ControlURL   string    `json:"control_url"`

	InterfaceName string `json:"interface_name"`
	AddressV4     string `json:"address_v4,omitempty"`
	AddressV6     string `json:"address_v6,omitempty"`

	// A key per membership, never shared between them, so two networks cannot
	// recognise the same device by its key (Invariant 19).
	WireGuardPrivateKey string `json:"wireguard_private_key"` // base64
	WireGuardPublicKey  string `json:"wireguard_public_key"`  // base64

	AppliedStateVersion int64     `json:"applied_state_version"`
	JoinedAt            time.Time `json:"joined_at"`
}

// Identity decodes the device identity.
func (s *State) Identity() (keys.Identity, error) {
	priv, err := base64.StdEncoding.DecodeString(s.IdentityPrivateKey)
	if err != nil {
		return keys.Identity{}, fmt.Errorf("agentstate: identity private key: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(s.IdentityPublicKey)
	if err != nil {
		return keys.Identity{}, fmt.Errorf("agentstate: identity public key: %w", err)
	}
	return keys.Identity{Public: pub, Private: priv}, nil
}

// SetIdentity records a device identity.
func (s *State) SetIdentity(id keys.Identity) {
	s.IdentityPrivateKey = base64.StdEncoding.EncodeToString(id.Private)
	s.IdentityPublicKey = base64.StdEncoding.EncodeToString(id.Public)
}

// FindMembership returns the membership for a network, if any.
func (s *State) FindMembership(networkID uuid.UUID) (Membership, bool) {
	for _, m := range s.Memberships {
		if m.NetworkID == networkID {
			return m, true
		}
	}
	return Membership{}, false
}

// AddMembership records a membership, replacing any for the same network.
func (s *State) AddMembership(m Membership) {
	for i := range s.Memberships {
		if s.Memberships[i].NetworkID == m.NetworkID {
			s.Memberships[i] = m
			return
		}
	}
	s.Memberships = append(s.Memberships, m)
}

// Path returns the state file's location inside dir.
func Path(dir string) string { return filepath.Join(dir, FileName) }

// Load reads state from dir.
func Load(dir string) (*State, error) {
	path := Path(dir)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotEnrolled
		}
		return nil, fmt.Errorf("agentstate: %w", err)
	}

	// Checked on read, not only on write: a file that has been chmodded since it was
	// written is exactly the case a write-time check cannot see.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s is %04o, want 0600", ErrPermissive, path, perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("agentstate: reading %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("agentstate: %s is not valid state: %w", path, err)
	}
	return &s, nil
}

// Save writes state to dir.
//
// Written to a temporary file and renamed, so a crash or a full disk halfway through
// cannot leave a device holding half a state file — which would mean an enrolled
// device that can no longer prove who it is.
func Save(dir string, s *State) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("agentstate: creating %s: %w", dir, err)
	}
	// MkdirAll respects umask, so the mode is set explicitly afterwards.
	if err := os.Chmod(dir, dirPerm); err != nil {
		return fmt.Errorf("agentstate: securing %s: %w", dir, err)
	}

	now := time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now

	encoded, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("agentstate: encoding state: %w", err)
	}
	encoded = append(encoded, '\n')

	path := Path(dir)
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("agentstate: creating a temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	// Permissions before contents, so the private keys are never briefly readable.
	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agentstate: securing %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agentstate: writing %s: %w", tmpName, err)
	}
	// Durable before visible: a rename that lands before the data does would leave a
	// valid-looking file with nothing in it.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agentstate: flushing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agentstate: closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("agentstate: replacing %s: %w", path, err)
	}
	return nil
}
