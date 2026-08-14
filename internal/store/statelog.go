package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// Change describes one thing that changed about a network's desired state.
type Change struct {
	// MembershipID names a peer whose state changed. Its current row is read when a delta
	// is computed, so this is a pointer to the fact rather than a copy of it.
	MembershipID *uuid.UUID

	// PeerPublicKey names a peer that is gone. Required for removals, because by the time
	// a delta is built the row that held this key may not exist — and an agent that is
	// never told to remove a peer keeps a tunnel configured to a device that does not.
	PeerPublicKey *string

	// Policy marks a change to the network's ACL policy, which names no peer because it
	// changes what every device may do.
	Policy bool

	// Routes marks a change to a route group or its advertisers, which names no peer for
	// the same reason.
	Routes bool
}

// PeerUpserted records that a membership's peer state changed.
func PeerUpserted(membershipID uuid.UUID) Change {
	id := membershipID
	return Change{MembershipID: &id}
}

// PeerRemoved records that a WireGuard key is no longer a peer.
func PeerRemoved(publicKey string) Change {
	key := publicKey
	return Change{PeerPublicKey: &key}
}

// RoutesChanged records that a route group or one of its advertisers changed.
//
// Names nothing, like a policy change and for the same reason: who carries a prefix is
// desired state for every device in the network, not only for the advertiser. Everyone
// else has to be told where to send that traffic.
func RoutesChanged() Change { return Change{Routes: true} }

// PolicyChanged records that the network's ACL policy changed.
//
// It names nothing, because it is about every device at once. One row rather than one per
// membership: a policy edit in a 500-device network would otherwise write 500 rows and
// produce 500-entry deltas describing peers that did not change.
func PolicyChanged() Change { return Change{Policy: true} }

// BumpVersion advances a network's state version and records what changed, together.
//
// One function because the two must not come apart. A version bumped without its changes
// logged produces a delta that reports a new version and no contents, so every agent
// acknowledges state it never received and the convergence metric says they are current.
// Changes logged without a bump are never sent at all. Both failures are silent, which is
// why this is not left to callers to remember.
//
// Must be called inside the same transaction as the mutation it describes.
func BumpVersion(ctx context.Context, q *dbgen.Queries, networkID uuid.UUID, changes ...Change) (int64, error) {
	if len(changes) == 0 {
		return 0, errors.New("store: a version bump needs at least one change to describe")
	}

	version, err := q.BumpNetworkStateVersion(ctx, networkID)
	if err != nil {
		return 0, fmt.Errorf("store: bumping state version: %w", err)
	}

	for i, change := range changes {
		kind, err := change.kind()
		if err != nil {
			return 0, fmt.Errorf("store: change %d: %w", i, err)
		}
		if _, err := q.RecordStateChange(ctx, dbgen.RecordStateChangeParams{
			NetworkID:     networkID,
			Version:       version,
			Kind:          kind,
			MembershipID:  change.MembershipID,
			PeerPublicKey: change.PeerPublicKey,
		}); err != nil {
			return 0, fmt.Errorf("store: recording change %d: %w", i, err)
		}
	}
	return version, nil
}

// kind reports which sort of change this is, refusing anything ambiguous.
func (c Change) kind() (string, error) {
	switch {
	case c.Policy && c.Routes:
		return "", errors.New("a change is both a policy change and a route change; it must be one")
	case c.Routes && (c.MembershipID != nil || c.PeerPublicKey != nil):
		return "", errors.New("a route change also names a peer; it is about all of them")
	case c.Routes:
		return "routes", nil
	case c.Policy && (c.MembershipID != nil || c.PeerPublicKey != nil):
		return "", errors.New("a policy change also names a peer; it is about all of them")
	case c.Policy:
		return "policy", nil
	case c.MembershipID != nil && c.PeerPublicKey != nil:
		return "", errors.New("a change names both a membership and a key; it must be one or the other")
	case c.MembershipID != nil:
		return "peer_upsert", nil
	case c.PeerPublicKey != nil:
		return "peer_remove", nil
	default:
		return "", errors.New("a change names neither a membership nor a key")
	}
}
