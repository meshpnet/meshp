package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

	// RouteGroupID names a route group that is gone. Required for removals, for the reason
	// PeerPublicKey is: by the time a delta is built the row has been deleted, so a builder
	// listing the groups that exist cannot find it — and a device that is never told to drop
	// a group keeps carrying it, which on an egress group means routing everything through
	// an exit node the control plane no longer knows about (#205).
	RouteGroupID *uuid.UUID

	// Policy marks a change to the network's ACL policy, which names no peer because it
	// changes what every device may do.
	Policy bool

	// Routes marks a change to a route group or its advertisers, which names no peer for
	// the same reason.
	Routes bool

	// Tunnel marks a change to the network's tunnel configuration — today, whether devices
	// claiming a default route must fail closed. It names no peer for the same reason again.
	Tunnel bool

	// DNS marks a change to the network's administrator-entered records, which names no
	// peer because every device in the network has to be able to resolve them.
	DNS bool
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

// RouteGroupRemoved records that a group is gone, naming it.
//
// Distinct from RoutesChanged, which says "recompute the assignments" and is answered by
// listing the groups that exist. A deleted group is in no such list, so it needs to name
// itself on the way out — the same reason peer removal carries a public key (#205).
func RouteGroupRemoved(id uuid.UUID) Change { return Change{RouteGroupID: &id} }

// PolicyChanged records that the network's ACL policy changed.
//
// It names nothing, because it is about every device at once. One row rather than one per
// membership: a policy edit in a 500-device network would otherwise write 500 rows and
// produce 500-entry deltas describing peers that did not change.
func PolicyChanged() Change { return Change{Policy: true} }

// TunnelChanged records that the network's tunnel configuration changed.
//
// A delta carries TunnelConfig whether or not this row is there, so it is tempting to think
// the row is redundant. It is not: without something in the log, the builder sees no changes
// in the window and returns a delta carrying a version number and nothing else. Every agent
// would acknowledge the new version, the convergence metric would call them current, and
// every one of them would still be enforcing the old answer.
func TunnelChanged() Change { return Change{Tunnel: true} }

// DNSRecordsChanged records that an administrator added or removed a name.
//
// Names nothing, for the reason the policy kind gives: a record is desired state for every
// device in the network, since every one of them must resolve it. The arguments are for the
// log line and the audit trail rather than for the row — a delta carries the whole record
// set, so which one moved does not change what is sent.
func DNSRecordsChanged(name, recordType string) Change { return Change{DNS: true} }

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
			RouteGroupID:  change.RouteGroupID,
		}); err != nil {
			return 0, fmt.Errorf("store: recording change %d: %w", i, err)
		}
	}
	return version, nil
}

// kind reports which sort of change this is, refusing anything ambiguous.
//
// Written as a count rather than a chain of pairwise exclusions. Each new kind would
// otherwise add a comparison against every existing one, and the entry that is easy to
// forget is the one that makes two kinds mutually exclusive — which fails by writing a row
// whose kind is only half of what the caller meant, silently. Here anything that is more
// than one thing is refused by construction.
func (c Change) kind() (string, error) {
	var kinds []string
	if c.Policy {
		kinds = append(kinds, "policy")
	}
	if c.Routes {
		kinds = append(kinds, "routes")
	}
	if c.Tunnel {
		kinds = append(kinds, "tunnel")
	}
	if c.DNS {
		kinds = append(kinds, "dns")
	}
	if c.MembershipID != nil {
		kinds = append(kinds, "peer_upsert")
	}
	if c.PeerPublicKey != nil {
		kinds = append(kinds, "peer_remove")
	}
	if c.RouteGroupID != nil {
		kinds = append(kinds, "route_group_remove")
	}

	switch len(kinds) {
	case 1:
		return kinds[0], nil
	case 0:
		return "", errors.New("a change describes nothing; it must name a peer or say what else moved")
	default:
		return "", fmt.Errorf("a change is %s at once; it must be exactly one",
			strings.Join(kinds, " and "))
	}
}

// BumpRoutesEverywhere advances this network's version and that of every network sharing a
// device with it.
//
// Route changes are the one kind that can reach outside their own network. A device's
// colliding prefixes are a property of the device -- two of *its* networks carrying the same
// prefix (ADR-0020) -- so adding a prefix here can create a collision on a device that is
// also somewhere else. State versions are per network (ADR-0008), and that somewhere else has
// no idea: its version never moves, no delta is built, and the membership there goes on
// routing the customer's real prefix while the range allocated for it sits unused.
//
// Scoped to networks that actually share a device, not the whole organisation. A deployment
// where nobody is in two networks at once pays one indexed query and bumps nothing, and one
// route group change never reconciles a fleet that has no reason to care.
func BumpRoutesEverywhere(ctx context.Context, q *dbgen.Queries, networkID uuid.UUID) error {
	if _, err := BumpVersion(ctx, q, networkID, RoutesChanged()); err != nil {
		return err
	}
	return bumpRoutesForSharedNetworks(ctx, q, networkID)
}

// bumpRoutesForSharedNetworks tells the other networks a shared device sits in that routes
// moved. Split out because a deletion bumps this network with an extra change of its own and
// still owes the others an ordinary routes bump.
func bumpRoutesForSharedNetworks(ctx context.Context, q *dbgen.Queries, networkID uuid.UUID) error {
	sharing, err := q.NetworksSharingADeviceWith(ctx, networkID)
	if err != nil {
		return fmt.Errorf("store: finding networks that share a device: %w", err)
	}
	for _, other := range sharing {
		if _, err := BumpVersion(ctx, q, other, RoutesChanged()); err != nil {
			return fmt.Errorf("store: telling network %s that a shared device's routes changed: %w", other, err)
		}
	}
	return nil
}
