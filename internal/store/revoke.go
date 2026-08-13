package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// ErrNotAMember means there was nothing to revoke: no such membership in that network, or
// it had already been revoked.
//
// One error for both, because they are the same answer to the only question an
// administrator is asking — is this device out? — and telling them apart would let anyone
// holding an admin token for one network probe for membership ids in another.
var ErrNotAMember = errors.New("store: no such active membership in this network")

// Revoked is what a revocation removed.
type Revoked struct {
	MembershipID uuid.UUID
	DeviceID     uuid.UUID

	// WireGuardPublicKey is what the other devices in the network must stop accepting. It
	// is the whole enforcement mechanism: a revoked device keeps its key and its address,
	// and what changes is that nobody else will talk to it.
	WireGuardPublicKey string
}

// RevokeMembership takes a device out of a network.
//
// The revocation and the removal record go in one transaction. Split apart they fail
// silently in both directions: a membership marked revoked with no logged removal leaves
// every other agent holding a peer that the database says is gone, and a logged removal
// with no revocation lets the device reconnect and be re-added on the next snapshot.
//
// What this does not do is reach the device. Revocation is enforced by the peers, not by
// the revoked one — the same shape as ACLs being enforced at the destination (ADR-0007).
// A device that is switched off, or that never reconnects, is out of the network the moment
// everyone else applies the removal, and nothing it does can put it back.
func (s *Store) RevokeMembership(ctx context.Context, req RevokeRequest) (Revoked, error) {
	var out Revoked

	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		row, err := q.RevokeMembership(ctx, dbgen.RevokeMembershipParams{
			ID:        req.MembershipID,
			NetworkID: req.NetworkID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotAMember
		}
		if err != nil {
			return fmt.Errorf("store: revoking membership: %w", err)
		}

		if _, err := BumpVersion(ctx, q, req.NetworkID, PeerRemoved(row.WireguardPublicKey)); err != nil {
			return err
		}

		// In the same transaction as the act itself. Cutting a device out of a network is
		// the most consequential thing an administrator can do here, and a revocation that
		// committed while its audit record was rolled back would be one nobody can account
		// for afterwards.
		metadata, _ := json.Marshal(map[string]any{
			"reason":               req.Reason,
			"wireguard_public_key": row.WireguardPublicKey,
		})
		networkID := req.NetworkID
		membershipID := row.MembershipID
		if _, err := q.CreateAuditEvent(ctx, dbgen.CreateAuditEventParams{
			OrganizationID: req.OrganizationID,
			NetworkID:      &networkID,
			ActorKind:      "api_token",
			ActorLabel:     req.ActorLabel,
			Action:         "device.revoked",
			ResourceKind:   "membership",
			ResourceID:     &membershipID,
			SourceIp:       req.SourceIP,
			Metadata:       metadata,
		}); err != nil {
			return fmt.Errorf("store: writing the revocation audit event: %w", err)
		}

		out = Revoked{
			MembershipID:       row.MembershipID,
			DeviceID:           row.DeviceID,
			WireGuardPublicKey: row.WireguardPublicKey,
		}
		return nil
	})
	if err != nil {
		return Revoked{}, err
	}
	return out, nil
}

// RevokeRequest is who is revoking what, and why.
type RevokeRequest struct {
	NetworkID    uuid.UUID
	MembershipID uuid.UUID

	// OrganizationID may be nil; the audit row tolerates it and a revocation is not worth
	// refusing because the network's organisation could not be read.
	OrganizationID *uuid.UUID

	// Reason is recorded and also sent to the device, so it is written by an administrator
	// and read by whoever finds the machine. Optional.
	Reason     string
	ActorLabel string
	SourceIP   *netip.Addr
}
