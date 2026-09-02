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

// ErrNoSuchDevice means there is no such device in this organisation.
//
// One error for "no such id" and "not yours", for the reason ErrNotAMember gives: telling
// them apart lets somebody holding a credential for one organisation probe for device ids
// in another.
var ErrNoSuchDevice = errors.New("store: no such device in this organisation")

// ForgetRequest is who is erasing what.
type ForgetRequest struct {
	OrganizationID uuid.UUID
	DeviceID       uuid.UUID

	// Actor is who is doing this. Required: WriteAudit refuses a zero one rather than
	// recording an erasure nobody can be asked about.
	Actor    Actor
	SourceIP *netip.Addr
}

// Forgotten is what an erasure removed.
type Forgotten struct {
	DeviceID uuid.UUID
	Name     string

	// Networks the device was a member of, whether or not those memberships were revoked.
	Networks []uuid.UUID

	// Keys every other device has been told to stop accepting.
	Keys []string
}

// ForgetDevice erases a device: its record, its memberships, its keys, and its route
// advertisements, in every network at once.
//
// The destructive counterpart to RevokeMembership, and deliberately a different shape.
// Revocation is per network and leaves the row visible, because an administrator checking
// that a device is out needs to see that it is out. This is per device and leaves nothing,
// because "take my laptop off this system" is a different question and revocation was never
// an answer to it.
//
// Organisation-scoped rather than network-scoped: a device can hold memberships in several
// networks (ADR-0004), and no single one of them owns it.
//
// Everything happens in one transaction, for the reason RevokeMembership gives. Split
// apart, the failures are silent in both directions: rows deleted without the peer removals
// logged leaves every other agent holding a key for a device that no longer exists and no
// record that will ever tell them otherwise, and removals logged without the delete leaves
// a device that has been cut off but not erased, which is the state this exists to end.
//
// What this does not do is reach the device. Like revocation, it is enforced by the peers
// (ADR-0007's shape): the erased device keeps whatever is on its disk, and what changes is
// that nobody will talk to it. Removing the software from the machine is a separate act and
// this does not depend on it having happened.
func (s *Store) ForgetDevice(ctx context.Context, req ForgetRequest) (Forgotten, error) {
	var out Forgotten

	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		// Scoped, though DeleteDevice below is scoped too and the transaction would take
		// back anything done in between. Both on purpose: this is the check that gives the
		// refusal its meaning, and relying on the delete alone would mean another tenant's
		// networks got peer removals bumped for a device that was never theirs to touch,
		// correct only because the rollback happened to catch it.
		device, err := q.GetDeviceInOrganization(ctx, dbgen.GetDeviceInOrganizationParams{
			ID:             req.DeviceID,
			OrganizationID: req.OrganizationID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchDevice
		}
		if err != nil {
			return fmt.Errorf("store: loading the device: %w", err)
		}

		// Read before the delete destroys it.
		memberships, err := q.ListMembershipsForForget(ctx, req.DeviceID)
		if err != nil {
			return fmt.Errorf("store: listing the device's memberships: %w", err)
		}

		for _, m := range memberships {
			out.Networks = append(out.Networks, m.NetworkID)

			// A membership that never completed enrolment has no current key. There is
			// nothing for anyone to stop accepting, and PeerRemoved("") would be a change
			// naming no peer.
			if m.WireguardPublicKey != nil && *m.WireguardPublicKey != "" {
				key := *m.WireguardPublicKey
				out.Keys = append(out.Keys, key)
				if _, err := BumpVersion(ctx, q, m.NetworkID, PeerRemoved(key)); err != nil {
					return err
				}
			}

			// Only when it carried something. Every bump costs every agent in the network a
			// delta, and a laptop that advertised nothing should not make five hundred
			// devices recompute their routes.
			if m.Advertises {
				if err := BumpRoutesEverywhere(ctx, q, m.NetworkID); err != nil {
					return err
				}
			}
		}

		rows, err := q.DeleteDevice(ctx, dbgen.DeleteDeviceParams{
			ID:             req.DeviceID,
			OrganizationID: req.OrganizationID,
		})
		if err != nil {
			return fmt.Errorf("store: deleting the device: %w", err)
		}
		if rows == 0 {
			// Read a moment ago inside this transaction, so this means a concurrent
			// erasure got there first rather than a scoping mistake.
			return ErrNoSuchDevice
		}

		// In the same transaction as the act. This is the only record that will exist
		// afterwards — the rows it describes are gone — so an erasure whose audit entry
		// rolled back would be one nobody could ever account for.
		//
		// One row per network rather than one for the organisation, because the only
		// reader is per network: ListAuditEventsForNetwork and the single `GET
		// /networks/{id}/audit` route. An organisation-scoped row would be written and
		// then be unreadable by anything, which is a mechanism nothing reaches (ADR-0018).
		// It is also where somebody would look — an administrator of one network asking
		// why a device vanished from it is reading that network's trail, not a list of
		// everything that ever happened to a tenant.
		deviceID := req.DeviceID
		orgID := req.OrganizationID
		writeOne := func(networkID *uuid.UUID, key string) error {
			metadata, _ := json.Marshal(map[string]any{
				"device_name":          device.Name,
				"wireguard_public_key": key,
				"networks":             out.Networks,
			})
			return WriteAudit(ctx, q, req.Actor, dbgen.CreateAuditEventParams{
				OrganizationID: &orgID,
				NetworkID:      networkID,
				Action:         "device.forgotten",
				ResourceKind:   "device",
				ResourceID:     &deviceID,
				SourceIp:       req.SourceIP,
				Metadata:       metadata,
			})
		}

		for _, m := range memberships {
			networkID := m.NetworkID
			key := ""
			if m.WireguardPublicKey != nil {
				key = *m.WireguardPublicKey
			}
			if err := writeOne(&networkID, key); err != nil {
				return err
			}
		}

		// A device that enrolled and joined nothing has no network whose trail could hold
		// this. Recorded against the organisation anyway: nothing reads those rows today,
		// and a destructive act going entirely unrecorded is the worse of the two.
		if len(memberships) == 0 {
			if err := writeOne(nil, ""); err != nil {
				return err
			}
		}

		out.DeviceID = req.DeviceID
		out.Name = device.Name
		return nil
	})
	if err != nil {
		return Forgotten{}, err
	}
	return out, nil
}
