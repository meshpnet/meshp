package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/meshpnet/meshp/internal/acl"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// ErrNoPolicy means a network has no policy in force.
//
// A condition rather than a failure, and one every caller has to handle deliberately: no
// policy means every device may reach every other, which is what a network does before
// anyone writes one. Treating it as an empty policy would silently deny everything the
// moment this code shipped.
var ErrNoPolicy = errors.New("store: this network has no active policy")

// Policy is one stored version of a network's ACL document.
type Policy struct {
	NetworkID uuid.UUID
	Version   int32
	Document  acl.Document
	Active    bool
	CreatedAt time.Time
}

// ActivePolicy returns the policy in force, or ErrNoPolicy.
func (s *Store) ActivePolicy(ctx context.Context, networkID uuid.UUID) (Policy, error) {
	row, err := s.queries.GetActivePolicy(ctx, networkID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNoPolicy
	}
	if err != nil {
		return Policy{}, fmt.Errorf("store: loading the active policy: %w", err)
	}

	doc, err := acl.Parse(row.Document)
	if err != nil {
		// Stored and unreadable. Refused rather than approximated: this document was
		// written by an older build with a different idea of what is valid, and compiling
		// part of a policy would produce a filter nobody wrote.
		return Policy{}, fmt.Errorf("store: the stored policy for network %s is unusable: %w",
			networkID, err)
	}
	return Policy{
		NetworkID: row.NetworkID,
		Version:   row.Version,
		Document:  doc,
		Active:    true,
		CreatedAt: row.CreatedAt,
	}, nil
}

// PublishPolicy stores a document and makes it the one in force.
//
// Publishing, standing the previous one down and logging the state change all happen in
// one transaction. Apart, they fail in ways nothing detects: a policy activated without a
// logged change reaches no agent until something unrelated bumps the version, and a logged
// change without an activated policy tells every agent to recompile against the policy
// that is still in force.
func (s *Store) PublishPolicy(ctx context.Context, req PublishPolicyRequest) (Policy, error) {
	if err := req.Document.Validate(); err != nil {
		return Policy{}, err
	}
	encoded, err := json.Marshal(req.Document)
	if err != nil {
		return Policy{}, fmt.Errorf("store: encoding the policy: %w", err)
	}

	var out Policy
	err = s.InTx(ctx, func(q *dbgen.Queries) error {
		version, err := q.NextPolicyVersion(ctx, req.NetworkID)
		if err != nil {
			return fmt.Errorf("store: choosing a policy version: %w", err)
		}
		// Stood down first. acl_policies carries a unique index over active policies per
		// network, so raising a new one while the old still stands is refused by the
		// database — which is the constraint doing its job rather than a race to lose.
		if _, err := q.DeactivatePolicies(ctx, req.NetworkID); err != nil {
			return fmt.Errorf("store: standing down the previous policy: %w", err)
		}

		row, err := q.InsertPolicy(ctx, dbgen.InsertPolicyParams{
			NetworkID:       req.NetworkID,
			Version:         version,
			Document:        encoded,
			IsActive:        true,
			CreatedByUserID: req.CreatedByUserID,
		})
		if err != nil {
			return fmt.Errorf("store: storing the policy: %w", err)
		}

		// One row, not one per device. A policy changes what every device may do, and
		// writing a peer change for each would make one edit to a 500-device network write
		// 500 rows and send 500-entry deltas.
		if _, err := BumpVersion(ctx, q, req.NetworkID, PolicyChanged()); err != nil {
			return err
		}

		metadata, _ := json.Marshal(map[string]any{
			"policy_version": row.Version,
			"rules":          len(req.Document.Rules),
		})
		networkID := req.NetworkID
		if err := WriteAudit(ctx, q, req.Actor, dbgen.CreateAuditEventParams{
			OrganizationID: req.OrganizationID,
			NetworkID:      &networkID,
			Action:         "policy.published",
			ResourceKind:   "acl_policy",
			ResourceID:     &row.ID,
			SourceIp:       req.SourceIP,
			Metadata:       metadata,
		}); err != nil {
			return err
		}

		out = Policy{
			NetworkID: row.NetworkID,
			Version:   row.Version,
			Document:  req.Document,
			Active:    true,
			CreatedAt: row.CreatedAt,
		}
		return nil
	})
	if err != nil {
		return Policy{}, err
	}
	return out, nil
}

// PublishPolicyRequest is a policy and who published it.
type PublishPolicyRequest struct {
	NetworkID uuid.UUID
	Document  acl.Document

	OrganizationID  *uuid.UUID
	CreatedByUserID *uuid.UUID
	// Actor is who is publishing. Required, like every audited action here.
	Actor    Actor
	SourceIP *netip.Addr
}

// PolicyDevices returns everything the compiler needs about a network's members.
//
// Revoked and suspended memberships are excluded by the query, so a policy never resolves
// a tag to a device that is no longer entitled to be reached — which would put a stale
// address in every other device's filter.
func (s *Store) PolicyDevices(ctx context.Context, networkID uuid.UUID) ([]acl.Device, error) {
	rows, err := s.queries.ListPolicyDevices(ctx, networkID)
	if err != nil {
		return nil, fmt.Errorf("store: listing devices for policy: %w", err)
	}

	out := make([]acl.Device, 0, len(rows))
	for _, row := range rows {
		device := acl.Device{Key: row.WireguardPublicKey, Tags: row.Tags}
		for _, addr := range []*netip.Addr{row.AddressV4, row.AddressV6} {
			if addr == nil {
				continue
			}
			unmapped := addr.Unmap()
			device.Addresses = append(device.Addresses,
				netip.PrefixFrom(unmapped, unmapped.BitLen()))
		}
		if len(device.Addresses) == 0 {
			// A member with no address cannot be a source or a destination, and including
			// it would put an empty device in every tag it carries.
			continue
		}
		out = append(out, device)
	}
	return out, nil
}
