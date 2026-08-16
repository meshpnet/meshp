package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// ErrNoSuchNetwork means the network named does not exist, or has been deleted.
var ErrNoSuchNetwork = errors.New("store: no such network")

// EgressFailClosed reports whether devices in this network must refuse egress outside the
// tunnel while they claim a default route.
func (s *Store) EgressFailClosed(ctx context.Context, networkID uuid.UUID) (bool, error) {
	network, err := s.Queries().GetNetwork(ctx, networkID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNoSuchNetwork
	}
	if err != nil {
		return false, fmt.Errorf("store: loading the network: %w", err)
	}
	return network.EgressFailClosed, nil
}

// SetEgressFailClosed records an administrator's answer to ADR-0011 for one network.
//
// True is the default and means a device claiming a default route installs a firewall that
// refuses everything not going through the tunnel. False means it does not, so traffic
// leaves in the clear if the tunnel drops — which is a decision worth being able to make,
// and worth being unable to make by accident.
//
// Reports whether anything changed. A write of the value the network already holds bumps
// nothing and tells nobody: every agent would otherwise be handed a delta for a
// reconfiguration that did not happen, and in a log that is indistinguishable from one that
// did.
//
// The write and the version bump share a transaction, like every other mutation here. A
// column changed without a logged change reaches no agent until something unrelated moves
// the version — and for this column that means devices going on enforcing a policy their
// administrator has already revoked, with the API reporting success.
func (s *Store) SetEgressFailClosed(ctx context.Context, networkID uuid.UUID, enforced bool) (bool, error) {
	changed := false
	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		row, err := q.SetNetworkEgressFailClosed(ctx, dbgen.SetNetworkEgressFailClosedParams{
			ID:               networkID,
			EgressFailClosed: enforced,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchNetwork
		}
		if err != nil {
			return fmt.Errorf("store: recording the fail-closed policy: %w", err)
		}
		if !row.Changed {
			return nil
		}

		// TunnelChanged rather than RoutesChanged, though this is about egress. What
		// changed is the tunnel configuration every device is sent, not who carries a
		// prefix; logging it as a route change would make every agent in the network
		// recompute and reinstall assignments that did not move.
		if _, err := BumpVersion(ctx, q, networkID, TunnelChanged()); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}
