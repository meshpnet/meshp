package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// PruneResult reports what a sweep removed.
type PruneResult struct {
	Networks int
	Rows     int64
}

// PruneDeltaLog drops change-log rows older than a cutoff and raises each network's delta
// floor to match.
//
// The log has to be bounded. Without this the table grows for the lifetime of the
// deployment, at one row per peer change per network — never fast enough to notice, and
// never anything but larger.
//
// The floor and the delete happen in one transaction per network, and that is the whole
// point of this function existing rather than two calls at a call site. If rows were
// removed without the floor moving, the network would claim it can build deltas from a
// version whose changes are gone: an agent at that version would be sent a delta with
// holes in it and would report success, because the version numbers agree while the
// contents do not (Invariant 21). Moving the floor without removing rows is merely
// wasteful — agents get snapshots they did not need — which is why, if only one of the two
// can happen, it must be that one.
//
// Per network rather than one transaction for everything: a sweep across ten thousand
// networks in a single transaction would hold locks for its whole duration and roll all of
// it back for one failure.
func (s *Store) PruneDeltaLog(ctx context.Context, olderThan time.Time) (PruneResult, error) {
	networks, err := s.Queries().ListNetworksWithPrunableChanges(ctx, olderThan)
	if err != nil {
		return PruneResult{}, fmt.Errorf("store: listing networks to prune: %w", err)
	}

	var out PruneResult
	for _, networkID := range networks {
		rows, err := s.pruneNetwork(ctx, networkID, olderThan)
		if err != nil {
			// Reporting what was done before the failure: a caller that logs "pruned
			// nothing" after removing half a million rows makes the next person's
			// reasoning about table growth wrong.
			return out, err
		}
		out.Networks++
		out.Rows += rows
	}
	return out, nil
}

func (s *Store) pruneNetwork(ctx context.Context, networkID uuid.UUID, olderThan time.Time) (int64, error) {
	var rows int64
	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		pruned, err := q.PruneStateChanges(ctx, dbgen.PruneStateChangesParams{
			NetworkID: networkID,
			OlderThan: olderThan,
		})
		if err != nil {
			return fmt.Errorf("store: pruning changes for %s: %w", networkID, err)
		}
		rows = pruned.RowsPruned
		if pruned.RowsPruned == 0 {
			// Nothing was old enough after all — another sweep got there first.
			return nil
		}
		// The floor is the highest version removed, not one past it: a delta *from* that
		// version needs the changes above it, all of which are still here.
		if _, err := q.RaiseDeltaFloor(ctx, dbgen.RaiseDeltaFloorParams{
			ID:      networkID,
			Version: pruned.HighestPruned,
		}); err != nil {
			return fmt.Errorf("store: raising the delta floor for %s: %w", networkID, err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return rows, nil
}
