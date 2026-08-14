package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/health"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// ErrNoSuchAdvertiser means the advertiser named is not in that network.
//
// Distinct from a database error because it arrives from a device: a report naming an
// advertiser in another network is refused rather than acted on, or a device could steer a
// network it cannot see.
var ErrNoSuchAdvertiser = errors.New("store: no such advertiser in this network")

// ObserveAdvertiser folds one client's report into an advertiser's health.
//
// The monitor's whole snapshot is persisted, not just the state. The counters are what make
// the next observation mean anything, and a state stored without them would restart every
// hysteresis window on each control-plane restart — turning a policy designed to resist
// flapping into one that flaps on deploys.
//
// The state version moves only when the state actually changed. Recomputing every agent's
// candidate order because one device sent a routine "still fine" would make a healthy
// network busier than a broken one.
func (s *Store) ObserveAdvertiser(ctx context.Context, req ObserveRequest) (health.Transition, error) {
	var out health.Transition

	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		row, err := q.GetAdvertiserForReport(ctx, dbgen.GetAdvertiserForReportParams{
			ID: req.AdvertiserID, NetworkID: req.NetworkID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchAdvertiser
		}
		if err != nil {
			return fmt.Errorf("store: loading the advertiser: %w", err)
		}

		clk := req.Clock
		if clk == nil {
			clk = clock.System{}
		}
		monitor := health.NewMonitor(health.DefaultPolicy(), clk)

		// Restored before observing, so the counters carry across restarts and across the
		// many sessions reporting about the same advertiser.
		if stored, err := q.GetAdvertiserHealth(ctx, req.AdvertiserID); err == nil {
			monitor.Restore(health.Snapshot{
				State:              health.State(stored.State),
				ConsecutiveOK:      int(stored.ConsecutiveOk),
				ConsecutiveFail:    int(stored.ConsecutiveFail),
				ConsecutivePartial: int(stored.ConsecutivePartial),
				LastImprovedAt:     timeOrZero(stored.LastImprovedAt),
				LastReportAt:       timeOrZero(stored.LastCheckedAt),
			})
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: loading advertiser health: %w", err)
		}

		// Only what a client observed. The advertiser's own self-report and a control-plane
		// probe are the other two inputs health.Report takes, and neither exists yet —
		// leaving them unknown is honest, and the monitor is built to fuse what it has.
		out = monitor.Observe(health.Report{ClientObserved: req.Observed})

		snapshot := monitor.Snapshot()
		if err := q.UpsertAdvertiserHealth(ctx, dbgen.UpsertAdvertiserHealthParams{
			AdvertiserID:       req.AdvertiserID,
			State:              string(snapshot.State),
			ConsecutiveOk:      int32(snapshot.ConsecutiveOK),
			ConsecutiveFail:    int32(snapshot.ConsecutiveFail),
			ConsecutivePartial: int32(snapshot.ConsecutivePartial),
			LastImprovedAt:     nilIfZero(snapshot.LastImprovedAt),
			LastCheckedAt:      nilIfZero(snapshot.LastReportAt),
		}); err != nil {
			return fmt.Errorf("store: storing advertiser health: %w", err)
		}

		if !out.Changed {
			return nil
		}
		// It changed, so every device's candidate order may have changed with it. This is
		// the whole point of the feature: an advertiser going unhealthy has to reach the
		// devices routing through it without them asking.
		if _, err := BumpVersion(ctx, q, row.NetworkID, RoutesChanged()); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return health.Transition{}, err
	}
	return out, nil
}

// ObserveRequest is one client's verdict on the advertiser it is using.
type ObserveRequest struct {
	NetworkID    uuid.UUID
	AdvertiserID uuid.UUID

	// Observed is what the device routing through this advertiser saw. Aggregation across
	// devices — so one laptop's broken Wi-Fi is not mistaken for a broken exit — is the
	// monitor's job, not this call's.
	Observed health.Signal

	Clock clock.Clock
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func nilIfZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
