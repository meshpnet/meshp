package store

import (
	"context"
	"encoding/json"
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

		// What this device says it is using, which nothing recorded until now. ADR-0003
		// splits authority — the server owns authorisation and order, the agent owns
		// liveness — and says the server records what the agent chose. This is that half.
		//
		// Written whether or not health changed, because a device can move between
		// candidates without any advertiser's health moving: an agent that finds its first
		// choice slow and switches has changed the answer to "what is carrying this" while
		// changing nobody's health state.
		if req.MembershipID != uuid.Nil {
			version, err := q.UpsertRouteAssignment(ctx, dbgen.UpsertRouteAssignmentParams{
				MembershipID: req.MembershipID,
				RouteGroupID: row.RouteGroupID,
				AdvertiserID: &req.AdvertiserID,
				Reason:       req.Reason,
			})
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				// The same choice as last time, which is most reports. Nothing moved, so
				// there is nothing to audit.
			case err != nil:
				return fmt.Errorf("store: recording the route assignment: %w", err)
			case version > 1:
				// A device moved between candidates. ADR-0003 completes here: the server
				// records what the agent chose and emits an audit event, treating it as
				// something that happened rather than as drift to be corrected.
				//
				// Version 1 is deliberately not audited. That is a device recording a
				// choice for the first time, which happens on every enrolment and
				// describes nothing going wrong.
				if err := auditRouteSwitch(ctx, q, req, row.RouteGroupID); err != nil {
					return err
				}
			}
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

	// MembershipID names the device doing the reporting, so its choice can be written down
	// alongside the health that choice produced.
	//
	// Zero on a caller that has only an advertiser to talk about, which skips the recording
	// rather than guessing at a membership. Recorded in the same transaction as the health
	// on purpose: the two come from one message, and split across transactions they could
	// disagree about which candidate a device is using at the moment somebody looks.
	//
	// There is deliberately no route group here. The agent names one in its report, and
	// taking it would let a device file an advertiser from one group as its choice in
	// another — nothing ties advertiser_id to route_group_id in the schema, so the pair
	// would simply be wrong and would stay wrong. The group is read from the advertiser
	// instead, which is scoped to the session's network and is the only version of the
	// answer this end can vouch for.
	MembershipID uuid.UUID

	// Reason is the agent's own account of why it chose this candidate, kept verbatim. It
	// is what answers "why did my outbound IP change?" six weeks later, and rewriting it
	// here would lose the only description that came from the machine that decided.
	Reason string

	// DeviceID is who is reporting, recorded as the actor when a move is audited. An
	// agent's failover is a device's action, not the control plane's — ADR-0003 gives the
	// choice to the agent — so attributing it to "system" would name the wrong actor for
	// the one decision here that nobody at the control plane made.
	DeviceID uuid.UUID

	// SwitchedFrom is the candidate the agent says it moved away from, kept for the audit
	// record. The agent's claim rather than a lookup: the row it replaced is gone by the
	// time this is written, and the two would agree anyway except in the case where the
	// agent's account is the interesting one.
	SwitchedFrom string

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

// auditRouteSwitch writes down that a device moved itself between candidates.
//
// In the transaction that recorded the move, for the reason revocation gives: a change that
// committed while its audit record was rolled back is one nobody can account for afterwards.
//
// Costs two extra reads, and only ever on a move. Both are lookups this call does not
// otherwise need — the organisation the event is filed under, and the device's name — and a
// move is rare enough that paying for them here is cheaper than carrying them through every
// routine report that changes nothing.
func auditRouteSwitch(ctx context.Context, q *dbgen.Queries, req ObserveRequest, groupID uuid.UUID) error {
	network, err := q.GetNetwork(ctx, req.NetworkID)
	if err != nil {
		return fmt.Errorf("store: reading the network for a route audit event: %w", err)
	}

	// The name, so the log reads as "hq-gateway moved" rather than as a pair of UUIDs. An
	// audit trail nobody can read without three joins is one nobody reads.
	label := ""
	if device, err := q.GetDevice(ctx, req.DeviceID); err == nil {
		label = device.Name
	}

	metadata, _ := json.Marshal(map[string]any{
		"advertiser_id":  req.AdvertiserID.String(),
		"switched_from":  req.SwitchedFrom,
		"reason":         req.Reason,
		"membership_id":  req.MembershipID.String(),
		"route_group_id": groupID.String(),
	})

	networkID := req.NetworkID
	actorID := req.DeviceID
	orgID := network.OrganizationID
	if _, err := q.CreateAuditEvent(ctx, dbgen.CreateAuditEventParams{
		OrganizationID: &orgID,
		NetworkID:      &networkID,
		// Not "system". The schema's comment on that value predates ADR-0003, which moved
		// the choice to the agent: this is a device reporting something it did, and filing
		// it under the control plane would credit the wrong actor.
		ActorKind:    "device",
		ActorID:      &actorID,
		ActorLabel:   label,
		Action:       "route.switched",
		ResourceKind: "route_group",
		ResourceID:   &groupID,
		Metadata:     metadata,
	}); err != nil {
		return fmt.Errorf("store: writing the route switch audit event: %w", err)
	}
	return nil
}
