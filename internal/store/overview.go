package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// DefaultOverviewDevices is how many devices one overview carries when the caller does not
// say.
//
// A bound rather than a page. The question this answers is "is anything here broken", which
// a second page cannot answer — an operator who has to click through four of them to find
// the one red device has been given a list, not a view. So the limit is set where a network
// larger than it is unusual, and a response that hits it says so rather than pretending.
const DefaultOverviewDevices = 500

// OverviewDevice is one membership and what it last told the control plane.
type OverviewDevice struct {
	MembershipID uuid.UUID
	DeviceID     uuid.UUID
	DeviceName   string
	State        string
	AddressV4    *netip.Addr
	AddressV6    *netip.Addr
	JoinedAt     time.Time
	RevokedAt    *time.Time

	// AppliedVersion is the version the database recorded, which is not necessarily what
	// the agent has applied: an acknowledgement reaches the hub before it is written.
	// Presence carries the other number, and the two disagreeing is ordinary.
	AppliedVersion int64
	LastAckAt      *time.Time
	LastError      string

	// Unapplied is what this device told the control plane it could not do. It has been
	// written on every acknowledgement since the first migration and read by nothing until
	// now, which is why a device that cannot filter, or cannot carry what it advertises,
	// has been invisible to everyone but whoever was logged into it.
	Unapplied []string

	// ConnectedSince is when a control session was opened, by whichever replica is holding
	// it. Nil when no session is open anywhere.
	//
	// The shared half of liveness. What a device *reports* — an applied version, a path
	// report — arrives on every heartbeat and stays in the process that received it
	// (ADR-0012); whether the session exists changes only when a device connects or goes
	// away, which is cheap enough to keep where every replica can see it.
	ConnectedSince *time.Time
}

// OverviewAdvertiser is one device offering to carry a route group's prefixes.
type OverviewAdvertiser struct {
	// ID is the advertiser row, which is what an assignment names. Not the membership: one
	// device can advertise for several groups, so the two are not interchangeable here.
	ID uuid.UUID

	MembershipID uuid.UUID
	DeviceName   string
	Priority     int32
	Weight       int32
	AdminState   string
	Region       string
	City         string

	// InUseBy is how many devices currently report routing through this candidate.
	//
	// An observation, not an instruction. ADR-0003 gives the agent the choice, so this is
	// the count of agents that have said what they chose — which is the closest thing to
	// "which candidate is carrying this" that exists, and it did not exist at all until
	// something started recording what devices report.
	//
	// Zero is not "not carrying". A device that has never sent a reachability report has
	// nothing recorded, and a group whose devices are all quiet reads as zero everywhere.
	InUseBy int64

	// Health is what the control plane has been told about this advertiser, and is empty
	// when it has been told nothing. Empty is not healthy: an advertiser nobody has
	// reported on has never been proven to carry anything, and rendering that as working
	// would make a group that has never worked look fine.
	Health string
}

// OverviewGroup is a route group with the devices offering to carry it.
type OverviewGroup struct {
	RouteGroup
	Advertisers []OverviewAdvertiser
}

// NetworkOverview is one network at one instant.
type NetworkOverview struct {
	NetworkID    uuid.UUID
	Slug         string
	Name         string
	StateVersion int64

	Devices []OverviewDevice
	Groups  []OverviewGroup

	// DevicesTruncated reports that this network holds more devices than the response
	// carries. Present from the first version of this type on purpose: a consumer that
	// paginates by not paginating cannot be told later that it should have been, so the
	// marker has to exist before anybody is relying on its absence.
	DevicesTruncated bool
}

// NetworkOverview reads everything one view of a network needs, at one instant.
//
// In a single transaction, which is the whole point. Assembled from separate reads it would
// render a state that never existed — a device shown as down beside the route group it
// advertises for shown as healthy, because the two were read either side of a change. That
// is the same silent wrong answer this project refuses for colliding prefixes (ADR-0020)
// and for ambiguous names (ADR-0021), and it is worse here because it is the screen
// somebody is looking at while deciding whether anything is wrong.
//
// Liveness is deliberately absent. It does not live in the database (ADR-0012), so it is
// sampled by the caller and joined on; putting it here would mean this function either
// reaching into a process's memory or lying about what a transaction can guarantee.
func (s *Store) NetworkOverview(ctx context.Context, networkID uuid.UUID, deviceLimit int) (NetworkOverview, error) {
	if deviceLimit <= 0 {
		deviceLimit = DefaultOverviewDevices
	}

	var out NetworkOverview
	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		network, err := q.GetNetwork(ctx, networkID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoSuchNetwork
			}
			return fmt.Errorf("store: reading the network: %w", err)
		}
		out.NetworkID = network.ID
		out.Slug = network.Slug
		out.Name = network.Name
		out.StateVersion = network.StateVersion

		// One more than asked for, so a full page and an overflowing one can be told apart
		// without a second count query inside the transaction.
		rows, err := q.ListNetworkOverviewDevices(ctx, dbgen.ListNetworkOverviewDevicesParams{
			NetworkID: networkID,
			Limit:     int32(deviceLimit) + 1, //nolint:gosec // bounded by the caller below
		})
		if err != nil {
			return fmt.Errorf("store: listing the network's devices: %w", err)
		}
		if len(rows) > deviceLimit {
			out.DevicesTruncated = true
			rows = rows[:deviceLimit]
		}
		out.Devices = make([]OverviewDevice, 0, len(rows))
		for _, row := range rows {
			device := OverviewDevice{
				MembershipID: row.MembershipID,
				DeviceID:     row.DeviceID,
				DeviceName:   row.DeviceName,
				State:        row.State,
				AddressV4:    row.AddressV4,
				AddressV6:    row.AddressV6,
				JoinedAt:     row.JoinedAt,
				RevokedAt:    row.RevokedAt,
				LastAckAt:    row.LastAckAt,
				Unapplied:    row.UnappliedComponents,

				// Set by whichever replica is holding the session, so this is true across
				// all of them rather than only for the one being asked.
				ConnectedSince: row.ConnectedSince,
			}
			// Nil where a membership has never opened a session and so has no state row.
			// Zero is the right reading of that — it has applied nothing — and it is also
			// what the column defaults to once the row exists, so the two agree.
			if row.AppliedVersion != nil {
				device.AppliedVersion = *row.AppliedVersion
			}
			if row.LastError != nil {
				device.LastError = *row.LastError
			}
			out.Devices = append(out.Devices, device)
		}

		groups, err := q.ListRouteGroups(ctx, networkID)
		if err != nil {
			return fmt.Errorf("store: listing route groups: %w", err)
		}
		if len(groups) == 0 {
			return nil
		}
		ids := make([]uuid.UUID, 0, len(groups))
		for _, g := range groups {
			ids = append(ids, g.ID)
		}
		prefixRows, err := q.ListRouteGroupPrefixes(ctx, ids)
		if err != nil {
			return fmt.Errorf("store: listing route group prefixes: %w", err)
		}
		prefixes := make(map[uuid.UUID][]netip.Prefix, len(groups))
		for _, p := range prefixRows {
			prefixes[p.RouteGroupID] = append(prefixes[p.RouteGroupID], p.Prefix)
		}

		advertiserRows, err := q.ListRouteAdvertisers(ctx, ids)
		if err != nil {
			return fmt.Errorf("store: listing route advertisers: %w", err)
		}
		// How many devices say they are using each candidate. Read in the same transaction
		// as everything else, so the counts describe the same instant as the health beside
		// them — a candidate shown as unhealthy and carrying forty devices is a real state,
		// and one assembled from two instants would not be.
		assignmentRows, err := q.CountRouteAssignments(ctx, ids)
		if err != nil {
			return fmt.Errorf("store: counting route assignments: %w", err)
		}
		inUse := make(map[uuid.UUID]int64, len(assignmentRows))
		for _, row := range assignmentRows {
			if row.AdvertiserID != nil {
				inUse[*row.AdvertiserID] = row.Devices
			}
		}

		advertisers := make(map[uuid.UUID][]OverviewAdvertiser, len(groups))
		for _, a := range advertiserRows {
			entry := OverviewAdvertiser{
				ID:           a.ID,
				InUseBy:      inUse[a.ID],
				MembershipID: a.MembershipID,
				DeviceName:   a.DeviceName,
				Priority:     a.Priority,
				Weight:       a.Weight,
				AdminState:   a.AdminState,
				Region:       a.Region,
				City:         a.City,
			}
			if a.HealthState != nil {
				entry.Health = *a.HealthState
			}
			advertisers[a.RouteGroupID] = append(advertisers[a.RouteGroupID], entry)
		}

		out.Groups = make([]OverviewGroup, 0, len(groups))
		for _, row := range groups {
			group, err := routeGroupFrom(dbgen.CreateRouteGroupRow(row), prefixes[row.ID])
			if err != nil {
				// Named, because the error says only that some JSON would not parse and
				// whoever reads it needs to know which group to go and look at.
				return fmt.Errorf("store: route group %s: %w", row.Slug, err)
			}
			out.Groups = append(out.Groups, OverviewGroup{
				RouteGroup:  group,
				Advertisers: advertisers[row.ID],
			})
		}
		return nil
	})
	if err != nil {
		return NetworkOverview{}, err
	}
	return out, nil
}
