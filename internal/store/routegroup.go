package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// slugPattern is what a network or route group may be called in a URL.
var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// ErrNoSuchRouteGroup means the group named does not exist in that network.
var ErrNoSuchRouteGroup = errors.New("store: no such route group in this network")

// RouteGroupKinds are the three shapes one primitive covers (ADR-0001).
//
// Internet egress, a LAN gateway and a service gateway differ only in what prefixes they
// carry: they share advertisers, health, priority and failover, so they share a table.
// Splitting them would mean writing that machinery three times and having it drift.
const (
	KindEgress  = "egress"
	KindSubnet  = "subnet"
	KindService = "service"
)

// RouteGroup is a set of prefixes and the devices that may carry them.
type RouteGroup struct {
	ID        uuid.UUID
	NetworkID uuid.UUID
	Slug      string
	Name      string
	Kind      string

	SelectionMode        string
	AutoFailback         bool
	FailbackDelaySeconds int32

	// StableEgressIP is the address traffic keeps across a failover, for customers who have
	// allowlisted an outbound IP with a bank or a vendor. Nil when the egress address may
	// change, which is the ordinary case.
	StableEgressIP *netip.Addr

	// Failover is how patient devices should be about moving between this group's
	// advertisers. Handed to agents rather than acted on here: the agent is the only thing
	// that can see whether a path works, and it has to keep deciding during a control-plane
	// outage (ADR-0003).
	Failover FailoverPolicy

	Prefixes []netip.Prefix
}

// CreateRouteGroupRequest describes a group to create.
type CreateRouteGroupRequest struct {
	NetworkID uuid.UUID
	Slug      string
	Name      string
	Kind      string
	Prefixes  []netip.Prefix

	SelectionMode        string
	AutoFailback         bool
	FailbackDelaySeconds int32
	StableEgressIP       *netip.Addr
	Failover             FailoverPolicy
}

// CreateRouteGroup stores a group and its prefixes.
//
// In one transaction with the state-version bump, for the same reason every other mutation
// is: a group stored without a logged change reaches no agent until something unrelated
// moves the version, and a logged change with no group tells every agent to recompute
// against something that is not there.
func (s *Store) CreateRouteGroup(ctx context.Context, req CreateRouteGroupRequest) (RouteGroup, error) {
	if err := validateSlug("route group", req.Slug); err != nil {
		return RouteGroup{}, err
	}
	if err := validateKind(req.Kind, req.Prefixes); err != nil {
		return RouteGroup{}, err
	}
	if err := req.Failover.Validate(); err != nil {
		return RouteGroup{}, err
	}
	failover, err := encodeFailover(req.Failover)
	if err != nil {
		return RouteGroup{}, err
	}

	var out RouteGroup
	err = s.InTx(ctx, func(q *dbgen.Queries) error {
		mode := req.SelectionMode
		if mode == "" {
			mode = "failover"
		}
		row, err := q.CreateRouteGroup(ctx, dbgen.CreateRouteGroupParams{
			NetworkID:            req.NetworkID,
			Slug:                 req.Slug,
			Name:                 orSlug(req.Name, req.Slug),
			Kind:                 req.Kind,
			SelectionMode:        mode,
			AutoFailback:         req.AutoFailback,
			FailbackDelaySeconds: req.FailbackDelaySeconds,
			StableEgressIp:       req.StableEgressIP,
			LocalFailover:        failover,
		})
		if err != nil {
			return fmt.Errorf("store: creating the route group: %w", err)
		}

		for _, prefix := range req.Prefixes {
			if err := q.AddRouteGroupPrefix(ctx, dbgen.AddRouteGroupPrefixParams{
				RouteGroupID: row.ID,
				Prefix:       prefix.Masked(),
			}); err != nil {
				return fmt.Errorf("store: adding prefix %s: %w", prefix, err)
			}
		}

		if _, err := BumpVersion(ctx, q, req.NetworkID, RoutesChanged()); err != nil {
			return err
		}

		out, err = routeGroupFrom(row, req.Prefixes)
		return err
	})
	if err != nil {
		return RouteGroup{}, err
	}
	return out, nil
}

// AdvertiseRequest offers a device as a carrier for a group.
type AdvertiseRequest struct {
	NetworkID    uuid.UUID
	GroupSlug    string
	MembershipID uuid.UUID

	// Priority orders advertisers. Lower is preferred, and equal priorities share load.
	Priority int32
	Weight   int32

	// AdminState is enabled, draining or disabled. Draining keeps the devices already using
	// this advertiser and refuses new ones, which is how maintenance happens without
	// dropping anybody.
	AdminState string

	Region, City, Provider string
}

// Advertise records that a device may carry a group's prefixes.
func (s *Store) Advertise(ctx context.Context, req AdvertiseRequest) error {
	if req.Weight <= 0 {
		req.Weight = 100
	}
	if req.AdminState == "" {
		req.AdminState = "enabled"
	}
	switch req.AdminState {
	case "enabled", "draining", "disabled":
	default:
		return invalid("admin state %q is not enabled, draining or disabled", req.AdminState)
	}

	return s.InTx(ctx, func(q *dbgen.Queries) error {
		group, err := q.GetRouteGroupBySlug(ctx, dbgen.GetRouteGroupBySlugParams{
			NetworkID: req.NetworkID, Slug: req.GroupSlug,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchRouteGroup
		}
		if err != nil {
			return fmt.Errorf("store: loading the route group: %w", err)
		}

		if _, err := q.UpsertRouteAdvertiser(ctx, dbgen.UpsertRouteAdvertiserParams{
			RouteGroupID: group.ID,
			MembershipID: req.MembershipID,
			Priority:     req.Priority,
			Weight:       req.Weight,
			AdminState:   req.AdminState,
			Region:       req.Region,
			City:         req.City,
			Provider:     req.Provider,
		}); err != nil {
			return fmt.Errorf("store: recording the advertiser: %w", err)
		}

		// Who carries a prefix is desired state for every device in the network, not only
		// for the advertiser: everyone else has to be told where to send that traffic.
		_, err = BumpVersion(ctx, q, req.NetworkID, RoutesChanged())
		return err
	})
}

// Withdraw stops a device advertising for a group.
func (s *Store) Withdraw(ctx context.Context, networkID uuid.UUID, groupSlug string, membershipID uuid.UUID) error {
	return s.InTx(ctx, func(q *dbgen.Queries) error {
		group, err := q.GetRouteGroupBySlug(ctx, dbgen.GetRouteGroupBySlugParams{
			NetworkID: networkID, Slug: groupSlug,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchRouteGroup
		}
		if err != nil {
			return fmt.Errorf("store: loading the route group: %w", err)
		}

		rows, err := q.DeleteRouteAdvertiser(ctx, dbgen.DeleteRouteAdvertiserParams{
			RouteGroupID: group.ID, MembershipID: membershipID,
		})
		if err != nil {
			return fmt.Errorf("store: removing the advertiser: %w", err)
		}
		if rows == 0 {
			return ErrNoSuchRouteGroup
		}
		_, err = BumpVersion(ctx, q, networkID, RoutesChanged())
		return err
	})
}

// DeleteRouteGroup removes a group and everything that advertised it.
func (s *Store) DeleteRouteGroup(ctx context.Context, networkID uuid.UUID, slug string) error {
	return s.InTx(ctx, func(q *dbgen.Queries) error {
		rows, err := q.DeleteRouteGroup(ctx, dbgen.DeleteRouteGroupParams{
			NetworkID: networkID, Slug: slug,
		})
		if err != nil {
			return fmt.Errorf("store: deleting the route group: %w", err)
		}
		if rows == 0 {
			return ErrNoSuchRouteGroup
		}
		_, err = BumpVersion(ctx, q, networkID, RoutesChanged())
		return err
	})
}

// RouteGroupsFor returns a network's groups with their prefixes.
func (s *Store) RouteGroupsFor(ctx context.Context, networkID uuid.UUID) ([]RouteGroup, error) {
	rows, err := s.queries.ListRouteGroups(ctx, networkID)
	if err != nil {
		return nil, fmt.Errorf("store: listing route groups: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	prefixRows, err := s.queries.ListRouteGroupPrefixes(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("store: listing route group prefixes: %w", err)
	}
	byGroup := make(map[uuid.UUID][]netip.Prefix, len(rows))
	for _, p := range prefixRows {
		byGroup[p.RouteGroupID] = append(byGroup[p.RouteGroupID], p.Prefix)
	}

	out := make([]RouteGroup, 0, len(rows))
	for _, row := range rows {
		group, err := routeGroupFrom(dbgen.CreateRouteGroupRow(row), byGroup[row.ID])
		if err != nil {
			// Named, because the error itself says only that some JSON would not parse and
			// an operator needs to know which group to go and look at.
			return nil, fmt.Errorf("store: route group %s: %w", row.Slug, err)
		}
		out = append(out, group)
	}
	return out, nil
}

// SetRouteGroupFailover replaces a group's local failover policy.
//
// Whole rather than field by field: the numbers only mean anything together, and a partial
// update is how an operator ends up with a combination nobody chose — a fail threshold of
// one from today's edit beside a recover threshold left over from last month's.
//
// In one transaction with the version bump, like every other route mutation. How patient a
// device is about moving is desired state for that device, so it has to be logged for agents
// to collect rather than sitting in a column nothing sends.
func (s *Store) SetRouteGroupFailover(ctx context.Context, networkID uuid.UUID, slug string, policy FailoverPolicy) (RouteGroup, error) {
	if err := policy.Validate(); err != nil {
		return RouteGroup{}, err
	}
	raw, err := encodeFailover(policy)
	if err != nil {
		return RouteGroup{}, err
	}

	var out RouteGroup
	err = s.InTx(ctx, func(q *dbgen.Queries) error {
		row, err := q.SetRouteGroupFailover(ctx, dbgen.SetRouteGroupFailoverParams{
			NetworkID: networkID, Slug: slug, LocalFailover: raw,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchRouteGroup
		}
		if err != nil {
			return fmt.Errorf("store: recording the failover policy: %w", err)
		}

		prefixes, err := q.ListRouteGroupPrefixes(ctx, []uuid.UUID{row.ID})
		if err != nil {
			return fmt.Errorf("store: listing route group prefixes: %w", err)
		}
		carried := make([]netip.Prefix, 0, len(prefixes))
		for _, p := range prefixes {
			carried = append(carried, p.Prefix)
		}

		out, err = routeGroupFrom(dbgen.CreateRouteGroupRow(row), carried)
		if err != nil {
			return err
		}

		// Written unconditionally, unlike the fail-closed opt-out, which skips the bump when
		// nothing changed. Comparing two policies for equality means deciding whether an
		// absent threshold equals an explicit default, and getting that wrong drops a real
		// edit silently. A route policy is changed by hand and rarely; a redundant delta
		// costs one reconcile per device, and the reconciler is idempotent by construction
		// (Invariant 18), so it costs nothing else.
		_, err = BumpVersion(ctx, q, networkID, RoutesChanged())
		return err
	})
	if err != nil {
		return RouteGroup{}, err
	}
	return out, nil
}

// Advertisers returns everything the selector needs about who may carry these groups.
func (s *Store) Advertisers(ctx context.Context, groupIDs []uuid.UUID) ([]dbgen.ListRouteAdvertisersRow, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	rows, err := s.queries.ListRouteAdvertisers(ctx, groupIDs)
	if err != nil {
		return nil, fmt.Errorf("store: listing advertisers: %w", err)
	}
	return rows, nil
}

// CreateNetwork makes a network, so standing one up does not require psql.
func (s *Store) CreateNetwork(ctx context.Context, orgID uuid.UUID, slug, name string, pools []netip.Prefix) (dbgen.CreateNetworkRow, error) {
	if err := validateSlug("network", slug); err != nil {
		return dbgen.CreateNetworkRow{}, err
	}

	var out dbgen.CreateNetworkRow
	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		row, err := q.CreateNetwork(ctx, dbgen.CreateNetworkParams{
			OrganizationID: orgID, Slug: slug, Name: orSlug(name, slug),
		})
		if err != nil {
			return fmt.Errorf("store: creating the network: %w", err)
		}
		for _, pool := range pools {
			family := int16(4)
			if pool.Addr().Is6() {
				family = 6
			}
			if _, err := q.CreateAddressPool(ctx, dbgen.CreateAddressPoolParams{
				NetworkID: row.ID, Prefix: pool.Masked(), Family: family, Purpose: "device",
			}); err != nil {
				return fmt.Errorf("store: adding address pool %s: %w", pool, err)
			}
		}
		out = row
		return nil
	})
	if err != nil {
		return dbgen.CreateNetworkRow{}, err
	}
	return out, nil
}

func routeGroupFrom(row dbgen.CreateRouteGroupRow, prefixes []netip.Prefix) (RouteGroup, error) {
	failover, err := decodeFailover(row.LocalFailover)
	if err != nil {
		return RouteGroup{}, err
	}
	return RouteGroup{
		ID: row.ID, NetworkID: row.NetworkID, Slug: row.Slug, Name: row.Name, Kind: row.Kind,
		SelectionMode:        row.SelectionMode,
		AutoFailback:         row.AutoFailback,
		FailbackDelaySeconds: row.FailbackDelaySeconds,
		StableEgressIP:       row.StableEgressIp,
		Failover:             failover,
		Prefixes:             prefixes,
	}, nil
}

func validateSlug(what, slug string) error {
	if !slugPattern.MatchString(slug) {
		return invalid(
			"%q is not a usable %s name; use lowercase letters, digits and hyphens", slug, what)
	}
	return nil
}

// validateKind checks that a group's prefixes match what its kind means.
//
// An egress group carries the default route and nothing else, because "send everything
// through this device" and "send this subnet through this device" are different decisions
// with different blast radii — and a group that quietly did both would be the more
// dangerous one wearing the safer one's name.
func validateKind(kind string, prefixes []netip.Prefix) error {
	switch kind {
	case KindEgress:
		if len(prefixes) != 0 {
			return invalid(
				"an egress group carries the default route and takes no prefixes of its own")
		}
	case KindSubnet, KindService:
		if len(prefixes) == 0 {
			return invalid("a %s group needs at least one prefix to carry", kind)
		}
		for _, p := range prefixes {
			if p.Bits() == 0 {
				return invalid(
					"%s is the default route; advertise it as an egress group rather than a %s one",
					p, kind)
			}
		}
	default:
		return invalid("%q is not one of egress, subnet, service", kind)
	}
	return nil
}

func orSlug(name, slug string) string {
	if strings.TrimSpace(name) == "" {
		return slug
	}
	return name
}
