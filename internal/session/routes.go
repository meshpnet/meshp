package session

import (
	"context"

	"net/netip"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/health"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/routes"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// routeGroupsFor computes what this device should be told about carried prefixes.
//
// The server owns the set of candidates and their order; the agent decides only which are
// alive (ADR-0003). That split is why a candidate list is sent rather than a single answer:
// an agent that has to ask the control plane before failing over cannot fail over during a
// control-plane outage, which is exactly when it is most likely to need to.
//
// A device is never offered itself. An advertiser reaching its own group through the mesh
// would be routing its own LAN traffic into a tunnel that comes back out of the same
// machine, which at best is a loop and at worst takes the site off the internet.
// Groups that exist and produce no assignment for this device come back as withdrawn ids
// rather than as silence. Proto3 cannot tell an empty repeated field from an absent one, so
// "you are assigned nothing" and "nothing about routes changed" would otherwise be the same
// message — and a device that lost its last advertiser would keep routing to it forever.
func (b *StateBuilder) routeGroupsFor(ctx context.Context, membership dbgen.GetMembershipForSessionRow) (assigned []*meshpv1.RouteGroupAssignment, withdrawn []string, advertised *meshpv1.AdvertisedRoutes, err error) {
	groups, err := b.store.RouteGroupsFor(ctx, membership.NetworkID)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(groups) == 0 {
		// Absent rather than empty. A network with no route groups has never asked this
		// device to forward anything, which is not the same as having asked and stopped.
		return nil, nil, nil, nil
	}

	ids := make([]uuid.UUID, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	advertiserRows, err := b.store.Advertisers(ctx, ids)
	if err != nil {
		return nil, nil, nil, err
	}

	byGroup := make(map[uuid.UUID][]dbgen.ListRouteAdvertisersRow, len(groups))
	for _, row := range advertiserRows {
		byGroup[row.RouteGroupID] = append(byGroup[row.RouteGroupID], row)
	}

	// Where colliding prefixes are reached, for this device (ADR-0020). Asked once for the
	// whole device rather than per group, because the collision is a property of the device
	// — it is two of *its* networks carrying the same prefix — and no single group can see
	// it.
	//
	// A failure here is not a reason to send no routes. It means colliding prefixes keep the
	// refusal they have today, which is the behaviour this replaces rather than a regression
	// on it, while everything uncontested still reaches the device.
	mapped, err := b.store.EnsureMappings(ctx, membership.DeviceID, store.DefaultMappedBlock)
	if err != nil {
		b.log.Error("a colliding prefix could not be given a range to be reached by",
			"device_id", membership.DeviceID, "error", logx.SafeError(err),
			"consequence", "route groups carrying it stay refused on devices that hold two of them")
	}
	mappedFor := mappedByNetwork(mapped, membership.NetworkID)

	// Present, and possibly empty. A device that carried a prefix and no longer does has to
	// be told so, and an empty list inside a present message says exactly that — while
	// proto3 cannot tell an empty repeated field from an absent one, which is why this is a
	// message rather than a repeated field on the delta.
	advertised = &meshpv1.AdvertisedRoutes{}

	for _, group := range groups {
		if carried := carriedBy(group, byGroup[group.ID], membership.MembershipID); carried != nil {
			advertised.Groups = append(advertised.Groups, carried)
		}

		candidates := selectFor(group, byGroup[group.ID], membership.MembershipID)
		if len(candidates) == 0 {
			// A group with nobody to carry it is not an assignment. Sending one with an
			// empty candidate list would have every agent install a route to nowhere, which
			// blackholes the prefix instead of leaving it alone — so it is withdrawn, which
			// says the same thing without the route.
			withdrawn = append(withdrawn, group.ID.String())
			continue
		}
		assigned = append(assigned, assignmentFor(group, candidates, mappedFor))
	}
	return assigned, withdrawn, advertised, nil
}

// carriedBy reports what this device must forward for a group, or nothing.
//
// Only an enabled or draining advertiser forwards. Draining still does, because it keeps
// the devices already using it and refuses new ones — a draining advertiser that stopped
// forwarding would drop every session it was meant to be letting finish, which is the
// opposite of what draining is for.
func carriedBy(group store.RouteGroup, rows []dbgen.ListRouteAdvertisersRow, self uuid.UUID) *meshpv1.AdvertisedRoutes_Group {
	for _, row := range rows {
		if row.MembershipID != self {
			continue
		}
		if routes.AdminState(row.AdminState) == routes.AdminDisabled {
			// Disabled means stop, and stopping has to reach the advertiser too. Leaving it
			// forwarding while nobody is steered at it is a path that works by accident.
			return nil
		}

		carried := &meshpv1.AdvertisedRoutes_Group{
			RouteGroupId: group.ID.String(),
			Name:         group.Name,
		}
		if group.Kind == store.KindEgress {
			carried.Prefixes = []string{"0.0.0.0/0", "::/0"}
		} else {
			for _, prefix := range group.Prefixes {
				carried.Prefixes = append(carried.Prefixes, prefix.String())
			}
		}
		if group.StableEgressIP != nil {
			carried.StableEgressIp = group.StableEgressIP.String()
		}
		return carried
	}
	return nil
}

// selectFor orders one group's advertisers for one device.
func selectFor(group store.RouteGroup, rows []dbgen.ListRouteAdvertisersRow, self uuid.UUID) []routes.Candidate {
	advertisers := make([]routes.Advertiser, 0, len(rows))
	for _, row := range rows {
		if row.MembershipID == self {
			continue
		}
		advertisers = append(advertisers, routes.Advertiser{
			ID:            row.ID.String(),
			PeerPublicKey: row.WireguardPublicKey,
			Priority:      int(row.Priority),
			Weight:        int(row.Weight),
			Admin:         routes.AdminState(row.AdminState),
			Health:        healthOf(row.HealthState),
			Region:        row.Region,
			City:          row.City,
			DisplayName:   row.DeviceName,
		})
	}
	if len(advertisers) == 0 {
		return nil
	}

	return routes.Select(routes.Request{
		// Keyed by the device, so two devices offered the same equal-priority advertisers
		// are spread between them rather than both landing on whichever sorts first.
		DeviceKey:   self.String(),
		Mode:        routes.Mode(group.SelectionMode),
		Advertisers: advertisers,
	})
}

// healthOf reads what the health table recorded, treating an absent row as unknown.
//
// Unknown is selectable and ranks last. On a fresh deployment every advertiser is unknown,
// and refusing to offer any of them would mean no egress at all until checks accumulate —
// while the agent probes a candidate before using it, so proposing an untested one cannot
// break a device.
func healthOf(state *string) health.State {
	if state == nil {
		return health.StateUnknown
	}
	return health.State(*state)
}

func assignmentFor(group store.RouteGroup, candidates []routes.Candidate, mapped map[netip.Prefix]netip.Prefix) *meshpv1.RouteGroupAssignment {
	assignment := &meshpv1.RouteGroupAssignment{
		RouteGroupId: group.ID.String(),
		Name:         group.Name,
		Mode:         modeOf(group.SelectionMode),
		LocalFailover: &meshpv1.LocalFailoverPolicy{
			// Enabled is stated rather than omitted. Proto3 cannot tell an absent bool from
			// false, so a policy that left it out would reach the agent as "this device may
			// not move itself" — the opposite of the column's default, and a fleet that sits
			// on dead advertisers waiting for a control plane that may be the thing that
			// failed.
			Enabled:          group.Failover.MayMove(),
			FailThreshold:    group.Failover.FailThreshold,
			RecoverThreshold: group.Failover.RecoverThreshold,
			MinHoldSeconds:   group.Failover.MinHoldSeconds,

			// What the device dials to find out whether the path through the advertiser
			// works. Empty is the ordinary case and means the agent falls back to whether
			// the advertiser's tunnel is up — which catches a gateway that is off, and not
			// one whose own uplink has failed.
			ProbeTargets:    group.Failover.ProbeTargets,
			ProbeQuorum:     group.Failover.ProbeQuorum,
			ProbeIntervalMs: group.Failover.ProbeIntervalMS,
		},
	}

	// An egress group carries the default route rather than prefixes of its own, which is
	// why the store refuses to let it hold any: the two families are named here so an agent
	// claiming a default route claims it for both.
	if group.Kind == store.KindEgress {
		assignment.Prefixes = []string{"0.0.0.0/0", "::/0"}
	} else {
		for _, prefix := range group.Prefixes {
			assignment.Prefixes = append(assignment.Prefixes, prefix.String())
		}
	}

	// Only the prefixes this group actually carries, and only the ones that collide. A
	// device is told where to reach a customer it cannot reach directly, and nothing else:
	// a mapped address is a thing a person has to know about, so one handed out for a
	// prefix nobody contests is a cost paid for nothing.
	for _, prefix := range group.Prefixes {
		to, ok := mapped[prefix.Masked()]
		if !ok {
			continue
		}
		assignment.MappedPrefixes = append(assignment.MappedPrefixes,
			&meshpv1.RouteGroupAssignment_MappedPrefix{Prefix: prefix.String(), Mapped: to.String()})
	}

	if group.StableEgressIP != nil {
		assignment.StableEgressIp = group.StableEgressIP.String()
	}

	for _, candidate := range candidates {
		assignment.Candidates = append(assignment.Candidates, &meshpv1.RouteCandidate{
			AdvertiserId:  candidate.ID,
			PeerPublicKey: candidate.PeerPublicKey,
			Priority:      uint32(candidate.Priority),
			Weight:        uint32(candidate.Weight),
			ServerHealth:  healthTo(candidate.Admin, candidate.Health),
			Region:        candidate.Region,
			City:          candidate.City,
			DisplayName:   candidate.DisplayName,
		})
	}
	return assignment
}

func modeOf(mode string) meshpv1.RouteGroupAssignment_Mode {
	if mode == string(routes.ModePinned) {
		return meshpv1.RouteGroupAssignment_MODE_PINNED
	}
	return meshpv1.RouteGroupAssignment_MODE_FAILOVER
}

// healthTo renders the server's view for the agent.
//
// Draining is reported in the health field rather than alongside it, because to an agent
// choosing a candidate the two mean the same thing: prefer somebody else, and keep working
// if you are already here. Splitting them would give the agent a second axis to reason
// about and no different action to take.
func healthTo(admin routes.AdminState, state health.State) meshpv1.RouteCandidate_Health {
	if admin == routes.AdminDraining {
		return meshpv1.RouteCandidate_HEALTH_DRAINING
	}
	switch state {
	case health.StateHealthy:
		return meshpv1.RouteCandidate_HEALTH_HEALTHY
	case health.StateDegraded:
		return meshpv1.RouteCandidate_HEALTH_DEGRADED
	case health.StateUnhealthy:
		return meshpv1.RouteCandidate_HEALTH_UNHEALTHY
	case health.StateOffline:
		return meshpv1.RouteCandidate_HEALTH_OFFLINE
	default:
		// Unknown maps to unspecified rather than to healthy. The agent probes before
		// using a candidate, so it does not need to be told an untested one is fine — and
		// telling it so would be a claim the control plane cannot support.
		return meshpv1.RouteCandidate_HEALTH_UNSPECIFIED
	}
}

// mappedByNetwork narrows a device's mappings to the network this state is being built for.
//
// The device's mappings span every network it is in, and each membership's state must carry
// only its own: telling a device that customer B's prefix is reached at 100.71.6.0/24 while
// building customer A's routes would put a range on A's interface that belongs to B's.
func mappedByNetwork(mappings []store.PrefixMapping, network uuid.UUID) map[netip.Prefix]netip.Prefix {
	if len(mappings) == 0 {
		return nil
	}
	out := make(map[netip.Prefix]netip.Prefix, len(mappings))
	for _, m := range mappings {
		if m.NetworkID != network {
			continue
		}
		out[m.Prefix.Masked()] = m.Mapped
	}
	return out
}
