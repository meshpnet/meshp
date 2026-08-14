package session

import (
	"context"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/health"
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
func (b *StateBuilder) routeGroupsFor(ctx context.Context, membership dbgen.GetMembershipForSessionRow) (assigned []*meshpv1.RouteGroupAssignment, withdrawn []string, err error) {
	groups, err := b.store.RouteGroupsFor(ctx, membership.NetworkID)
	if err != nil {
		return nil, nil, err
	}
	if len(groups) == 0 {
		return nil, nil, nil
	}

	ids := make([]uuid.UUID, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	advertiserRows, err := b.store.Advertisers(ctx, ids)
	if err != nil {
		return nil, nil, err
	}

	byGroup := make(map[uuid.UUID][]dbgen.ListRouteAdvertisersRow, len(groups))
	for _, row := range advertiserRows {
		byGroup[row.RouteGroupID] = append(byGroup[row.RouteGroupID], row)
	}

	for _, group := range groups {
		candidates := selectFor(group, byGroup[group.ID], membership.MembershipID)
		if len(candidates) == 0 {
			// A group with nobody to carry it is not an assignment. Sending one with an
			// empty candidate list would have every agent install a route to nowhere, which
			// blackholes the prefix instead of leaving it alone — so it is withdrawn, which
			// says the same thing without the route.
			withdrawn = append(withdrawn, group.ID.String())
			continue
		}
		assigned = append(assigned, assignmentFor(group, candidates))
	}
	return assigned, withdrawn, nil
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

func assignmentFor(group store.RouteGroup, candidates []routes.Candidate) *meshpv1.RouteGroupAssignment {
	assignment := &meshpv1.RouteGroupAssignment{
		RouteGroupId: group.ID.String(),
		Name:         group.Name,
		Mode:         modeOf(group.SelectionMode),
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
