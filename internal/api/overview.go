package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/session"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// Presence answers which memberships are talking to this control plane right now.
//
// An interface here rather than a call into the hub, because liveness is per-process today
// and will not be: ADR-0012 puts it behind a Redis implementation for the multi-replica
// case. Naming the dependency now means that arrives as a swap rather than as a change to
// this handler. It is deliberately the smallest thing the endpoint needs — one question,
// answered for one network, sampled once.
type Presence interface {
	NetworkPresence(networkID uuid.UUID) []session.Connected
}

// maxOverviewDevices bounds what the caller may ask for.
//
// The limit exists because this response is built in one transaction and held in memory
// twice over, and an unbounded one is a way to make the control plane do arbitrary work by
// asking politely. A caller wanting more than this wants a different endpoint, and should
// say so rather than discovering the ceiling by hitting it.
const maxOverviewDevices = 5000

// handleNetworkOverview answers "is anything in this network unreachable, and what is
// carrying for it", in one response describing one instant.
//
// The whole question in one round trip, rather than a page assembling it from several. Two
// polls half a second apart show devices from one instant beside route groups from another,
// which renders states that never existed — a device down and the group it advertises for
// healthy. The database work happens in one transaction and presence is sampled once, and
// `as_of` says when that was so a stale page can be seen to be stale rather than read as
// current.
func (s *Server) handleNetworkOverview(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	limit, ok := s.overviewLimit(w, r)
	if !ok {
		return
	}

	// Sampled before the transaction rather than after. Both orders are defensible and
	// neither is atomic — presence does not live in the database — so the one that errs
	// toward reporting a device as disconnected is chosen: a device that connected during
	// the read shows as down for one poll, which corrects itself, where the other order
	// would report a device as connected after its session had gone.
	connected := make(map[uuid.UUID]session.Connected)
	if s.presence != nil {
		for _, c := range s.presence.NetworkPresence(networkID) {
			connected[c.MembershipID] = c
		}
	}

	overview, err := s.store.NetworkOverview(r.Context(), networkID, limit)
	if errors.Is(err, store.ErrNoSuchNetwork) {
		// A 404 rather than an empty overview, which would render as a real network with
		// nothing in it — and "this customer has no devices" is a very different thing to
		// read at a glance than "you are looking at the wrong network".
		httpx.Error(w, s.log, http.StatusNotFound, "no_such_network", "no such network")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	// One instant for the whole response: as_of, and whatever the fault rules compare
	// against. Calling the clock twice would let a device be judged against a moment the
	// response does not claim to describe.
	now := s.cfg.Clock.Now().UTC()
	faultCount := 0

	devices := make([]map[string]any, 0, len(overview.Devices))
	for _, d := range overview.Devices {
		device := map[string]any{
			"membership_id": d.MembershipID,
			"device_id":     d.DeviceID,
			"device_name":   d.DeviceName,
			"state":         d.State,
			"joined_at":     d.JoinedAt,
			// Always present, and always a list. A page that has to distinguish absent from
			// empty before it can decide whether a device is healthy will get it wrong once.
			"unapplied_components": append([]string{}, d.Unapplied...),
			"applied_version":      d.AppliedVersion,
			"connected":            false,
		}

		// Connected here, or connected to another replica. The database knows the second
		// and only this process knows the first, so the answer is the union — before this,
		// a control plane reported the devices attached to itself and called the rest
		// disconnected, which on a two-replica deployment is roughly half of them.
		c, live := connected[d.MembershipID]
		if live || d.ConnectedSince != nil {
			device["connected"] = true
			device["connected_since"] = d.ConnectedSince
		}

		if live {
			// This replica is holding the session, so it has what the device last said.
			device["connected_since"] = c.ConnectedAt
			// The agent's own number, beside the database's. They disagree while an
			// acknowledgement is in flight, and a reader chasing a device that looks stuck
			// needs to see which of the two is behind.
			device["reported_version"] = c.AppliedVersion

			// What the device says about its own data plane, absent until it has said
			// something. Absent and "no peers" are different answers and only one of them
			// is worth rendering, so the field is omitted rather than zeroed: a device that
			// has not reported yet must not read as a device with nothing configured.
			//
			// Counts rather than a verdict. Whether this adds up to a problem is #116's
			// question, and answering it here would settle that by accident.
			if !c.Tunnel.ReportedAt.IsZero() {
				device["tunnel"] = map[string]any{
					"reported_at": c.Tunnel.ReportedAt.UTC(),
					"peers":       c.Tunnel.Peers,
					"handshaked":  c.Tunnel.Handshaked,
					"talking":     c.Tunnel.Talking,
					"relayed":     c.Tunnel.Relayed,
				}
			}
		} else if device["connected"] == true {
			// Held by another replica. Said rather than left to be inferred from a missing
			// tunnel field, which a reader would otherwise take for "this device has not
			// reported yet" — a device that has been talking to the replica next door for
			// an hour is not the same as one that has never said anything, and only one of
			// them is worth investigating.
			//
			// ADR-0012 keeps the per-heartbeat detail in the process that received it, so
			// there is genuinely nothing to show here. Reporting the absence honestly is
			// the whole of what this control plane can do about that.
			device["reported_by"] = "another_replica"
		}
		if d.AddressV4 != nil {
			device["address_v4"] = d.AddressV4.String()
		}
		if d.AddressV6 != nil {
			device["address_v6"] = d.AddressV6.String()
		}
		if d.RevokedAt != nil {
			device["revoked_at"] = d.RevokedAt
		}
		if d.LastAckAt != nil {
			device["last_ack_at"] = d.LastAckAt
		}
		if d.LastError != "" {
			device["last_error"] = d.LastError
		}

		// What is wrong with it, decided here rather than by whoever is rendering
		// (ADR-0023). Always present and always a list, so a consumer never has to tell
		// absent from empty before it can decide whether to raise an alarm.
		var held *session.Connected
		if live {
			held = &c
		}
		faults := deviceFaults(d, held, d.ConnectedSince != nil, now)
		device["faults"] = faults
		faultCount += len(faults)

		devices = append(devices, device)
	}

	groups := make([]map[string]any, 0, len(overview.Groups))
	for _, g := range overview.Groups {
		advertisers := make([]map[string]any, 0, len(g.Advertisers))
		for _, a := range g.Advertisers {
			advertiser := map[string]any{
				"membership_id": a.MembershipID,
				"device_name":   a.DeviceName,
				"priority":      a.Priority,
				"weight":        a.Weight,
				"admin_state":   a.AdminState,
				// "unknown" rather than an empty string or an omitted field, because the
				// three readings of a missing health state are not the same and only one of
				// them is true: nobody has reported on this advertiser yet. Rendering that
				// as healthy would make a group that has never worked look fine.
				"health":    healthOrUnknown(a.Health),
				"connected": false,
				// Whether this candidate could carry anything at all, decided by the same
				// rule that decides whether the group has a fault. A consumer marking
				// unusable candidates must not have to derive it a second time and reach a
				// different answer (ADR-0023 §5).
				"viable": viableAdvertiser(a),
				// How many devices report routing through this one. The nearest thing to
				// "which candidate is carrying" that exists: the agent chooses (ADR-0003),
				// so this is a count of what agents have said, not a decision anybody made.
				"in_use_by": a.InUseBy,
			}
			if _, live := connected[a.MembershipID]; live {
				advertiser["connected"] = true
			}
			if a.Region != "" {
				advertiser["region"] = a.Region
			}
			if a.City != "" {
				advertiser["city"] = a.City
			}
			advertisers = append(advertisers, advertiser)
		}

		prefixes := make([]string, 0, len(g.Prefixes))
		for _, p := range g.Prefixes {
			prefixes = append(prefixes, p.String())
		}
		groupTrouble := groupFaults(g)
		faultCount += len(groupTrouble)

		group := map[string]any{
			"faults":         groupTrouble,
			"id":             g.ID,
			"slug":           g.Slug,
			"name":           g.Name,
			"kind":           g.Kind,
			"prefixes":       prefixes,
			"selection_mode": g.SelectionMode,
			"advertisers":    advertisers,
		}
		if g.StableEgressIP != nil {
			group["stable_egress_ip"] = g.StableEgressIP.String()
		}
		groups = append(groups, group)
	}

	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		// The instant everything below describes. Rendered by the page, so a poll that
		// failed makes it visibly stale rather than leaving old numbers looking current.
		"as_of": now,
		"network": map[string]any{
			"id":            overview.NetworkID,
			"slug":          overview.Slug,
			"name":          overview.Name,
			"state_version": overview.StateVersion,
		},
		"devices":           devices,
		"devices_truncated": overview.DevicesTruncated,
		"route_groups":      groups,
		// Every fault in the network, counted once. A roll-up drawing forty tiles should
		// not have to walk forty device lists to put a number on each one (ADR-0023).
		"fault_count": faultCount,
		// The server decides how often it is asked, so a deployment under load can slow
		// its pages down without shipping a new one.
		"poll_after_seconds": int(overviewPollInterval / time.Second),
	})
}

// overviewPollInterval is how long a page should wait before asking again.
const overviewPollInterval = 5 * time.Second

// handleListNetworks answers what networks the caller can see.
//
// The caller's own organisation, not every network this control plane holds. Until
// permissions existed this returned all of them to anybody who was signed in, which on a
// deployment with more than one tenant was a list of other people's networks — the kind of
// leak that is invisible in development, where there is only ever one.
//
// The administrative token belongs to no organisation and still sees everything, which is
// what it is for (ADR-0024 §5) and what keeps a deployment operator able to answer "what is
// on this box".
func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	var (
		rows []dbgen.ListAllNetworksRow
		err  error
	)
	if user := callerFrom(r).user; user != nil {
		var scoped []dbgen.ListNetworksForOrganizationWithCountsRow
		scoped, err = s.store.Queries().ListNetworksForOrganizationWithCounts(r.Context(), user.OrganizationID)
		for _, row := range scoped {
			rows = append(rows, dbgen.ListAllNetworksRow(row))
		}
	} else {
		rows, err = s.store.Queries().ListAllNetworks(r.Context())
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id":                  row.ID,
			"slug":                row.Slug,
			"name":                row.Name,
			"organization_id":     row.OrganizationID,
			"organization_slug":   row.OrganizationSlug,
			"state_version":       row.StateVersion,
			"created_at":          row.CreatedAt,
			"active_device_count": row.ActiveDeviceCount,
		})
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"networks": out})
}

// overviewLimit reads ?devices=, which exists so a caller can ask for less rather than more.
func (s *Server) overviewLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("devices")
	if raw == "" {
		return store.DefaultOverviewDevices, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"devices must be a positive whole number")
		return 0, false
	}
	if n > maxOverviewDevices {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"devices may be at most "+strconv.Itoa(maxOverviewDevices))
		return 0, false
	}
	return n, true
}

func healthOrUnknown(state string) string {
	if state == "" {
		return "unknown"
	}
	return state
}
