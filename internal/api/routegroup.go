package api

import (
	"errors"
	"net/http"
	"net/netip"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/store"
)

// handleCreateRouteGroup makes a set of prefixes and the devices that may carry them.
//
// One primitive for internet egress, a LAN gateway and a service gateway (ADR-0001): they
// differ only in what prefixes they carry, and they share advertisers, health, priority and
// failover. Three separate features would mean writing that machinery three times.
func (s *Server) handleCreateRouteGroup(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	var body struct {
		Slug                 string          `json:"slug"`
		Name                 string          `json:"name"`
		Kind                 string          `json:"kind"`
		Prefixes             []string        `json:"prefixes"`
		SelectionMode        string          `json:"selection_mode"`
		AutoFailback         *bool           `json:"auto_failback"`
		FailbackDelaySeconds int32           `json:"failback_delay_seconds"`
		StableEgressIP       string          `json:"stable_egress_ip"`
		LocalFailover        *failoverPolicy `json:"local_failover"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	req := store.CreateRouteGroupRequest{
		NetworkID:            networkID,
		Slug:                 body.Slug,
		Name:                 body.Name,
		Kind:                 body.Kind,
		SelectionMode:        body.SelectionMode,
		AutoFailback:         body.AutoFailback == nil || *body.AutoFailback,
		FailbackDelaySeconds: body.FailbackDelaySeconds,
		// Stated rather than left zero. A zero FailoverPolicy behaves identically — Enabled
		// is a pointer and nil already means "may move" — but the row it stores is `{}`,
		// and somebody reading this table wants to see what the group's policy is without
		// having to know which absences are which.
		Failover: store.DefaultFailoverPolicy(),
	}
	if body.LocalFailover != nil {
		req.Failover = body.LocalFailover.toStore()
	}
	for _, raw := range body.Prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
				"prefix "+raw+" is not a CIDR")
			return
		}
		req.Prefixes = append(req.Prefixes, prefix)
	}
	if body.StableEgressIP != "" {
		addr, err := netip.ParseAddr(body.StableEgressIP)
		if err != nil {
			httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
				"stable_egress_ip is not an address")
			return
		}
		req.StableEgressIP = &addr
	}

	group, err := s.store.CreateRouteGroup(r.Context(), req)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	s.log.Info("route group created",
		"network_id", networkID, "slug", group.Slug, "kind", group.Kind,
		"prefixes", len(group.Prefixes))

	// Who carries a prefix is desired state for every device, so everyone needs telling.
	s.tellNetwork(networkID)
	httpx.WriteJSON(w, s.log, http.StatusCreated, renderGroup(group))
}

func (s *Server) handleListRouteGroups(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	groups, err := s.store.RouteGroupsFor(r.Context(), networkID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		out = append(out, renderGroup(g))
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"route_groups": out})
}

func (s *Server) handleDeleteRouteGroup(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	slug := r.PathValue("slug")

	err := s.store.DeleteRouteGroup(r.Context(), networkID, slug)
	if errors.Is(err, store.ErrNoSuchRouteGroup) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found", "no such route group in this network")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	// Same reasoning as handleAdvertise: this slug names a group to look up rather than
	// one to create, so nothing has checked its shape.
	s.log.Info("route group deleted", "network_id", networkID, "slug", logx.Safe(slug))
	s.tellNetwork(networkID)
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleAdvertise offers a device as a carrier for a group.
//
// An advertiser is a role a device plays, never a separate kind of machine: the same laptop
// that is a peer can carry a branch office's subnet, and stopping is a withdrawal rather
// than a rebuild.
func (s *Server) handleAdvertise(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	slug := r.PathValue("slug")

	var body struct {
		MembershipID string `json:"membership_id"`
		Priority     int32  `json:"priority"`
		Weight       int32  `json:"weight"`
		AdminState   string `json:"admin_state"`
		Region       string `json:"region"`
		City         string `json:"city"`
		Provider     string `json:"provider"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	membershipID, err := uuid.Parse(body.MembershipID)
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "membership_id must be a UUID")
		return
	}

	err = s.store.Advertise(r.Context(), store.AdvertiseRequest{
		NetworkID: networkID, GroupSlug: slug, MembershipID: membershipID,
		Priority: body.Priority, Weight: body.Weight, AdminState: body.AdminState,
		Region: body.Region, City: body.City, Provider: body.Provider,
	})
	if errors.Is(err, store.ErrNoSuchRouteGroup) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found", "no such route group in this network")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	// Through logx.Safe: the slug comes from the URL path, and an unvalidated one reaching
	// a log line lets whoever chose it write their own entries. Validated slugs elsewhere
	// in this file cannot contain a newline; this one has not been through the store's
	// pattern, because looking a group up does not require it to be well formed.
	s.log.Info("advertiser recorded",
		"network_id", networkID, "slug", logx.Safe(slug), "membership_id", membershipID,
		"priority", body.Priority)
	s.tellNetwork(networkID)
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]string{"status": "advertising"})
}

func (s *Server) handleWithdraw(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	membershipID, ok := s.pathUUID(w, r, "membershipID")
	if !ok {
		return
	}

	err := s.store.Withdraw(r.Context(), networkID, r.PathValue("slug"), membershipID)
	if errors.Is(err, store.ErrNoSuchRouteGroup) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found",
			"no such route group, or that device was not advertising for it")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	s.tellNetwork(networkID)
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]string{"status": "withdrawn"})
}

// handleCreateNetwork stands up a network, so doing it does not require psql.
func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrganizationID string   `json:"organization_id"`
		Slug           string   `json:"slug"`
		Name           string   `json:"name"`
		AddressPools   []string `json:"address_pools"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	// A person belongs to one organisation and a machine acts within its owner's, so
	// neither has to name one. Only the administrative token does, because it belongs to
	// no organisation at all.
	mine := callerOrganization(callerFrom(r))
	orgID, err := uuid.Parse(body.OrganizationID)
	if body.OrganizationID == "" && mine != nil {
		orgID, err = *mine, nil
	}
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"organization_id must be a UUID, or omitted to use your own organisation")
		return
	}
	// The permission that got this request here was held over the caller's own organisation,
	// so it authorises a network in that one and no other. Without this check the guard would
	// be asking about one tenant and the handler writing to another.
	if mine != nil && orgID != *mine {
		httpx.Error(w, s.log, http.StatusForbidden, "forbidden",
			"you may only create networks in your own organisation")
		return
	}

	var pools []netip.Prefix
	for _, raw := range body.AddressPools {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
				"address pool "+raw+" is not a CIDR")
			return
		}
		pools = append(pools, prefix)
	}
	if len(pools) == 0 {
		// Refused rather than defaulted. A network with no pool enrols nobody, and the
		// failure would surface as an enrolment that cannot allocate an address rather than
		// as the missing configuration it is.
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"a network needs at least one address pool; devices are given addresses from it")
		return
	}

	network, err := s.store.CreateNetwork(r.Context(), orgID, body.Slug, body.Name, pools)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	s.log.Info("network created", "network_id", network.ID, "slug", network.Slug)
	httpx.WriteJSON(w, s.log, http.StatusCreated, map[string]any{
		"network_id": network.ID,
		"slug":       network.Slug,
		"name":       network.Name,
	})
}

func renderGroup(g store.RouteGroup) map[string]any {
	prefixes := make([]string, 0, len(g.Prefixes))
	for _, p := range g.Prefixes {
		prefixes = append(prefixes, p.String())
	}
	out := map[string]any{
		"id":                     g.ID,
		"slug":                   g.Slug,
		"name":                   g.Name,
		"kind":                   g.Kind,
		"prefixes":               prefixes,
		"selection_mode":         g.SelectionMode,
		"auto_failback":          g.AutoFailback,
		"failback_delay_seconds": g.FailbackDelaySeconds,
		"local_failover":         renderFailover(g.Failover),
	}
	if g.StableEgressIP != nil {
		out["stable_egress_ip"] = g.StableEgressIP.String()
	}
	return out
}
