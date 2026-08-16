package api

import (
	"errors"
	"net/http"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/store"
)

// failoverPolicy is how an administrator writes a route group's local failover policy.
//
// Every field is a pointer, so "not mentioned" is told from "set to zero". It matters
// differently for each: an absent `enabled` must mean the default rather than false, since
// false is the setting that stops a device leaving a dead advertiser; and an absent threshold
// must mean the agent's default rather than zero, since zero would be a device that moves
// before it has probed anything.
type failoverPolicy struct {
	Enabled          *bool   `json:"enabled"`
	FailThreshold    *uint32 `json:"fail_threshold"`
	RecoverThreshold *uint32 `json:"recover_threshold"`
	MinHoldSeconds   *uint32 `json:"min_hold_seconds"`

	// ProbeTargets is a pointer to a slice so that an explicit empty list is told from an
	// absent one. Both end up storing nothing, but only one of them is somebody deciding to
	// stop probing, and the log line should be able to say which.
	ProbeTargets    *[]string `json:"probe_targets"`
	ProbeQuorum     *uint32   `json:"probe_quorum"`
	ProbeIntervalMS *uint32   `json:"probe_interval_ms"`
}

func (p failoverPolicy) toStore() store.FailoverPolicy {
	out := store.DefaultFailoverPolicy()
	if p.Enabled != nil {
		enabled := *p.Enabled
		out.Enabled = &enabled
	}
	if p.FailThreshold != nil {
		out.FailThreshold = *p.FailThreshold
	}
	if p.RecoverThreshold != nil {
		out.RecoverThreshold = *p.RecoverThreshold
	}
	if p.MinHoldSeconds != nil {
		out.MinHoldSeconds = *p.MinHoldSeconds
	}
	if p.ProbeTargets != nil {
		out.ProbeTargets = *p.ProbeTargets
	}
	if p.ProbeQuorum != nil {
		out.ProbeQuorum = *p.ProbeQuorum
	}
	if p.ProbeIntervalMS != nil {
		out.ProbeIntervalMS = *p.ProbeIntervalMS
	}
	return out
}

// renderFailover is what the API says a group's policy is.
//
// The stored numbers verbatim, zeros included, rather than the defaults the agent would
// apply in their place. An operator reading this back needs to know what is written down: a
// response that showed 3 where nothing is stored would make an unset field look like a
// decision, and the next person to raise the agent's default would be surprised twice.
func renderFailover(p store.FailoverPolicy) map[string]any {
	targets := p.ProbeTargets
	if targets == nil {
		// An empty array rather than null, so a client can iterate what comes back without
		// a special case for the group nobody has configured.
		targets = []string{}
	}
	return map[string]any{
		"enabled":           p.MayMove(),
		"fail_threshold":    p.FailThreshold,
		"recover_threshold": p.RecoverThreshold,
		"min_hold_seconds":  p.MinHoldSeconds,
		"probe_targets":     targets,
		"probe_quorum":      p.ProbeQuorum,
		"probe_interval_ms": p.ProbeIntervalMS,
	}
}

// handleSetRouteGroupFailover replaces a group's local failover policy.
//
// A PUT of the whole policy rather than a PATCH of parts. The numbers only mean anything
// together — a fail threshold of one beside a recover threshold left from a previous edit is
// a device that moves on the first lost packet and takes ten successes to come back — so
// anything not named here goes back to its default rather than keeping whatever was there.
func (s *Server) handleSetRouteGroupFailover(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	slug := r.PathValue("slug")

	var body failoverPolicy
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	group, err := s.store.SetRouteGroupFailover(r.Context(), networkID, slug, body.toStore())
	if errors.Is(err, store.ErrNoSuchRouteGroup) {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found", "no such route group in this network")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	// Through logx.Safe for the reason handleAdvertise gives: this slug names a group to look
	// up rather than one to create, so nothing has checked its shape.
	s.log.Info("failover policy recorded",
		"network_id", networkID, "slug", logx.Safe(slug),
		"enabled", group.Failover.MayMove(),
		"fail_threshold", group.Failover.FailThreshold,
		"recover_threshold", group.Failover.RecoverThreshold,
		"min_hold_seconds", group.Failover.MinHoldSeconds,
		"probe_targets", len(group.Failover.ProbeTargets))

	// How patient a device is about moving is desired state for every device that carries
	// this group, so everyone needs telling.
	s.tellNetwork(networkID)
	httpx.WriteJSON(w, s.log, http.StatusOK, renderGroup(group))
}
