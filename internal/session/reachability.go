package session

import (
	"context"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/health"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/store"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// handleReachabilityReport folds a device's verdict on its advertiser into that
// advertiser's health.
//
// This is the signal the whole failover story rests on. The control plane can reach an
// advertiser's host and learn almost nothing: what matters is whether traffic sent through
// it arrives, and only the devices actually using it can say. So the agents report, the
// monitor fuses, and selection reorders — without anybody asking the control plane a
// question first.
//
// The network comes from the session rather than the report, so a device can only ever
// speak about advertisers in a network it belongs to. Everything else in the message is a
// claim by a device about itself, which is exactly the sort of claim to bound.
func (s *Server) handleReachabilityReport(ctx context.Context, sess *Session, report *meshpv1.ReachabilityReport) {
	advertiserID, err := uuid.Parse(report.GetAdvertiserId())
	if err != nil {
		// Not worth ending a session over. A newer agent may report about something this
		// build does not model, and the report is advisory (ADR-0008).
		s.log.Debug("ignoring a reachability report with an unusable advertiser id",
			"membership_id", sess.MembershipID)
		return
	}

	observed := health.SignalFail
	if report.GetReachable() {
		observed = health.SignalOK
	}

	transition, err := s.store.ObserveAdvertiser(ctx, store.ObserveRequest{
		NetworkID:    sess.NetworkID,
		AdvertiserID: advertiserID,
		Observed:     observed,
		Clock:        s.clk,
	})
	if err != nil {
		// Including a report about an advertiser in another network, which is refused
		// rather than acted on.
		s.log.Warn("could not record a reachability report",
			"membership_id", sess.MembershipID, "advertiser_id", advertiserID,
			"error", logx.SafeError(err))
		return
	}

	if transition.Changed {
		// Logged at info because this is the event an operator asks about six weeks later,
		// wanting to know why their traffic moved.
		s.log.Info("advertiser health changed",
			"advertiser_id", advertiserID,
			"from", string(transition.From), "to", string(transition.To),
			"reason", logx.Safe(transition.Reason),
			"reported_by", sess.MembershipID)
	}

	if from := report.GetSwitchedFromAdvertiserId(); from != "" {
		// The agent moved itself, which is what it is meant to do (ADR-0003). Recorded as a
		// decision rather than as drift: the server ordered the candidates and the agent
		// chose among them, so this is the system working.
		s.log.Info("a device moved between advertisers",
			"membership_id", sess.MembershipID,
			"from", logx.Safe(from), "to", advertiserID.String(),
			"reason", logx.Safe(report.GetSwitchReason()))
	}
}
