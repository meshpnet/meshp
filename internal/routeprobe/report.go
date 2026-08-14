package routeprobe

import (
	"sort"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// This file is the other half of the failover loop. Deciding locally is what lets a device
// leave a dead advertiser during a control-plane outage (ADR-0003), but a decision nobody
// hears about only helps the device that made it. The control plane fuses reports from every
// device using an advertiser and reorders the candidates it hands out — so one device's
// observation is what stops the next device from being sent to the same dead gateway.
//
// Only what the chooser judged worth reporting is queued: a change, or the first verdict for
// a group. Two reasons, and the second is the load-bearing one.
//
// A healthy network should be quieter than a broken one, or the reports arrive in the volume
// that makes them useless. And the server folds each report as one observation of that
// advertiser, so a device that reported on a timer would supply evidence in proportion to
// how long it had been running rather than to what it had seen. Ten queued repeats of "still
// fine" would clear a recovery threshold of ten on their own.
//
// The same argument decides the shape of the queue: **one report per group, newest wins.**
// A backlog draining after a reconnection is exactly the inflation described above, and it
// would arrive at the worst moment — when a device has just been out of touch and the server
// is least sure what is true. Superseding instead means a reconnecting device says what it
// believes now, once, which is all it actually knows.

// recordLocked queues a verdict for the control plane, replacing any unsent one.
//
// Called with the lock held, from Observe.
func (c *Chooser) recordLocked(groupID string, decision Decision, result Result) {
	report := &meshpv1.ReachabilityReport{
		RouteGroupId:             groupID,
		AdvertiserId:             decision.Current,
		Reachable:                result.Reachable,
		RttMs:                    millis(result),
		ConsecutiveFailures:      uint32(decision.ConsecutiveFailures),
		SwitchedFromAdvertiserId: decision.Switched,
		SwitchReason:             decision.Reason,
	}

	// A switch that has not been sent yet is carried forward rather than dropped, so long
	// as the newer verdict is about the same advertiser and records no move of its own.
	// The device is still on that advertiser having moved to it, so saying so stays true —
	// and the alternative loses the one line an operator goes looking for six weeks later
	// when they want to know why their traffic moved.
	if previous, ok := c.pending[groupID]; ok && decision.Switched == "" &&
		previous.GetSwitchedFromAdvertiserId() != "" &&
		previous.GetAdvertiserId() == report.GetAdvertiserId() {
		report.SwitchedFromAdvertiserId = previous.GetSwitchedFromAdvertiserId()
		report.SwitchReason = previous.GetSwitchReason()
	}

	c.pending[groupID] = report
}

// Pending takes the reports waiting to be sent, in a stable order.
//
// Taking rather than copying: whatever is handed back is the caller's to deliver, and a
// caller that cannot deliver hands it back with Requeue.
func (c *Chooser) Pending() []*meshpv1.ReachabilityReport {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.pending) == 0 {
		return nil
	}
	out := make([]*meshpv1.ReachabilityReport, 0, len(c.pending))
	for _, report := range c.pending {
		out = append(out, report)
	}
	clear(c.pending)
	sort.Slice(out, func(i, j int) bool {
		return out[i].GetRouteGroupId() < out[j].GetRouteGroupId()
	})
	return out
}

// Requeue puts back reports that could not be sent.
//
// A group with a newer verdict keeps the newer one. Returning something to the queue must
// not be a way for a stale report to win, or a stuck writer would end up telling the control
// plane that a gateway which has since failed is fine.
//
// Worth having rather than dropping on the floor: the reports that fail to send are the ones
// produced while something is already wrong, which is when the control plane most needs
// them.
func (c *Chooser) Requeue(reports []*meshpv1.ReachabilityReport) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, report := range reports {
		if report == nil {
			continue
		}
		if _, newer := c.pending[report.GetRouteGroupId()]; newer {
			continue
		}
		c.pending[report.GetRouteGroupId()] = report
	}
}

// millis converts a round-trip time for the wire, clamped into what the field can hold.
//
// A handshake-derived probe reports zero, meaning "not measured". Nothing branches on it.
func millis(result Result) uint32 {
	ms := result.RTT.Milliseconds()
	if ms <= 0 {
		return 0
	}
	const maxUint32 = int64(^uint32(0))
	if ms > maxUint32 {
		return uint32(maxUint32)
	}
	return uint32(ms)
}
