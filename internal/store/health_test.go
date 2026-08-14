package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/health"
)

// advertiserFor returns an advertiser id for a device carrying a group.
func advertiserFor(t *testing.T, s seeded, slug string, membershipID uuid.UUID) uuid.UUID {
	t.Helper()
	if err := s.Advertise(testContext(t), AdvertiseRequest{
		NetworkID: s.netID, GroupSlug: slug, MembershipID: membershipID,
	}); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := s.pool.QueryRow(testContext(t),
		`SELECT id FROM route_advertisers WHERE membership_id = $1`, membershipID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// The signal the whole failover story rests on: devices report, the monitor fuses, and an
// advertiser that stops working stops being offered.
func TestClientReportsDriveAdvertiserHealth(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	clk := clock.NewFake()
	membershipID := addDevice()
	subnetGroup(t, s, "branch")
	advertiserID := advertiserFor(t, s, "branch", membershipID)

	// Enough consecutive failures to cross the policy's threshold. The exact number is the
	// policy's business; what matters here is that reports accumulate rather than each one
	// deciding on its own.
	var last health.Transition
	for range 10 {
		clk.Advance(time.Minute)
		got, err := s.ObserveAdvertiser(ctx, ObserveRequest{
			NetworkID: s.netID, AdvertiserID: advertiserID,
			Observed: health.SignalFail, Clock: clk,
		})
		if err != nil {
			t.Fatal(err)
		}
		last = got
	}
	if last.To == health.StateHealthy || last.To == health.StateUnknown {
		t.Fatalf("after ten failing reports the advertiser is %q", last.To)
	}

	// And it is persisted, so the next control plane to start does not begin again from
	// nothing — which would restart every hysteresis window on each deploy.
	var state string
	var fails int32
	if err := s.pool.QueryRow(ctx,
		`SELECT state, consecutive_fail FROM advertiser_health WHERE advertiser_id = $1`,
		advertiserID).Scan(&state, &fails); err != nil {
		t.Fatal(err)
	}
	if fails == 0 {
		t.Error("the counters were not persisted, so hysteresis restarts on every deploy")
	}
}

// An advertiser going unhealthy has to reach the devices routing through it without them
// asking, so the state version moves — but only when it actually changed.
func TestOnlyARealChangeMovesTheStateVersion(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	clk := clock.NewFake()
	membershipID := addDevice()
	subnetGroup(t, s, "branch")
	advertiserID := advertiserFor(t, s, "branch", membershipID)

	version := func() int64 {
		t.Helper()
		var v int64
		if err := s.pool.QueryRow(ctx,
			`SELECT state_version FROM networks WHERE id = $1`, s.netID).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Drive it to a settled state first.
	for range 10 {
		clk.Advance(time.Minute)
		if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
			NetworkID: s.netID, AdvertiserID: advertiserID,
			Observed: health.SignalFail, Clock: clk,
		}); err != nil {
			t.Fatal(err)
		}
	}

	settled := version()
	for range 5 {
		clk.Advance(time.Minute)
		transition, err := s.ObserveAdvertiser(ctx, ObserveRequest{
			NetworkID: s.netID, AdvertiserID: advertiserID,
			Observed: health.SignalFail, Clock: clk,
		})
		if err != nil {
			t.Fatal(err)
		}
		if transition.Changed {
			t.Fatal("a repeat of the same verdict was reported as a change")
		}
	}
	if after := version(); after != settled {
		t.Errorf("routine reports moved the state version %d -> %d; a healthy network "+
			"would be busier than a broken one", settled, after)
	}
}

// A device can only ever speak about advertisers in a network it belongs to. Without this
// a device in one network could steer another it cannot see.
func TestAReportAboutAnotherNetworkIsRefused(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	membershipID := addDevice()
	subnetGroup(t, s, "branch")
	advertiserID := advertiserFor(t, s, "branch", membershipID)

	if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
		NetworkID: uuid.New(), AdvertiserID: advertiserID, Observed: health.SignalFail,
	}); !errors.Is(err, ErrNoSuchAdvertiser) {
		t.Errorf("error = %v, want ErrNoSuchAdvertiser", err)
	}
	if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
		NetworkID: s.netID, AdvertiserID: uuid.New(), Observed: health.SignalFail,
	}); !errors.Is(err, ErrNoSuchAdvertiser) {
		t.Errorf("unknown advertiser: error = %v, want ErrNoSuchAdvertiser", err)
	}
}

// Health reaches selection, which is the only reason any of this exists.
func TestAnUnhealthyAdvertiserIsRankedBelowAnUnknownOne(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	clk := clock.NewFake()
	broken, fresh := addDevice(), addDevice()
	group := subnetGroup(t, s, "branch")
	brokenID := advertiserFor(t, s, "branch", broken)
	_ = advertiserFor(t, s, "branch", fresh)

	for range 10 {
		clk.Advance(time.Minute)
		if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
			NetworkID: s.netID, AdvertiserID: brokenID,
			Observed: health.SignalFail, Clock: clk,
		}); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := s.Advertisers(ctx, []uuid.UUID{group.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID != brokenID {
			continue
		}
		if row.HealthState == nil {
			t.Fatal("the failing advertiser has no health for selection to read")
		}
		if health.State(*row.HealthState).Usable() {
			t.Errorf("the failing advertiser is still usable: %q", *row.HealthState)
		}
		return
	}
	t.Fatal("the failing advertiser is no longer listed at all")
}

// The counters have to accumulate across reports, and across control-plane restarts. Each
// call builds a fresh Monitor — there is no in-memory state between them — so if the stored
// snapshot were not restored first, every observation would begin again from nothing and a
// policy designed to resist flapping would flap on every deploy.
//
// Asserted on the count rather than on the resulting state, because a state that happens to
// degrade on the first failure would hide this entirely. An earlier version of this file
// tested only the state and passed with the restore removed.
func TestCountersAccumulateAcrossReports(t *testing.T) {
	s, addDevice := seedNetwork(t)
	ctx := testContext(t)
	clk := clock.NewFake()
	membershipID := addDevice()
	subnetGroup(t, s, "branch")
	advertiserID := advertiserFor(t, s, "branch", membershipID)

	const reports = 4
	for range reports {
		clk.Advance(time.Minute)
		if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
			NetworkID: s.netID, AdvertiserID: advertiserID,
			Observed: health.SignalFail, Clock: clk,
		}); err != nil {
			t.Fatal(err)
		}
	}

	var fails int32
	if err := s.pool.QueryRow(ctx,
		`SELECT consecutive_fail FROM advertiser_health WHERE advertiser_id = $1`,
		advertiserID).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != reports {
		t.Fatalf("consecutive_fail = %d after %d failing reports; the stored counters are "+
			"not being restored, so hysteresis restarts on every report", fails, reports)
	}

	// And a success resets it, which is the other half of the same mechanism.
	clk.Advance(time.Minute)
	if _, err := s.ObserveAdvertiser(ctx, ObserveRequest{
		NetworkID: s.netID, AdvertiserID: advertiserID,
		Observed: health.SignalOK, Clock: clk,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT consecutive_fail FROM advertiser_health WHERE advertiser_id = $1`,
		advertiserID).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != 0 {
		t.Errorf("consecutive_fail = %d after a success, want 0", fails)
	}
}
