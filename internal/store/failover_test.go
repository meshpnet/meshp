package store

import (
	"errors"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

// The column defaults to '{"enabled": true}', and a policy that does not mention it must
// read the same way. The safe direction for an absent value is the one that lets a device
// leave a dead advertiser, because it cannot ask the control plane to move it during the
// outage most likely to have caused the problem.
func TestAnUnstatedPolicyLetsTheDeviceMove(t *testing.T) {
	for name, p := range map[string]FailoverPolicy{
		"nothing stated":  {},
		"stated true":     {Enabled: boolPtr(true)},
		"only thresholds": {FailThreshold: 2, RecoverThreshold: 5},
	} {
		if !p.MayMove() {
			t.Errorf("%s: reports that the device may not move itself", name)
		}
	}
	if (FailoverPolicy{Enabled: boolPtr(false)}).MayMove() {
		t.Error("an explicit false still lets the device move itself")
	}
}

// Round-tripping through the column has to preserve the difference between "false" and
// "not mentioned", which is the whole reason Enabled is a pointer.
func TestAPolicySurvivesTheColumn(t *testing.T) {
	for name, want := range map[string]FailoverPolicy{
		"an opt-out":      {Enabled: boolPtr(false)},
		"stated defaults": {Enabled: boolPtr(true)},
		"thresholds":      {Enabled: boolPtr(true), FailThreshold: 2, RecoverThreshold: 8, MinHoldSeconds: 120},
	} {
		raw, err := encodeFailover(want)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := decodeFailover(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.MayMove() != want.MayMove() {
			t.Errorf("%s: may_move %v, want %v", name, got.MayMove(), want.MayMove())
		}
		if got.FailThreshold != want.FailThreshold ||
			got.RecoverThreshold != want.RecoverThreshold ||
			got.MinHoldSeconds != want.MinHoldSeconds {
			t.Errorf("%s: read back %+v, want %+v", name, got, want)
		}
	}
}

// A row that will not parse is an error rather than a default. A device quietly running on
// numbers nobody wrote is indistinguishable from the policy working.
func TestAPolicyThatWillNotParseIsRefused(t *testing.T) {
	if _, err := decodeFailover([]byte(`{"enabled": "yes"`)); err == nil {
		t.Error("malformed JSON was accepted")
	}
	// An empty column is the one case that gets the schema default, because refusing would
	// take the whole route group away over a missing knob.
	got, err := decodeFailover(nil)
	if err != nil {
		t.Fatalf("an empty column was refused: %v", err)
	}
	if !got.MayMove() {
		t.Error("an empty column read as an opt-out")
	}
}

// Leaving slowly and returning quickly is backwards: a device would oscillate across a
// flapping advertiser, dropping every connection through it on each pass. Refused rather
// than corrected — silently swapping an operator's numbers is worse than telling them.
func TestABackwardsPolicyIsRefused(t *testing.T) {
	for name, p := range map[string]FailoverPolicy{
		"recovering faster than it fails": {FailThreshold: 5, RecoverThreshold: 2},
		"a threshold nobody could reach":  {FailThreshold: 5000},
		"a recover threshold as large":    {RecoverThreshold: 5000},
		"a hold measured in years":        {MinHoldSeconds: 100_000_000},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	for name, p := range map[string]FailoverPolicy{
		"equal thresholds":  {FailThreshold: 3, RecoverThreshold: 3},
		"the usual shape":   {FailThreshold: 3, RecoverThreshold: 10, MinHoldSeconds: 60},
		"nothing stated":    {},
		"only a fail count": {FailThreshold: 3},
		// Unset is not "below": it means the agent's default, which is higher than any
		// sensible fail threshold. Rejecting this would refuse the ordinary case of naming
		// one number and leaving the other alone.
		"a fail count with no recover count": {FailThreshold: 900},
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

// The policy has to survive the database, because the column is where it lives between an
// administrator writing it and an agent being sent it.
func TestTheStoredPolicyIsWhatComesBack(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)

	group := subnetGroup(t, s, "branch")
	if !group.Failover.MayMove() {
		t.Error("a group created without a policy came back as an opt-out")
	}

	updated, err := s.SetRouteGroupFailover(ctx, s.netID, "branch", FailoverPolicy{
		Enabled: boolPtr(false), FailThreshold: 2, RecoverThreshold: 20, MinHoldSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Failover.MayMove() {
		t.Error("the opt-out did not stick")
	}
	if updated.Failover.FailThreshold != 2 || updated.Failover.RecoverThreshold != 20 ||
		updated.Failover.MinHoldSeconds != 300 {
		t.Errorf("stored %+v", updated.Failover)
	}
	// And the prefixes came back with it, rather than the group losing them on an edit that
	// had nothing to do with them.
	if len(updated.Prefixes) != 1 {
		t.Errorf("%d prefixes after setting the policy, want 1", len(updated.Prefixes))
	}

	groups, err := s.RouteGroupsFor(ctx, s.netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Failover.MayMove() {
		t.Errorf("read back %+v", groups)
	}
}

// How patient a device is about moving is desired state, so a change has to be logged for
// agents to collect rather than sitting in a column nothing sends.
func TestSettingThePolicyTellsAgents(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)
	subnetGroup(t, s, "branch")

	var before int64
	if err := s.pool.QueryRow(ctx,
		`SELECT state_version FROM networks WHERE id = $1`, s.netID).Scan(&before); err != nil {
		t.Fatal(err)
	}

	if _, err := s.SetRouteGroupFailover(ctx, s.netID, "branch",
		FailoverPolicy{Enabled: boolPtr(true), FailThreshold: 2}); err != nil {
		t.Fatal(err)
	}

	var kind string
	var version int64
	if err := s.pool.QueryRow(ctx,
		`SELECT kind, version FROM state_changes WHERE network_id = $1 ORDER BY id DESC LIMIT 1`,
		s.netID).Scan(&kind, &version); err != nil {
		t.Fatalf("no change was logged: %v", err)
	}
	if kind != "routes" {
		t.Errorf("logged kind = %q, want routes", kind)
	}
	if version <= before {
		t.Errorf("the change was logged at version %d, which is not past %d", version, before)
	}
}

// A typo in a slug is told from a change, rather than reported as a success that stored
// nothing.
func TestSettingThePolicyOnAnUnknownGroupIsRefused(t *testing.T) {
	s, _ := seedNetwork(t)

	_, err := s.SetRouteGroupFailover(testContext(t), s.netID, "nope", DefaultFailoverPolicy())
	if !errors.Is(err, ErrNoSuchRouteGroup) {
		t.Errorf("err = %v, want ErrNoSuchRouteGroup", err)
	}
}

// A policy that cannot behave is refused before it is stored, not after — otherwise the
// group is left holding numbers the API has already said no to.
func TestABackwardsPolicyIsNotStored(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)
	subnetGroup(t, s, "branch")

	if _, err := s.SetRouteGroupFailover(ctx, s.netID, "branch",
		FailoverPolicy{FailThreshold: 5, RecoverThreshold: 2}); err == nil {
		t.Fatal("a backwards policy was stored")
	}

	groups, err := s.RouteGroupsFor(ctx, s.netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Failover.FailThreshold != 0 {
		t.Errorf("the refused policy was stored anyway: %+v", groups[0].Failover)
	}
}
