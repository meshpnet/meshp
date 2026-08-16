package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// A tunnel change is about every device at once, so it names none — and it is exactly one
// sort of thing, so a Change that claims to be two is refused rather than silently written
// as whichever the switch happened to reach first.
func TestTunnelChangeNamesNoPeer(t *testing.T) {
	kind, err := TunnelChanged().kind()
	if err != nil || kind != "tunnel" {
		t.Fatalf("kind = %q, %v", kind, err)
	}

	id := uuid.New()
	key := "a-key"
	for name, change := range map[string]Change{
		"a tunnel change naming a peer":         {Tunnel: true, MembershipID: &id},
		"a tunnel change naming a removed key":  {Tunnel: true, PeerPublicKey: &key},
		"both a tunnel and a policy change":     {Tunnel: true, Policy: true},
		"both a tunnel and a route change":      {Tunnel: true, Routes: true},
		"a change that says it is three things": {Tunnel: true, Routes: true, Policy: true},
	} {
		if _, err := change.kind(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The column exists so an administrator can answer ADR-0011, and the answer has to survive
// being written and read back. A network nobody has configured enforces.
func TestEgressFailClosedDefaultsToEnforcing(t *testing.T) {
	s, _ := seedNetwork(t)

	enforced, err := s.EgressFailClosed(testContext(t), s.netID)
	if err != nil {
		t.Fatal(err)
	}
	if !enforced {
		t.Error("a network nobody has configured does not enforce")
	}
}

// The write and the version bump share a transaction, so a stored answer is always one that
// has been logged for agents to collect. Checked through the log rather than through the
// version alone: a bump with nothing logged produces a delta with a number and no contents,
// which every agent acknowledges while continuing to enforce the old answer.
func TestOptingOutLogsAChangeAgentsCanSee(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)

	changed, err := s.SetEgressFailClosed(ctx, s.netID, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("the first write reported no change")
	}

	var kind string
	var version int64
	if err := s.pool.QueryRow(ctx,
		`SELECT kind, version FROM state_changes WHERE network_id = $1 ORDER BY id DESC LIMIT 1`,
		s.netID).Scan(&kind, &version); err != nil {
		t.Fatalf("no change was logged: %v", err)
	}
	if kind != "tunnel" {
		t.Errorf("logged kind = %q, want tunnel", kind)
	}

	var head int64
	if err := s.pool.QueryRow(ctx,
		`SELECT state_version FROM networks WHERE id = $1`, s.netID).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if version != head {
		t.Errorf("the change was logged at version %d while the network is at %d", version, head)
	}
}

// Writing the value a network already holds must not bump anything. Every agent would
// otherwise be handed a delta for a reconfiguration that did not happen.
func TestWritingTheSameAnswerLogsNothing(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)

	if _, err := s.SetEgressFailClosed(ctx, s.netID, false); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM state_changes WHERE network_id = $1`, s.netID).Scan(&before); err != nil {
		t.Fatal(err)
	}

	changed, err := s.SetEgressFailClosed(ctx, s.netID, false)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("writing the same answer reported a change")
	}

	var after int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM state_changes WHERE network_id = $1`, s.netID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("%d changes logged for a write that changed nothing", after-before)
	}
}

// A network that is not there is told apart from one that is, rather than reported as a
// success that stored nothing.
func TestSettingItOnAnUnknownNetworkIsRefused(t *testing.T) {
	s, _ := seedNetwork(t)
	ctx := testContext(t)

	if _, err := s.SetEgressFailClosed(ctx, uuid.New(), false); !errors.Is(err, ErrNoSuchNetwork) {
		t.Errorf("err = %v, want ErrNoSuchNetwork", err)
	}
	if _, err := s.EgressFailClosed(ctx, uuid.New()); !errors.Is(err, ErrNoSuchNetwork) {
		t.Errorf("reading gave err = %v, want ErrNoSuchNetwork", err)
	}
}
