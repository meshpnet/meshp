package session

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// headVersion is the network's current state version.
func (f *fixture) headVersion() uint64 {
	f.t.Helper()
	var v int64
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT state_version FROM networks WHERE id = $1`, f.netID).Scan(&v); err != nil {
		f.t.Fatal(err)
	}
	return uint64(v)
}

// stateFor asks the builder what an agent at fromVersion should receive.
func (f *fixture) stateFor(membershipID uuid.UUID, fromVersion uint64) *meshpv1.StateDelta {
	f.t.Helper()
	got, err := NewStateBuilder(f.store).For(f.ctx, membershipID, fromVersion)
	if err != nil {
		f.t.Fatalf("For(%s, %d): %v", membershipID, fromVersion, err)
	}
	return got
}

func isSnapshot(d *meshpv1.StateDelta) bool { return d.GetFromVersion() == 0 }

func TestAFreshAgentGetsASnapshot(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")

	got := f.stateFor(alice.membershipID, 0)
	if !isSnapshot(got) {
		t.Errorf("from_version = %d, want 0 for an agent with nothing", got.GetFromVersion())
	}
	if len(got.GetUpsertPeers()) != 1 {
		t.Errorf("%d peers, want 1 (bob, not alice herself)", len(got.GetUpsertPeers()))
	}
	if got.GetToVersion() != f.headVersion() {
		t.Errorf("to_version = %d, want head %d", got.GetToVersion(), f.headVersion())
	}
}

// An agent that is current still needs to hear the version, or the convergence gap never
// closes and it looks behind forever.
func TestAnAgentAtHeadGetsAnEmptyDelta(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	head := f.headVersion()

	got := f.stateFor(alice.membershipID, head)
	if isSnapshot(got) {
		t.Error("an agent already at head was sent a whole snapshot")
	}
	if len(got.GetUpsertPeers()) != 0 || len(got.GetRemovePeerKeys()) != 0 {
		t.Errorf("delta is not empty: +%d -%d", len(got.GetUpsertPeers()), len(got.GetRemovePeerKeys()))
	}
	if got.GetToVersion() != head {
		t.Errorf("to_version = %d, want %d", got.GetToVersion(), head)
	}
}

// The point of the whole exercise: a device joining a large network must not cause every
// other agent to be sent the entire network again.
func TestAnAgentBehindGetsOnlyWhatChanged(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")
	f.enrolDevice("carol")
	before := f.headVersion()

	dave := f.enrolDevice("dave")

	got := f.stateFor(alice.membershipID, before)
	if isSnapshot(got) {
		t.Fatal("an agent one version behind was sent a snapshot")
	}
	if got.GetFromVersion() != before {
		t.Errorf("from_version = %d, want %d", got.GetFromVersion(), before)
	}
	if len(got.GetUpsertPeers()) != 1 {
		t.Fatalf("%d upserts, want 1 — only dave changed", len(got.GetUpsertPeers()))
	}
	if name := got.GetUpsertPeers()[0].GetDeviceName(); name != "dave" {
		t.Errorf("the delta names %q, want dave", name)
	}
	_ = dave
}

// A device is never its own peer, even when the change that moved the version was its own
// enrolment.
func TestADeltaNeverContainsTheRecipient(t *testing.T) {
	f := newFixture(t)
	f.enrolDevice("alice")
	before := f.headVersion()
	bob := f.enrolDevice("bob")

	// Bob is behind by his own enrolment.
	got := f.stateFor(bob.membershipID, before)
	for _, p := range got.GetUpsertPeers() {
		if p.GetDeviceName() == "bob" {
			t.Error("the delta contains the device it was built for")
		}
	}
}

// Below the floor the log no longer reaches, so a delta would have holes in it.
func TestAnAgentBelowTheDeltaFloorGetsASnapshot(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")
	before := f.headVersion()
	f.enrolDevice("carol")

	// A delta is available at this point.
	if isSnapshot(f.stateFor(alice.membershipID, before)) {
		t.Fatal("a delta was not available before pruning")
	}

	// Now raise the floor above where the agent is, which is what pruning does.
	if _, err := f.store.Queries().RaiseDeltaFloor(f.ctx, dbgen.RaiseDeltaFloorParams{
		ID:      f.netID,
		Version: int64(before) + 1,
	}); err != nil {
		t.Fatal(err)
	}

	if got := f.stateFor(alice.membershipID, before); !isSnapshot(got) {
		t.Errorf("an agent below the floor got a delta from %d", got.GetFromVersion())
	}
}

// An agent claiming to be ahead of the server holds state we cannot explain — after a
// database restore, or against a different deployment. Replacing what it has is the only
// safe answer; patching it would build on a version that never existed here.
func TestAnAgentAheadOfTheServerGetsASnapshot(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	if got := f.stateFor(alice.membershipID, f.headVersion()+100); !isSnapshot(got) {
		t.Errorf("an agent ahead of the server got a delta from %d", got.GetFromVersion())
	}
}

// A delta bigger than the snapshot it replaces is a worse answer to the same question.
func TestALargeDeltaBecomesASnapshot(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	from := f.headVersion()

	// More changes than there are peers: the same membership touched repeatedly, which is
	// what a busy network looks like from one agent's point of view.
	bob := f.enrolDevice("bob")
	for range 6 {
		if err := f.store.InTx(f.ctx, func(q *dbgen.Queries) error {
			_, err := storeBumpVersion(f.ctx, q, f.netID, bob.membershipID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	got := f.stateFor(alice.membershipID, from)
	if !isSnapshot(got) {
		t.Errorf("a delta of many changes over few peers was not collapsed to a snapshot")
	}
}

// A membership touched repeatedly appears once, with its current state.
//
// Enough peers that the collapse is observable: with only two, three changes exceed the
// snapshot threshold and the delta path is never reached, which is how the first version
// of this test managed to skip itself.
func TestRepeatedChangesCollapse(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")
	for _, name := range []string{"carol", "dave", "erin", "frank"} {
		f.enrolDevice(name)
	}
	from := f.headVersion()

	const touches = 4
	for range touches {
		if err := f.store.InTx(f.ctx, func(q *dbgen.Queries) error {
			_, err := storeBumpVersion(f.ctx, q, f.netID, bob.membershipID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	got := f.stateFor(alice.membershipID, from)
	if isSnapshot(got) {
		t.Fatalf("%d changes over 5 peers collapsed to a snapshot; the threshold is wrong", touches)
	}
	if len(got.GetUpsertPeers()) != 1 {
		t.Fatalf("%d upserts for one membership changed %d times, want 1", len(got.GetUpsertPeers()), touches)
	}
	if name := got.GetUpsertPeers()[0].GetDeviceName(); name != "bob" {
		t.Errorf("the single upsert names %q, want bob", name)
	}
	// And it carries current state, not a replay of each change.
	if len(got.GetUpsertPeers()[0].GetAllowedIps()) == 0 {
		t.Error("the collapsed upsert carries no addresses")
	}
}

// A removal has to reach the agent, or it keeps a tunnel configured to a device that is
// gone. Nothing writes peer_remove yet — revocation is not implemented — so the change is
// recorded directly here, which is exactly how revocation will record it.
func TestARemovalReachesTheAgent(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	bob := f.enrolDevice("bob")
	from := f.headVersion()

	var bobKey string
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT public_key FROM wireguard_keys WHERE membership_id = $1`, bob.membershipID).Scan(&bobKey); err != nil {
		t.Fatal(err)
	}

	if err := f.store.InTx(f.ctx, func(q *dbgen.Queries) error {
		_, err := storeBumpVersionRemove(f.ctx, q, f.netID, bobKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	got := f.stateFor(alice.membershipID, from)
	if isSnapshot(got) {
		t.Fatal("a single removal produced a snapshot")
	}
	if len(got.GetRemovePeerKeys()) != 1 || got.GetRemovePeerKeys()[0] != bobKey {
		t.Errorf("remove keys = %v, want [%s]", got.GetRemovePeerKeys(), bobKey)
	}
}

// Two computations of the same delta must produce identical bytes. The delta is built by
// walking maps, and Go randomises map iteration order — leaking that onto the wire would
// look like configuration churn to every agent in the network.
func TestDeltasAreDeterministic(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")
	from := f.headVersion()
	f.enrolDevice("carol")
	f.enrolDevice("dave")

	first := f.stateFor(alice.membershipID, from)
	for attempt := range 30 {
		again := f.stateFor(alice.membershipID, from)
		if !proto.Equal(first, again) {
			t.Fatalf("attempt %d produced a different delta:\n %v\n %v", attempt, first, again)
		}
	}
}

// The property that makes all of this safe, against the real server and the real client:
//
//	apply(snapshot at F, delta F→H) == snapshot at H
func TestFollowingDeltasMatchesASnapshot(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")

	followed := peerset.New()
	followed.Apply(f.stateFor(alice.membershipID, 0))

	// A run of real mutations, each delivered as whatever the server decides to send.
	for _, name := range []string{"bob", "carol", "dave", "erin"} {
		f.enrolDevice(name)
		followed.Apply(f.stateFor(alice.membershipID, followed.Version()))
	}

	fresh := peerset.New()
	fresh.Apply(f.stateFor(alice.membershipID, 0))

	if !followed.Equal(fresh) {
		t.Fatalf("following the server's deltas diverged from its snapshot\n  followed: %v\n  snapshot: %v",
			followed.Keys(), fresh.Keys())
	}
	if followed.Version() != fresh.Version() {
		t.Errorf("versions differ: %d and %d", followed.Version(), fresh.Version())
	}
	if followed.Len() != 4 {
		t.Errorf("%d peers, want 4", followed.Len())
	}
}

// Pruning must raise the floor as well as delete rows, or an agent below it is handed a
// delta with holes.
func TestPruningRaisesTheFloor(t *testing.T) {
	f := newFixture(t)
	alice := f.enrolDevice("alice")
	f.enrolDevice("bob")
	before := f.headVersion()
	f.enrolDevice("carol")

	// Through the shipping path, not the two queries it is built from: what has to hold
	// is that whatever prunes in production also moves the floor.
	res, err := f.store.PruneDeltaLog(f.ctx, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows == 0 {
		t.Fatal("pruning removed nothing")
	}
	if res.Networks != 1 {
		t.Errorf("pruned %d networks, want 1", res.Networks)
	}

	// With the log gone and the floor raised, the agent must be sent a snapshot rather
	// than an empty delta that claims nothing changed.
	got := f.stateFor(alice.membershipID, before)
	if !isSnapshot(got) {
		t.Errorf("after pruning, an agent behind got a delta from %d with %d upserts",
			got.GetFromVersion(), len(got.GetUpsertPeers()))
	}
	if len(got.GetUpsertPeers()) != 2 {
		t.Errorf("%d peers in the snapshot, want 2", len(got.GetUpsertPeers()))
	}
}

// --- helpers ----------------------------------------------------------------

// storeBumpVersion records a peer change the way a mutation would, so tests can move the
// version without inventing a whole feature to do it.
func storeBumpVersion(ctx context.Context, q *dbgen.Queries, networkID, membershipID uuid.UUID) (int64, error) {
	return store.BumpVersion(ctx, q, networkID, store.PeerUpserted(membershipID))
}

func storeBumpVersionRemove(ctx context.Context, q *dbgen.Queries, networkID uuid.UUID, publicKey string) (int64, error) {
	return store.BumpVersion(ctx, q, networkID, store.PeerRemoved(publicKey))
}
