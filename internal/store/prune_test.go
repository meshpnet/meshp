package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// pruneFixture is a network with a change log of known age.
type pruneFixture struct {
	t     *testing.T
	ctx   context.Context
	store *Store
	netID uuid.UUID
}

func newPruneFixture(t *testing.T) *pruneFixture {
	t.Helper()
	st, ctx := freshStore(t), testContext(t)

	var orgID, netID uuid.UUID
	if err := st.Pool().QueryRow(ctx,
		`INSERT INTO organizations (slug,name) VALUES ('prune','Prune') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool().QueryRow(ctx,
		`INSERT INTO networks (organization_id,slug,name) VALUES ($1,'p','P') RETURNING id`,
		orgID).Scan(&netID); err != nil {
		t.Fatal(err)
	}
	return &pruneFixture{t: t, ctx: ctx, store: st, netID: netID}
}

// change records a removal at a given age. A removal because it carries its own key and so
// needs no membership row, which keeps this about the log rather than about enrolment.
func (f *pruneFixture) change(key string, age time.Duration) int64 {
	f.t.Helper()
	var version int64
	if err := f.store.InTx(f.ctx, func(q *dbgen.Queries) error {
		v, err := BumpVersion(f.ctx, q, f.netID, PeerRemoved(key))
		version = v
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	if age > 0 {
		if _, err := f.store.Pool().Exec(f.ctx,
			`UPDATE state_changes SET created_at = now() - $2::interval WHERE network_id = $1 AND version = $3`,
			f.netID, age.String(), version); err != nil {
			f.t.Fatal(err)
		}
	}
	return version
}

func (f *pruneFixture) logSize() int {
	f.t.Helper()
	var n int
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT count(*) FROM state_changes WHERE network_id = $1`, f.netID).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *pruneFixture) floor() int64 {
	f.t.Helper()
	var v int64
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT oldest_delta_version FROM networks WHERE id = $1`, f.netID).Scan(&v); err != nil {
		f.t.Fatal(err)
	}
	return v
}

func TestPruneRemovesOnlyWhatIsOldEnough(t *testing.T) {
	f := newPruneFixture(t)
	f.change("old-one", 48*time.Hour)
	f.change("old-two", 30*time.Hour)
	f.change("recent", time.Minute)

	res, err := f.store.PruneDeltaLog(f.ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 2 {
		t.Errorf("pruned %d rows, want 2", res.Rows)
	}
	if res.Networks != 1 {
		t.Errorf("pruned %d networks, want 1", res.Networks)
	}
	if n := f.logSize(); n != 1 {
		t.Errorf("%d rows remain, want 1", n)
	}
}

// The floor and the delete are one transaction. If the floor did not move, the network
// would offer deltas from a version whose changes are gone — and the agent would apply
// them and report success (Invariant 21).
func TestPruneRaisesTheFloorToTheHighestVersionRemoved(t *testing.T) {
	f := newPruneFixture(t)
	f.change("a", 48*time.Hour)
	secondOld := f.change("b", 48*time.Hour)
	f.change("c", time.Minute)

	if _, err := f.store.PruneDeltaLog(f.ctx, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := f.floor(); got != secondOld {
		t.Errorf("floor = %d, want %d — the highest version removed", got, secondOld)
	}
}

// Every version at or below the floor must be one the log can no longer serve, and every
// version above it must be fully covered. A floor that is off by one in either direction
// is either a snapshot nobody needed or a delta with a hole in it.
func TestNothingSurvivesBelowTheFloor(t *testing.T) {
	f := newPruneFixture(t)
	for range 5 {
		f.change(uuid.NewString(), 48*time.Hour)
	}
	for range 3 {
		f.change(uuid.NewString(), time.Minute)
	}

	if _, err := f.store.PruneDeltaLog(f.ctx, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	floor := f.floor()
	var below int
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT count(*) FROM state_changes WHERE network_id = $1 AND version <= $2`,
		f.netID, floor).Scan(&below); err != nil {
		t.Fatal(err)
	}
	if below != 0 {
		t.Errorf("%d rows survive at or below the floor %d", below, floor)
	}

	// And the log above the floor is contiguous: a delta from the floor upward needs every
	// version in between.
	changes, err := f.store.Queries().ListStateChangesSince(f.ctx, dbgen.ListStateChangesSinceParams{
		NetworkID:   f.netID,
		FromVersion: floor,
		ToVersion:   floor + 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 {
		t.Errorf("%d changes above the floor, want the 3 that were too recent to prune", len(changes))
	}
}

// A sweep with nothing to do must not open a transaction per network, and must not claim it
// did work.
func TestPruneWithNothingOldEnoughDoesNothing(t *testing.T) {
	f := newPruneFixture(t)
	f.change("recent", time.Minute)
	floorBefore := f.floor()

	res, err := f.store.PruneDeltaLog(f.ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.Networks != 0 || res.Rows != 0 {
		t.Errorf("reported %d networks and %d rows, want none", res.Networks, res.Rows)
	}
	if f.floor() != floorBefore {
		t.Errorf("the floor moved to %d with nothing pruned", f.floor())
	}
	if n := f.logSize(); n != 1 {
		t.Errorf("%d rows remain, want 1", n)
	}
}

// Pruning twice is not different from pruning once: the floor uses greatest(), so a second
// sweep cannot lower it.
func TestPruneIsIdempotent(t *testing.T) {
	f := newPruneFixture(t)
	f.change("a", 48*time.Hour)
	f.change("b", 48*time.Hour)

	first, err := f.store.PruneDeltaLog(f.ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	floorAfterFirst := f.floor()

	second, err := f.store.PruneDeltaLog(f.ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Rows != 0 {
		t.Errorf("the second sweep pruned %d rows, want 0 (the first pruned %d)", second.Rows, first.Rows)
	}
	if f.floor() != floorAfterFirst {
		t.Errorf("the floor moved from %d to %d on a second sweep", floorAfterFirst, f.floor())
	}
}

// Networks are pruned independently: one with an old log must not raise another's floor.
func TestPruneKeepsNetworksSeparate(t *testing.T) {
	f := newPruneFixture(t)

	var otherOrg, other uuid.UUID
	if err := f.store.Pool().QueryRow(f.ctx,
		`INSERT INTO organizations (slug,name) VALUES ('prune2','Prune Two') RETURNING id`).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Pool().QueryRow(f.ctx,
		`INSERT INTO networks (organization_id,slug,name) VALUES ($1,'q','Q') RETURNING id`,
		otherOrg).Scan(&other); err != nil {
		t.Fatal(err)
	}

	f.change("old", 48*time.Hour)
	// The other network's change is recent, so nothing of its own is prunable.
	if err := f.store.InTx(f.ctx, func(q *dbgen.Queries) error {
		_, err := BumpVersion(f.ctx, q, other, PeerRemoved("other-recent"))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := f.store.PruneDeltaLog(f.ctx, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	var otherFloor int64
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT oldest_delta_version FROM networks WHERE id = $1`, other).Scan(&otherFloor); err != nil {
		t.Fatal(err)
	}
	if otherFloor != 0 {
		t.Errorf("the other network's floor is %d, want 0", otherFloor)
	}
	var otherRows int
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT count(*) FROM state_changes WHERE network_id = $1`, other).Scan(&otherRows); err != nil {
		t.Fatal(err)
	}
	if otherRows != 1 {
		t.Errorf("the other network has %d rows, want 1", otherRows)
	}
}
