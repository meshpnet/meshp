package peerset

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func peer(key string, addr string) *meshpv1.Peer {
	return &meshpv1.Peer{
		PublicKey:                  key,
		AllowedIps:                 []string{addr + "/32"},
		PersistentKeepaliveSeconds: 25,
		DeviceName:                 "device-" + key,
	}
}

func snapshot(version uint64, peers ...*meshpv1.Peer) *meshpv1.StateDelta {
	return &meshpv1.StateDelta{FromVersion: 0, ToVersion: version, UpsertPeers: peers}
}

func delta(from, to uint64, upsert []*meshpv1.Peer, remove []string) *meshpv1.StateDelta {
	return &meshpv1.StateDelta{FromVersion: from, ToVersion: to, UpsertPeers: upsert, RemovePeerKeys: remove}
}

func TestApplySnapshot(t *testing.T) {
	s := New()
	s.Apply(snapshot(3, peer("a", "100.90.0.1"), peer("b", "100.90.0.2")))

	if s.Version() != 3 {
		t.Errorf("version = %d, want 3", s.Version())
	}
	if got := s.Keys(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("keys = %v, want [a b]", got)
	}
}

// A snapshot describes the whole world, so it must replace what came before. Merging one
// into existing peers would silently keep peers the server no longer knows about.
func TestSnapshotReplacesEverything(t *testing.T) {
	s := New()
	s.Apply(snapshot(1, peer("a", "100.90.0.1"), peer("stale", "100.90.0.9")))
	s.Apply(snapshot(2, peer("a", "100.90.0.1"), peer("b", "100.90.0.2")))

	if s.Has("stale") {
		t.Error("a peer absent from the newer snapshot survived it")
	}
	if got := s.Keys(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("keys = %v, want [a b]", got)
	}
}

func TestApplyDelta(t *testing.T) {
	s := New()
	s.Apply(snapshot(1, peer("a", "100.90.0.1"), peer("b", "100.90.0.2")))
	s.Apply(delta(1, 2, []*meshpv1.Peer{peer("c", "100.90.0.3")}, []string{"a"}))

	if got := s.Keys(); !slices.Equal(got, []string{"b", "c"}) {
		t.Errorf("keys = %v, want [b c]", got)
	}
	if s.Version() != 2 {
		t.Errorf("version = %d, want 2", s.Version())
	}
}

// Within one delta, a key that is both removed and upserted is a rotation or a re-add, and
// the upsert is the newer fact. Applying them the other way round would drop the peer.
func TestUpsertWinsOverRemovalInTheSameDelta(t *testing.T) {
	s := New()
	s.Apply(snapshot(1, peer("a", "100.90.0.1")))
	s.Apply(delta(1, 2, []*meshpv1.Peer{peer("a", "100.90.0.7")}, []string{"a"}))

	got, ok := s.Get("a")
	if !ok {
		t.Fatal("the peer was removed despite being upserted in the same delta")
	}
	if got.GetAllowedIps()[0] != "100.90.0.7/32" {
		t.Errorf("allowed ips = %v, want the upserted value", got.GetAllowedIps())
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	// Invariant 18: applying the same state twice produces identical state. This is what
	// makes the reconciler safe to re-run, which it will be on every reconnect.
	first := New()
	first.Apply(snapshot(5, peer("a", "100.90.0.1"), peer("b", "100.90.0.2")))

	twice := New()
	twice.Apply(snapshot(5, peer("a", "100.90.0.1"), peer("b", "100.90.0.2")))
	twice.Apply(snapshot(5, peer("a", "100.90.0.1"), peer("b", "100.90.0.2")))

	if !first.Equal(twice) {
		t.Error("applying the same snapshot twice produced a different set")
	}
	if first.Version() != twice.Version() {
		t.Errorf("versions differ: %d and %d", first.Version(), twice.Version())
	}
}

// The set must own its peers. Holding the caller's pointers would let a later mutation of
// a received message change state that was already applied.
func TestApplyCopiesPeers(t *testing.T) {
	original := peer("a", "100.90.0.1")
	s := New()
	s.Apply(snapshot(1, original))

	original.DeviceName = "renamed after the fact"
	original.AllowedIps[0] = "10.0.0.0/8"

	got, _ := s.Get("a")
	if got.GetDeviceName() == "renamed after the fact" {
		t.Error("mutating the applied message changed the stored peer")
	}
	if got.GetAllowedIps()[0] != "100.90.0.1/32" {
		t.Errorf("allowed ips changed to %v", got.GetAllowedIps())
	}
}

func TestEqualComparesContentsNotVersions(t *testing.T) {
	a := New()
	a.Apply(snapshot(7, peer("x", "100.90.0.1")))

	// Same contents, different version: still equal, because equality is about peers.
	b := New()
	b.Apply(snapshot(9, peer("x", "100.90.0.1")))
	if !a.Equal(b) {
		t.Error("sets with identical peers compared unequal")
	}

	// Same version, different contents: the failure worth detecting. A comparison that
	// only looked at versions would call this equality.
	c := New()
	c.Apply(snapshot(7, peer("y", "100.90.0.2")))
	if a.Equal(c) {
		t.Error("sets with different peers compared equal")
	}
}

func TestDiff(t *testing.T) {
	have := New()
	have.Apply(snapshot(1, peer("keep", "100.90.0.1"), peer("drop", "100.90.0.2"), peer("change", "100.90.0.3")))

	want := New()
	want.Apply(snapshot(2, peer("keep", "100.90.0.1"), peer("change", "100.90.0.9"), peer("add", "100.90.0.4")))

	add, remove := have.Diff(want)

	var addedKeys []string
	for _, p := range add {
		addedKeys = append(addedKeys, p.GetPublicKey())
	}
	// "change" is in both but differs, so it has to be re-applied.
	if !slices.Equal(addedKeys, []string{"add", "change"}) {
		t.Errorf("add = %v, want [add change]", addedKeys)
	}
	if !slices.Equal(remove, []string{"drop"}) {
		t.Errorf("remove = %v, want [drop]", remove)
	}

	// A set diffed against itself needs no work, which is what makes a reconcile loop
	// quiet when nothing has changed.
	noAdd, noRemove := want.Diff(want)
	if len(noAdd) != 0 || len(noRemove) != 0 {
		t.Errorf("diffing a set against itself produced work: +%d -%d", len(noAdd), len(noRemove))
	}
}

func TestApplyNilIsSafe(t *testing.T) {
	s := New()
	s.Apply(snapshot(1, peer("a", "100.90.0.1")))
	s.Apply(nil)
	if s.Version() != 1 || !s.Has("a") {
		t.Error("applying nil changed the set")
	}
}

// --- the property that makes deltas safe ------------------------------------

// A model of the server's peer set, so deltas can be generated the way the server would
// and checked against what a snapshot at the same version would say.
type model struct {
	peers   map[string]*meshpv1.Peer
	version uint64
}

func (m *model) snapshot() *meshpv1.StateDelta {
	out := &meshpv1.StateDelta{FromVersion: 0, ToVersion: m.version}
	for _, key := range sortedKeys(m.peers) {
		out.UpsertPeers = append(out.UpsertPeers, proto.CloneOf(m.peers[key]))
	}
	return out
}

func sortedKeys(m map[string]*meshpv1.Peer) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// mutate makes a random change and returns the delta describing it, exactly as the server
// would compute one.
func (m *model) mutate(rng *rand.Rand, step int) *meshpv1.StateDelta {
	from := m.version
	m.version++

	switch {
	case len(m.peers) == 0 || rng.IntN(3) > 0:
		// Add or update.
		key := fmt.Sprintf("k%02d", rng.IntN(12))
		p := peer(key, fmt.Sprintf("100.90.0.%d", 1+step%250))
		m.peers[key] = proto.CloneOf(p)
		return delta(from, m.version, []*meshpv1.Peer{p}, nil)

	default:
		// Remove.
		keys := sortedKeys(m.peers)
		key := keys[rng.IntN(len(keys))]
		delete(m.peers, key)
		return delta(from, m.version, nil, []string{key})
	}
}

// The property everything else rests on:
//
//	apply(snapshot at F, deltas F→H) == snapshot at H
//
// If it ever fails, an agent's peers drift from the control plane's while both report the
// same version — which nothing downstream can detect, because the convergence metric only
// compares numbers.
func TestPropertyDeltasReachTheSameStateAsASnapshot(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x70656572, 0x73657421))

	for round := range 200 {
		m := &model{peers: map[string]*meshpv1.Peer{}}

		// Some history before the agent starts, so it begins from a non-empty snapshot at a
		// non-zero version rather than always from nothing.
		for step := range 1 + rng.IntN(6) {
			m.mutate(rng, step)
		}

		followed := New()
		followed.Apply(m.snapshot())

		// Then a run of changes delivered as deltas.
		steps := 1 + rng.IntN(15)
		for step := range steps {
			followed.Apply(m.mutate(rng, step))
		}

		fresh := New()
		fresh.Apply(m.snapshot())

		if !followed.Equal(fresh) {
			t.Fatalf("round %d: following %d deltas diverged from a snapshot\n  followed: %v\n  snapshot: %v",
				round, steps, followed.Keys(), fresh.Keys())
		}
		if followed.Version() != fresh.Version() {
			t.Fatalf("round %d: versions differ: %d and %d", round, followed.Version(), fresh.Version())
		}
	}
}

// A set that has followed deltas needs no work to reach a snapshot of the same version,
// which is the same property expressed the way the reconciler will use it.
func TestPropertyAFollowedSetNeedsNoReconciliation(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 22))

	for round := range 100 {
		m := &model{peers: map[string]*meshpv1.Peer{}}
		followed := New()
		followed.Apply(m.snapshot())

		for step := range 1 + rng.IntN(20) {
			followed.Apply(m.mutate(rng, step))
		}

		fresh := New()
		fresh.Apply(m.snapshot())

		add, remove := followed.Diff(fresh)
		if len(add) != 0 || len(remove) != 0 {
			t.Fatalf("round %d: a followed set still needed +%d -%d to match a snapshot",
				round, len(add), len(remove))
		}
	}
}

func FuzzApply(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{})
	f.Add([]byte{255, 255})

	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 512 {
			ops = ops[:512]
		}
		s := New()
		var version uint64

		for _, op := range ops {
			key := fmt.Sprintf("k%d", op%8)
			version++
			switch op % 3 {
			case 0:
				s.Apply(snapshot(version, peer(key, "100.90.0.1")))
			case 1:
				s.Apply(delta(s.Version(), version, []*meshpv1.Peer{peer(key, "100.90.0.2")}, nil))
			case 2:
				s.Apply(delta(s.Version(), version, nil, []string{key}))
			}

			// Whatever happens, the set stays self-consistent: sorted, deduplicated, and
			// reporting a length that matches its contents.
			keys := s.Keys()
			if len(keys) != s.Len() {
				t.Fatalf("Len() = %d but Keys() returned %d", s.Len(), len(keys))
			}
			if !slices.IsSorted(keys) {
				t.Fatalf("Keys() is not sorted: %v", keys)
			}
			for i := 1; i < len(keys); i++ {
				if keys[i] == keys[i-1] {
					t.Fatalf("Keys() contains a duplicate: %v", keys)
				}
			}
			if s.Version() != version {
				t.Fatalf("version = %d, want %d", s.Version(), version)
			}
		}
	})
}

// The same property, with the server's fallback interleaved.
//
// The plain version above always applies a snapshot to a fresh set, which makes
// "replace" and "merge" indistinguishable — a set that merged snapshots passed it. The
// case that matters is an agent that has followed deltas and then falls behind the delta
// floor, or reconnects, and is handed a snapshot on top of what it already has. If that
// merges, it keeps peers the server has forgotten, forever, at a version that says it is
// current.
func TestPropertySnapshotsInterleavedWithDeltas(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xfa11bac, 5))

	for round := range 200 {
		m := &model{peers: map[string]*meshpv1.Peer{}}
		followed := New()
		followed.Apply(m.snapshot())

		snapshots := 0
		for step := range 2 + rng.IntN(20) {
			d := m.mutate(rng, step)
			// Occasionally the server answers with a snapshot instead, which is what it does
			// when an agent is further behind than the change log goes.
			if rng.IntN(4) == 0 {
				followed.Apply(m.snapshot())
				snapshots++
				continue
			}
			followed.Apply(d)
		}

		fresh := New()
		fresh.Apply(m.snapshot())

		if !followed.Equal(fresh) {
			t.Fatalf("round %d: diverged after %d interleaved snapshots\n  followed: %v\n  snapshot: %v",
				round, snapshots, followed.Keys(), fresh.Keys())
		}
	}
}

// A clone must not share anything with what it was cloned from — neither the map nor the
// messages in it. Sharing either turns "compare what I applied against what I am being
// asked to apply" into a comparison of something with itself.
func TestCloneSharesNothing(t *testing.T) {
	original := New()
	original.Apply(&meshpv1.StateDelta{
		FromVersion: 0,
		ToVersion:   7,
		UpsertPeers: []*meshpv1.Peer{
			{PublicKey: "aaa", DeviceName: "one", AllowedIps: []string{"10.0.0.1/32"}},
			{PublicKey: "bbb", DeviceName: "two", AllowedIps: []string{"10.0.0.2/32"}},
		},
		Tunnel: &meshpv1.TunnelConfig{Mtu: 1420},
	})

	clone := original.Clone()
	if !clone.Equal(original) {
		t.Fatal("a fresh clone does not equal what it was cloned from")
	}
	if clone.Version() != original.Version() {
		t.Fatalf("clone at version %d, original at %d", clone.Version(), original.Version())
	}

	// Changing the original must leave the clone alone: a new peer, a removed peer, a
	// mutated peer and a new tunnel.
	original.Apply(&meshpv1.StateDelta{
		FromVersion:    7,
		ToVersion:      8,
		UpsertPeers:    []*meshpv1.Peer{{PublicKey: "ccc", DeviceName: "three"}},
		RemovePeerKeys: []string{"aaa"},
		Tunnel:         &meshpv1.TunnelConfig{Mtu: 1280},
	})
	if clone.Len() != 2 {
		t.Errorf("the clone has %d peers after the original changed, want 2", clone.Len())
	}
	if !clone.Has("aaa") {
		t.Error("a peer removed from the original vanished from the clone")
	}
	if clone.Has("ccc") {
		t.Error("a peer added to the original appeared in the clone")
	}
	if clone.Version() != 7 {
		t.Errorf("the clone is at version %d, want the version it was cloned at (7)", clone.Version())
	}
	if got := clone.Tunnel().GetMtu(); got != 1420 {
		t.Errorf("the clone's MTU is %d, want 1420", got)
	}

	// And the messages themselves, not just the map that holds them.
	peer, _ := original.Get("bbb")
	peer.DeviceName = "renamed-in-place"
	cloned, _ := clone.Get("bbb")
	if cloned.GetDeviceName() != "two" {
		t.Errorf("mutating a peer in the original renamed it in the clone to %q",
			cloned.GetDeviceName())
	}
}

func relayConfig(ids ...string) *meshpv1.RelayConfig {
	cfg := &meshpv1.RelayConfig{}
	for _, id := range ids {
		cfg.Relays = append(cfg.Relays, &meshpv1.RelayConfig_Relay{
			Id: id, Region: "test", Endpoints: []string{id + ".example:3478"},
		})
	}
	return cfg
}

// The agent has to keep the relay configuration, not just read past it. A peer's relay_id
// names one of these, so a set that dropped them would know a peer is relayed and have no
// address to dial.
func TestApplyKeepsRelays(t *testing.T) {
	s := New()
	d := snapshot(1, peer("a", "100.90.0.1"))
	d.Relays = relayConfig("relay1")
	s.Apply(d)

	if got := len(s.Relays().GetRelays()); got != 1 {
		t.Fatalf("relays = %d, want 1", got)
	}
	relay, ok := s.Relay("relay1")
	if !ok {
		t.Fatal("relay1 not found by id")
	}
	if got := relay.GetEndpoints(); !slices.Equal(got, []string{"relay1.example:3478"}) {
		t.Errorf("endpoints = %v", got)
	}
	if _, ok := s.Relay("nope"); ok {
		t.Error("found a relay that was never sent")
	}
	if _, ok := s.Relay(""); ok {
		t.Error("an empty relay id matched a relay; a peer with no relay would find one")
	}
}

// Absent in a delta means unchanged. A server that has nothing to say about relays sends
// no RelayConfig, and forgetting them then would drop every relayed peer's path on the
// next unrelated peer change.
func TestDeltaWithoutRelaysLeavesThemAlone(t *testing.T) {
	s := New()
	first := snapshot(1, peer("a", "100.90.0.1"))
	first.Relays = relayConfig("relay1")
	s.Apply(first)

	s.Apply(delta(1, 2, []*meshpv1.Peer{peer("b", "100.90.0.2")}, nil))

	if _, ok := s.Relay("relay1"); !ok {
		t.Fatal("a delta that said nothing about relays discarded them")
	}
}

// A snapshot describes the whole world, so one carrying no relays means this deployment
// has none. Keeping the previous ones would leave an agent dialling a decommissioned relay
// and reporting itself relayed through it.
func TestSnapshotWithoutRelaysClearsThem(t *testing.T) {
	s := New()
	first := snapshot(1, peer("a", "100.90.0.1"))
	first.Relays = relayConfig("relay1")
	s.Apply(first)

	s.Apply(snapshot(2, peer("a", "100.90.0.1")))

	if s.Relays() != nil {
		t.Fatalf("a snapshot with no relays left %v behind", s.Relays())
	}
}

// Desired state is more than the peers. Two sets that agree on every peer and disagree
// about the relay are not the same state, and calling them equal would let Invariant 21
// hold while an agent folded deltas into the wrong relay.
func TestEqualComparesConfiguration(t *testing.T) {
	build := func(relays *meshpv1.RelayConfig, mtu uint32) *Set {
		s := New()
		d := snapshot(1, peer("a", "100.90.0.1"))
		d.Relays = relays
		d.Tunnel = &meshpv1.TunnelConfig{Mtu: mtu}
		s.Apply(d)
		return s
	}

	if !build(relayConfig("relay1"), 1387).Equal(build(relayConfig("relay1"), 1387)) {
		t.Error("identical sets compared unequal")
	}
	if build(relayConfig("relay1"), 1387).Equal(build(relayConfig("relay2"), 1387)) {
		t.Error("sets using different relays compared equal")
	}
	if build(relayConfig("relay1"), 1387).Equal(build(relayConfig("relay1"), 1420)) {
		t.Error("sets with different MTUs compared equal")
	}
	if build(nil, 1420).Equal(build(relayConfig("relay1"), 1420)) {
		t.Error("a set with no relays compared equal to one with a relay")
	}
	if !build(nil, 1420).Equal(build(nil, 1420)) {
		t.Error("two sets with no relays compared unequal")
	}
}

// Clone exists so the holder of a set is not reading one the session is folding into
// (Invariant 22). That has to cover the configuration as well as the peers.
func TestCloneCopiesConfiguration(t *testing.T) {
	s := New()
	d := snapshot(1, peer("a", "100.90.0.1"))
	d.Relays = relayConfig("relay1")
	s.Apply(d)

	clone := s.Clone()
	if _, ok := clone.Relay("relay1"); !ok {
		t.Fatal("the clone lost the relays")
	}

	// Mutating the clone must not reach back into the original.
	clone.relays.Relays[0].Id = "tampered"
	if _, ok := s.Relay("relay1"); !ok {
		t.Error("editing the clone's relays changed the original's")
	}
}

func assignment(id string, prefixes ...string) *meshpv1.RouteGroupAssignment {
	return &meshpv1.RouteGroupAssignment{RouteGroupId: id, Prefixes: prefixes}
}

// A snapshot describes the whole world, so one naming no route groups means this device
// carries nothing. Keeping the last set would leave it routing a prefix its network no
// longer asks it to — and a reconnect is delivered as a snapshot, so this is the path a
// withdrawn assignment actually takes.
func TestASnapshotClearsTheRouteGroups(t *testing.T) {
	s := New()
	first := snapshot(1)
	first.RouteGroups = []*meshpv1.RouteGroupAssignment{assignment("g1", "192.168.10.0/24")}
	s.Apply(first)
	if len(s.RouteGroups()) != 1 {
		t.Fatalf("the assignment was not kept: %+v", s.RouteGroups())
	}

	s.Apply(snapshot(2))
	if got := s.RouteGroups(); len(got) != 0 {
		t.Fatalf("a snapshot with no route groups left %+v behind", got)
	}
}

// A delta names groups to upsert and groups to withdraw, so absent means unchanged.
func TestADeltaUpsertsAndWithdrawsRouteGroups(t *testing.T) {
	s := New()
	first := snapshot(1)
	first.RouteGroups = []*meshpv1.RouteGroupAssignment{
		assignment("g1", "192.168.10.0/24"),
		assignment("g2", "192.168.20.0/24"),
	}
	s.Apply(first)

	// Unrelated change: the assignments stay.
	s.Apply(delta(1, 2, []*meshpv1.Peer{peer("a", "100.90.0.1")}, nil))
	if len(s.RouteGroups()) != 2 {
		t.Fatalf("an unrelated delta changed the assignments: %+v", s.RouteGroups())
	}

	d := delta(2, 3, nil, nil)
	d.RemovedRouteGroupIds = []string{"g1"}
	d.RouteGroups = []*meshpv1.RouteGroupAssignment{assignment("g3", "10.0.0.0/8")}
	s.Apply(d)

	got := s.RouteGroups()
	if len(got) != 2 {
		t.Fatalf("%d assignments, want 2: %+v", len(got), got)
	}
	// Sorted by id, so two sets with the same contents render identically.
	if got[0].GetRouteGroupId() != "g2" || got[1].GetRouteGroupId() != "g3" {
		t.Errorf("assignments = %v %v", got[0].GetRouteGroupId(), got[1].GetRouteGroupId())
	}
}

// A group both withdrawn and reassigned in one delta ends up assigned: the upsert is the
// newer fact, the same rule the peer list uses.
func TestAReassignedGroupSurvivesItsOwnWithdrawal(t *testing.T) {
	s := New()
	first := snapshot(1)
	first.RouteGroups = []*meshpv1.RouteGroupAssignment{assignment("g1", "192.168.10.0/24")}
	s.Apply(first)

	d := delta(1, 2, nil, nil)
	d.RemovedRouteGroupIds = []string{"g1"}
	d.RouteGroups = []*meshpv1.RouteGroupAssignment{assignment("g1", "192.168.99.0/24")}
	s.Apply(d)

	got := s.RouteGroups()
	if len(got) != 1 {
		t.Fatalf("%d assignments, want 1", len(got))
	}
	if got[0].GetPrefixes()[0] != "192.168.99.0/24" {
		t.Errorf("the withdrawal won over the reassignment: %v", got[0].GetPrefixes())
	}
}

// Assignments are desired state like the peers are, so two sets that disagree about them
// are not the same state — and Clone must copy them or the holder reads the session's.
func TestRouteGroupsCountForEqualityAndAreCloned(t *testing.T) {
	build := func(prefix string) *Set {
		s := New()
		d := snapshot(1)
		d.RouteGroups = []*meshpv1.RouteGroupAssignment{assignment("g1", prefix)}
		s.Apply(d)
		return s
	}

	if !build("192.168.10.0/24").Equal(build("192.168.10.0/24")) {
		t.Error("identical sets compared unequal")
	}
	if build("192.168.10.0/24").Equal(build("192.168.20.0/24")) {
		t.Error("sets carrying different prefixes compared equal")
	}
	if build("192.168.10.0/24").Equal(New()) {
		t.Error("a set with an assignment compared equal to one with none")
	}

	original := build("192.168.10.0/24")
	clone := original.Clone()
	if len(clone.RouteGroups()) != 1 {
		t.Fatal("the clone lost the assignments")
	}
	clone.routeGroups["g1"].Prefixes[0] = "tampered"
	if original.RouteGroups()[0].GetPrefixes()[0] != "192.168.10.0/24" {
		t.Error("editing the clone changed the original")
	}
}

// Present-and-empty says "you carry nothing now", which a device that used to carry
// something has to hear. A snapshot clears it for the same reason it clears everything
// else: a reconnect is delivered as a snapshot.
func TestAdvertisedRoutesAreFoldedAndCleared(t *testing.T) {
	s := New()
	if s.Advertised() != nil {
		t.Fatal("a fresh set already claims to carry something")
	}

	first := snapshot(1)
	first.Advertised = &meshpv1.AdvertisedRoutes{Groups: []*meshpv1.AdvertisedRoutes_Group{
		{RouteGroupId: "g1", Prefixes: []string{"192.168.10.0/24"}},
	}}
	s.Apply(first)
	if len(s.Advertised().GetGroups()) != 1 {
		t.Fatalf("the advertisement was not kept: %+v", s.Advertised())
	}

	// Absent in a delta means unchanged.
	s.Apply(delta(1, 2, []*meshpv1.Peer{peer("a", "100.90.0.1")}, nil))
	if len(s.Advertised().GetGroups()) != 1 {
		t.Errorf("an unrelated delta changed what this device carries")
	}

	// Present-and-empty means it stopped.
	stop := delta(2, 3, nil, nil)
	stop.Advertised = &meshpv1.AdvertisedRoutes{}
	s.Apply(stop)
	if s.Advertised() == nil {
		t.Fatal("an explicit stop was read as no news")
	}
	if len(s.Advertised().GetGroups()) != 0 {
		t.Errorf("it is still carrying %+v", s.Advertised().GetGroups())
	}

	// And a snapshot clears it: a device that reconnects must not resume forwarding for a
	// network that no longer asks it to.
	s.Apply(snapshot(4))
	if s.Advertised() != nil {
		t.Errorf("a snapshot left %+v behind", s.Advertised())
	}
}

// What a device forwards is desired state like everything else, so it counts for equality
// and Clone must copy it.
func TestAdvertisedRoutesCountForEqualityAndAreCloned(t *testing.T) {
	build := func(prefix string) *Set {
		s := New()
		d := snapshot(1)
		if prefix != "" {
			d.Advertised = &meshpv1.AdvertisedRoutes{Groups: []*meshpv1.AdvertisedRoutes_Group{
				{RouteGroupId: "g1", Prefixes: []string{prefix}},
			}}
		}
		s.Apply(d)
		return s
	}

	if !build("192.168.10.0/24").Equal(build("192.168.10.0/24")) {
		t.Error("identical sets compared unequal")
	}
	if build("192.168.10.0/24").Equal(build("192.168.20.0/24")) {
		t.Error("sets carrying different prefixes compared equal")
	}
	if build("192.168.10.0/24").Equal(build("")) {
		t.Error("a forwarding device compared equal to one that carries nothing")
	}

	original := build("192.168.10.0/24")
	clone := original.Clone()
	if len(clone.Advertised().GetGroups()) != 1 {
		t.Fatal("the clone lost what the device carries")
	}
	clone.advertised.Groups[0].Prefixes[0] = "tampered"
	if original.Advertised().GetGroups()[0].GetPrefixes()[0] != "192.168.10.0/24" {
		t.Error("editing the clone changed the original")
	}
}
