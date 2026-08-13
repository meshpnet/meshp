// Package peerset holds the peers a device has been told about, and applies deltas to
// them.
//
// It exists so that "apply a delta" is a thing with a definition rather than something
// each caller improvises. The reconciler will use it to decide which WireGuard peers to
// add and remove; today it is what makes the property that matters testable:
//
//	apply(snapshot at F, delta F→H) == snapshot at H
//
// That is Invariant 21, and Clone is what upholds Invariant 22.
//
// If that ever stops holding, an agent's idea of the network drifts from the control
// plane's and nothing detects it — the version numbers agree while the contents do not.
// That is much worse than a missed update, because everything downstream, including the
// convergence metric, then reports health.
package peerset

import (
	"sort"

	"google.golang.org/protobuf/proto"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// Set is the peers a device knows about, keyed by WireGuard public key.
//
// Keyed by public key rather than by membership because that is what WireGuard itself is
// keyed by: a rotated key is a different peer to the data plane, arriving as a removal
// and an addition rather than as a modification.
type Set struct {
	peers   map[string]*meshpv1.Peer
	version uint64
	tunnel  *meshpv1.TunnelConfig
}

// New returns an empty set at version zero.
func New() *Set {
	return &Set{peers: make(map[string]*meshpv1.Peer)}
}

// Version is the state version this set reflects.
func (s *Set) Version() uint64 { return s.version }

// SetVersion overrides the recorded version.
//
// Used when an apply fails: the peers may already have been folded in, but the version
// must go back to the one actually in force, or the agent would report having reached a
// state it did not.
func (s *Set) SetVersion(v uint64) { s.version = v }

// Tunnel is the tunnel configuration last received, or nil.
func (s *Set) Tunnel() *meshpv1.TunnelConfig { return s.tunnel }

// Len is how many peers are known.
func (s *Set) Len() int { return len(s.peers) }

// Apply folds a delta into the set.
//
// A snapshot — from_version zero — replaces everything, because that is what a snapshot
// means: the server is describing the whole world rather than a change to it. Merging one
// into existing peers would silently keep peers the server no longer knows about, which
// is exactly the drift this package exists to prevent.
func (s *Set) Apply(delta *meshpv1.StateDelta) {
	if delta == nil {
		return
	}

	if delta.GetFromVersion() == 0 {
		s.peers = make(map[string]*meshpv1.Peer, len(delta.GetUpsertPeers()))
	}

	// Removals first. Within one delta a key that is both removed and upserted is a
	// rotation or a re-add, and the upsert is the newer fact.
	for _, key := range delta.GetRemovePeerKeys() {
		delete(s.peers, key)
	}
	for _, peer := range delta.GetUpsertPeers() {
		s.peers[peer.GetPublicKey()] = proto.CloneOf(peer)
	}

	if delta.GetTunnel() != nil {
		s.tunnel = proto.CloneOf(delta.GetTunnel())
	}
	s.version = delta.GetToVersion()
}

// Clone returns an independent copy.
//
// Handed to anything that keeps the set beyond the call it arrived in. A shared set would
// be read while the owner folds the next delta into it, and — worse than the race — a
// holder comparing "what I have" against a set that mutates underneath it can never see a
// difference, so a reconciler would decide there was nothing to do.
func (s *Set) Clone() *Set {
	out := &Set{peers: make(map[string]*meshpv1.Peer, len(s.peers)), version: s.version}
	for key, peer := range s.peers {
		out.peers[key] = proto.CloneOf(peer)
	}
	if s.tunnel != nil {
		out.tunnel = proto.CloneOf(s.tunnel)
	}
	return out
}

// Peers returns the known peers, ordered by public key.
//
// Sorted so that two sets with the same contents compare equal and produce identical
// output. An unsorted map walk would make every comparison and every rendering of this
// depend on Go's randomised iteration order.
func (s *Set) Peers() []*meshpv1.Peer {
	out := make([]*meshpv1.Peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetPublicKey() < out[j].GetPublicKey() })
	return out
}

// Keys returns the known public keys, sorted.
func (s *Set) Keys() []string {
	out := make([]string, 0, len(s.peers))
	for k := range s.peers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Has reports whether a peer is known.
func (s *Set) Has(publicKey string) bool {
	_, ok := s.peers[publicKey]
	return ok
}

// Get returns a peer.
func (s *Set) Get(publicKey string) (*meshpv1.Peer, bool) {
	p, ok := s.peers[publicKey]
	return p, ok
}

// Equal reports whether two sets hold the same peers with the same contents.
//
// Compares contents rather than versions: two sets at the same version that disagree
// about their peers is precisely the failure worth detecting, and one that only compared
// versions would call it equality.
func (s *Set) Equal(other *Set) bool {
	if s == nil || other == nil {
		return s == other
	}
	if len(s.peers) != len(other.peers) {
		return false
	}
	for key, mine := range s.peers {
		theirs, ok := other.peers[key]
		if !ok || !proto.Equal(mine, theirs) {
			return false
		}
	}
	return true
}

// Diff reports what would have to change to turn s into want.
//
// The reconciler's shape: given what the host has and what it should have, produce the
// additions and removals. Returned sorted, so applying a diff twice does the same thing
// both times.
func (s *Set) Diff(want *Set) (add []*meshpv1.Peer, remove []string) {
	for _, peer := range want.Peers() {
		mine, ok := s.peers[peer.GetPublicKey()]
		if !ok || !proto.Equal(mine, peer) {
			add = append(add, peer)
		}
	}
	for _, key := range s.Keys() {
		if !want.Has(key) {
			remove = append(remove, key)
		}
	}
	return add, remove
}
