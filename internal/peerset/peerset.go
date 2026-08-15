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
//
// # Adding a field to StateDelta
//
// Every field this Set carries has to be handled in four places, and missing one is silent:
//
//  1. the fold in Apply, where absent means unchanged rather than cleared;
//  2. the clear in the snapshot path, since a snapshot is the whole truth and a field left
//     over from the previous state makes it a lie;
//  3. Clone, or two Sets share a pointer and Invariant 22 is gone;
//  4. Equal, or a test that folds and compares passes without ever looking at the field.
//
// This is not hypothetical. `relays` was added to the proto and to everything downstream of
// it, and not to the fold — so the agent dropped every relay the control plane sent, and the
// entire relay feature was dead on main while its own tests passed. Nothing caught it,
// because each piece was tested against a Set built by hand rather than against one this
// package produced.
//
// The mistake generalises past this package, and ADR-0018 records the shape of it.
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
	relays  *meshpv1.RelayConfig
	filter  *meshpv1.PacketFilter

	// routeGroups is keyed by id, because a delta names groups to upsert and groups to
	// withdraw rather than replacing the set.
	routeGroups map[string]*meshpv1.RouteGroupAssignment

	// advertised is what this device must forward, or nil when it has never been told.
	//
	// Present-and-empty is meaningful: it says this device carries nothing now, which a
	// device that used to carry something has to hear. That is why the wire carries a
	// message rather than a repeated field — proto3 cannot tell an empty one from an
	// absent one, and here the difference is a gateway that keeps forwarding after it
	// stopped being one.
	advertised *meshpv1.AdvertisedRoutes
}

// New returns an empty set at version zero.
func New() *Set {
	return &Set{
		peers:       make(map[string]*meshpv1.Peer),
		routeGroups: make(map[string]*meshpv1.RouteGroupAssignment),
	}
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

// Filter is the packet filter last received, or nil when this network has no policy.
//
// Nil and empty are different answers and must stay that way: nil means nobody has written
// a policy, so everything is permitted, while an empty filter with default_deny set means
// a policy exists and permits nothing.
func (s *Set) Filter() *meshpv1.PacketFilter { return s.filter }

// RouteGroups are the carried prefixes this device has been assigned, ordered by id.
//
// Sorted, so two sets with the same contents render identically and a reconciler comparing
// them does not mistake map order for a change.
func (s *Set) RouteGroups() []*meshpv1.RouteGroupAssignment {
	out := make([]*meshpv1.RouteGroupAssignment, 0, len(s.routeGroups))
	for _, g := range s.routeGroups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetRouteGroupId() < out[j].GetRouteGroupId() })
	return out
}

// Advertised is what this device must forward, or nil when it has never been told.
func (s *Set) Advertised() *meshpv1.AdvertisedRoutes { return s.advertised }

// Relays is the relay configuration last received, or nil.
//
// A peer's relay_id names one of these, so an agent that did not keep them would know a
// peer is relayed and have no way to find the relay.
func (s *Set) Relays() *meshpv1.RelayConfig { return s.relays }

// Relay returns the relay with this id.
//
// Looked up by id rather than taking the first, because relay_id is the peer's answer to
// "through which one" and honouring it is the whole point of sending several.
func (s *Set) Relay(id string) (*meshpv1.RelayConfig_Relay, bool) {
	if id == "" {
		return nil, false
	}
	for _, relay := range s.relays.GetRelays() {
		if relay.GetId() == id {
			return relay, true
		}
	}
	return nil, false
}

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

	snapshot := delta.GetFromVersion() == 0
	if snapshot {
		s.peers = make(map[string]*meshpv1.Peer, len(delta.GetUpsertPeers()))
		// And the configuration that came with them. A snapshot describes the whole world,
		// so a snapshot carrying no relays means this deployment has none — keeping the
		// previous ones would leave an agent dialling a relay that has been decommissioned
		// and reporting itself relayed through it.
		s.relays = nil
		// The same for the filter, and here it is a security property rather than a
		// housekeeping one: a policy that has been withdrawn must stop being enforced, and
		// an agent that kept the last filter it saw would go on denying traffic its network
		// no longer denies, with nothing to say why.
		s.filter = nil
		// And the assignments. A snapshot describes the whole world, so one naming no route
		// groups means this device carries nothing — keeping the last set would leave it
		// routing a prefix its network no longer asks it to.
		s.routeGroups = make(map[string]*meshpv1.RouteGroupAssignment)
		s.advertised = nil
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
	// Absent in a delta means unchanged, which is why the snapshot case cleared it above:
	// there is otherwise no way for a server to say "no relays any more".
	if delta.GetRelays() != nil {
		s.relays = proto.CloneOf(delta.GetRelays())
	}
	if delta.GetFilter() != nil {
		s.filter = proto.CloneOf(delta.GetFilter())
	}

	// Withdrawals first, so a group both withdrawn and reassigned in one delta ends up
	// assigned — the same rule the peer list uses, and for the same reason: the upsert is
	// the newer fact.
	for _, id := range delta.GetRemovedRouteGroupIds() {
		delete(s.routeGroups, id)
	}
	for _, group := range delta.GetRouteGroups() {
		s.routeGroups[group.GetRouteGroupId()] = proto.CloneOf(group)
	}
	if delta.GetAdvertised() != nil {
		s.advertised = proto.CloneOf(delta.GetAdvertised())
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
	if s.relays != nil {
		out.relays = proto.CloneOf(s.relays)
	}
	if s.filter != nil {
		out.filter = proto.CloneOf(s.filter)
	}
	out.routeGroups = make(map[string]*meshpv1.RouteGroupAssignment, len(s.routeGroups))
	for id, group := range s.routeGroups {
		out.routeGroups[id] = proto.CloneOf(group)
	}
	if s.advertised != nil {
		out.advertised = proto.CloneOf(s.advertised)
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

// Equal reports whether two sets hold the same peers and the same configuration.
//
// Compares contents rather than versions: two sets at the same version that disagree
// about their peers is precisely the failure worth detecting, and one that only compared
// versions would call it equality.
//
// The tunnel and relay configuration count. They are desired state like the peers are, and
// leaving them out would mean Invariant 21 — apply(snapshot at F, delta F→H) == snapshot at
// H — held while an agent folded deltas into the wrong relay, which is a way to be
// unreachable with every check reporting agreement.
func (s *Set) Equal(other *Set) bool {
	if s == nil || other == nil {
		return s == other
	}
	if len(s.peers) != len(other.peers) {
		return false
	}
	if !proto.Equal(s.tunnel, other.tunnel) || !proto.Equal(s.relays, other.relays) {
		return false
	}
	if !proto.Equal(s.filter, other.filter) {
		return false
	}
	if !proto.Equal(s.advertised, other.advertised) {
		return false
	}
	if len(s.routeGroups) != len(other.routeGroups) {
		return false
	}
	for id, mine := range s.routeGroups {
		theirs, ok := other.routeGroups[id]
		if !ok || !proto.Equal(mine, theirs) {
			return false
		}
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
