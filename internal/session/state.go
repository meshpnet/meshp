package session

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/relayproto"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// keepaliveSeconds is how often a peer sends a keepalive.
//
// Twenty-five seconds is the WireGuard convention, chosen to stay under the shortest NAT
// mapping timeouts commonly seen in the wild. Getting this wrong does not break
// connectivity outright; it makes it break after a pause, which is much harder to
// diagnose.
const keepaliveSeconds = 25

// StateBuilder turns what the database says into what an agent should do.
type StateBuilder struct {
	store *store.Store

	// relays is what this deployment offers, sent to every agent as part of desired state.
	// Nil where relaying is not configured, in which case peers carry neither an endpoint
	// nor a relay and know about each other without being able to reach each other.
	relays *meshpv1.RelayConfig
}

// NewStateBuilder returns a builder reading from st.
func NewStateBuilder(st *store.Store) *StateBuilder { return &StateBuilder{store: st} }

// WithRelays returns a builder that tells agents about these relays.
func (b *StateBuilder) WithRelays(relays *meshpv1.RelayConfig) *StateBuilder {
	b.relays = relays
	return b
}

// For returns the state to send an agent that has applied fromVersion.
//
// A delta when one can be built, a snapshot otherwise. The choice is made here rather
// than by the caller, so there is one place that decides and one set of rules to reason
// about:
//
//   - An agent at version zero has nothing to build on.
//   - An agent below the network's delta floor is further behind than the log goes.
//   - An agent claiming a version ahead of the server has state we cannot explain — after
//     a database restore, or against a different deployment — and the safe answer is to
//     replace what it has rather than patch it.
//   - An agent whose delta would be larger than a snapshot may as well have the snapshot.
func (b *StateBuilder) For(ctx context.Context, membershipID uuid.UUID, fromVersion uint64) (*meshpv1.StateDelta, error) {
	membership, err := b.store.Queries().GetMembershipForSession(ctx, membershipID)
	if err != nil {
		return nil, fmt.Errorf("session: loading membership: %w", err)
	}
	head := uint64(membership.StateVersion)

	window, err := b.store.Queries().GetDeltaWindow(ctx, membership.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("session: reading the delta window: %w", err)
	}
	floor := uint64(window.OldestDeltaVersion)

	switch {
	case fromVersion == 0:
		return b.snapshot(ctx, membership)
	case fromVersion > head:
		return b.snapshot(ctx, membership)
	case fromVersion < floor:
		return b.snapshot(ctx, membership)
	case fromVersion == head:
		// Already current. An empty delta rather than nothing at all, so the agent
		// acknowledges this version and the convergence gap closes; saying nothing would
		// leave it looking behind forever.
		return &meshpv1.StateDelta{FromVersion: fromVersion, ToVersion: head}, nil
	}

	changes, err := b.store.Queries().CountStateChangesSince(ctx, dbgen.CountStateChangesSinceParams{
		NetworkID:   membership.NetworkID,
		FromVersion: int64(fromVersion),
		ToVersion:   int64(head),
	})
	if err != nil {
		return nil, fmt.Errorf("session: counting changes: %w", err)
	}
	if changes == 0 {
		// Versions moved without anything this agent can see changing — a mutation
		// elsewhere in the network, or one that only touched the agent itself. It still
		// needs to hear the new number.
		return &meshpv1.StateDelta{FromVersion: fromVersion, ToVersion: head}, nil
	}

	peers, err := b.store.Queries().ListPeersForMembership(ctx, dbgen.ListPeersForMembershipParams{
		NetworkID: membership.NetworkID,
		ID:        membershipID,
	})
	if err != nil {
		return nil, fmt.Errorf("session: listing peers: %w", err)
	}
	// A delta with more entries than the snapshot it replaces is a worse answer to the
	// same question.
	if changes > int64(len(peers)) {
		return b.snapshotFromPeers(membership, peers), nil
	}

	return b.delta(ctx, membership, fromVersion, head)
}

// Snapshot returns the complete desired state for a membership.
func (b *StateBuilder) Snapshot(ctx context.Context, membershipID uuid.UUID) (*meshpv1.StateDelta, error) {
	membership, err := b.store.Queries().GetMembershipForSession(ctx, membershipID)
	if err != nil {
		return nil, fmt.Errorf("session: loading membership: %w", err)
	}
	return b.snapshot(ctx, membership)
}

func (b *StateBuilder) snapshot(ctx context.Context, membership dbgen.GetMembershipForSessionRow) (*meshpv1.StateDelta, error) {
	peers, err := b.store.Queries().ListPeersForMembership(ctx, dbgen.ListPeersForMembershipParams{
		NetworkID: membership.NetworkID,
		ID:        membership.MembershipID,
	})
	if err != nil {
		return nil, fmt.Errorf("session: listing peers: %w", err)
	}
	return b.snapshotFromPeers(membership, peers), nil
}

func (b *StateBuilder) snapshotFromPeers(membership dbgen.GetMembershipForSessionRow, peers []dbgen.ListPeersForMembershipRow) *meshpv1.StateDelta {
	delta := &meshpv1.StateDelta{
		// Zero means a snapshot: the whole world rather than a change to it.
		FromVersion: 0,
		ToVersion:   uint64(membership.StateVersion),
		UpsertPeers: make([]*meshpv1.Peer, 0, len(peers)),
		Tunnel:      b.tunnelConfig(),
		Relays:      b.relays,
	}
	for _, p := range peers {
		delta.UpsertPeers = append(delta.UpsertPeers, b.peerFrom(
			p.WireguardPublicKey, p.DeviceName, p.Tags, p.AddressV4, p.AddressV6))
	}
	return delta
}

// delta builds the changes between two versions.
func (b *StateBuilder) delta(ctx context.Context, membership dbgen.GetMembershipForSessionRow, fromVersion, head uint64) (*meshpv1.StateDelta, error) {
	changes, err := b.store.Queries().ListStateChangesSince(ctx, dbgen.ListStateChangesSinceParams{
		NetworkID:   membership.NetworkID,
		FromVersion: int64(fromVersion),
		ToVersion:   int64(head),
	})
	if err != nil {
		return nil, fmt.Errorf("session: listing changes: %w", err)
	}

	// Collapsed in order, so a membership touched five times is sent once, and a peer
	// added and then removed within the window is only removed. The log is ordered by
	// version then id, so the last word about anything wins.
	upserts := make(map[uuid.UUID]struct{})
	removes := make(map[string]struct{})

	for _, change := range changes {
		switch change.Kind {
		case "peer_upsert":
			if change.MembershipID == nil {
				continue // the membership was deleted; its removal is logged separately
			}
			if *change.MembershipID == membership.MembershipID {
				continue // a device is never its own peer
			}
			upserts[*change.MembershipID] = struct{}{}

		case "peer_remove":
			if change.PeerPublicKey == nil {
				continue
			}
			removes[*change.PeerPublicKey] = struct{}{}
		}
	}

	delta := &meshpv1.StateDelta{
		FromVersion: fromVersion,
		ToVersion:   head,
		// Sent with every delta, not only snapshots. It is small, it changes rarely, and an
		// agent that missed the snapshot carrying it would have peers naming a relay it
		// knows nothing about.
		Relays: b.relays,
		Tunnel: b.tunnelConfig(),
	}

	for id := range upserts {
		peer, err := b.store.Queries().GetPeerForMembership(ctx, id)
		if err != nil {
			if store.IsNotFound(err) {
				// Upserted and then made unreachable — revoked, suspended, or its key
				// rotated — within the window. There is a peer_remove for whatever key it
				// had, so dropping the upsert here is correct rather than lossy.
				continue
			}
			return nil, fmt.Errorf("session: loading peer %s: %w", id, err)
		}
		// A key that is being removed and re-added in the same delta is a rotation. The
		// upsert is the newer fact, so it must not also be removed.
		delete(removes, peer.WireguardPublicKey)
		delta.UpsertPeers = append(delta.UpsertPeers, b.peerFrom(
			peer.WireguardPublicKey, peer.DeviceName, peer.Tags, peer.AddressV4, peer.AddressV6))
	}

	for key := range removes {
		delta.RemovePeerKeys = append(delta.RemovePeerKeys, key)
	}

	// Sorted, because the maps above are walked in Go's randomised order. Two computations
	// of the same delta must produce identical bytes, or every agent sees churn that is
	// not there.
	sortPeers(delta.UpsertPeers)
	sortStrings(delta.RemovePeerKeys)

	return delta, nil
}

func (b *StateBuilder) peerFrom(publicKey, deviceName string, tags []string, v4, v6 *netip.Addr) *meshpv1.Peer {
	peer := &meshpv1.Peer{
		PublicKey:                  publicKey,
		AllowedIps:                 allowedIPs(v4, v6),
		PersistentKeepaliveSeconds: keepaliveSeconds,
		DeviceName:                 deviceName,
		Tags:                       tags,
		// No endpoints. Nothing discovers where a peer is yet, so every peer is reached
		// through a relay — which is what relay-first means (ADR-0002) rather than a
		// limitation to apologise for. Endpoints arrive with discovery, and a peer that has
		// one will prefer it.
	}
	if relay := b.preferredRelay(); relay != nil {
		peer.RelayId = relay.GetId()
	}
	return peer
}

// preferredRelay is the relay this deployment offers, or nothing.
func (b *StateBuilder) preferredRelay() *meshpv1.RelayConfig_Relay {
	if b.relays == nil || len(b.relays.GetRelays()) == 0 {
		return nil
	}
	// One relay today. When there are several, this is where region and load belong — and
	// the agent is told all of them regardless, so it can fall back without asking.
	return b.relays.GetRelays()[0]
}

func (b *StateBuilder) tunnelConfig() *meshpv1.TunnelConfig {
	// 1420 leaves room for WireGuard's overhead inside a 1500-byte path.
	mtu := uint32(1420)

	// A relayed packet carries the relay's header outside the WireGuard packet, so it needs
	// a smaller tunnel. WireGuard's MTU is per interface rather than per peer, so one
	// relayed peer lowers it for all of them — and since every peer is relayed until
	// discovery exists, that is every interface today.
	//
	// Chosen over switching the MTU as peers move between relayed and direct: a changing
	// MTU makes the failure intermittent, and the failure mode is loss of large packets
	// only, which is the hardest thing to attribute. A stable conservative number costs a
	// little throughput on direct paths and nothing else.
	if b.preferredRelay() != nil {
		mtu = uint32(relayproto.RelayedTunnelMTU)
	}

	return &meshpv1.TunnelConfig{
		Mtu: mtu,
		// No default route is claimed yet, so there is nothing to fail closed around. This
		// turns on with route groups (ADR-0011).
		FailClosed: false,
	}
}

// allowedIPs renders a peer's addresses as single-host prefixes.
//
// A host route per address, never the whole pool: AllowedIPs is WireGuard's routing table,
// so a peer given 100.90.0.0/24 would receive traffic for every other device in the
// network. Widening it is how a mesh accidentally becomes a hub.
func allowedIPs(v4, v6 *netip.Addr) []string {
	out := make([]string, 0, 2)
	if v4 != nil && v4.IsValid() {
		out = append(out, netip.PrefixFrom(*v4, v4.BitLen()).String())
	}
	if v6 != nil && v6.IsValid() {
		out = append(out, netip.PrefixFrom(*v6, v6.BitLen()).String())
	}
	return out
}

// addressesOf renders a membership's own addresses for ServerHello.
func addressesOf(v4, v6 *netip.Addr) []string { return allowedIPs(v4, v6) }

func sortPeers(peers []*meshpv1.Peer) {
	sort.Slice(peers, func(i, j int) bool { return peers[i].GetPublicKey() < peers[j].GetPublicKey() })
}

func sortStrings(s []string) { sort.Strings(s) }
