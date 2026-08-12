package session

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// keepaliveSeconds is how often a peer sends a keepalive.
//
// Twenty-five seconds is the WireGuard convention, chosen to stay under the shortest
// NAT mapping timeouts commonly seen in the wild. Getting this wrong does not break
// connectivity outright; it makes it break after a pause, which is much harder to
// diagnose.
const keepaliveSeconds = 25

// StateBuilder turns what the database says into what an agent should do.
//
// Snapshots only, for now. Deltas need version history to compute against, which is
// the next piece of work; the protocol already carries from_version so agents built
// against this will not need changing when deltas arrive (ADR-0008).
type StateBuilder struct {
	store *store.Store
}

// NewStateBuilder returns a builder reading from st.
func NewStateBuilder(st *store.Store) *StateBuilder { return &StateBuilder{store: st} }

// Snapshot returns the complete desired state for a membership.
func (b *StateBuilder) Snapshot(ctx context.Context, membershipID uuid.UUID) (*meshpv1.StateDelta, error) {
	membership, err := b.store.Queries().GetMembershipForSession(ctx, membershipID)
	if err != nil {
		return nil, fmt.Errorf("session: loading membership: %w", err)
	}

	peers, err := b.store.Queries().ListPeersForMembership(ctx, dbgen.ListPeersForMembershipParams{
		NetworkID: membership.NetworkID,
		ID:        membershipID,
	})
	if err != nil {
		return nil, fmt.Errorf("session: listing peers: %w", err)
	}

	delta := &meshpv1.StateDelta{
		// Zero means a snapshot rather than a delta from a known version.
		FromVersion: 0,
		ToVersion:   uint64(membership.StateVersion),
		UpsertPeers: make([]*meshpv1.Peer, 0, len(peers)),
		Tunnel: &meshpv1.TunnelConfig{
			// 1420 leaves room for WireGuard's overhead inside a 1500-byte path. It is a
			// starting point, not a measurement: the agent probes and reports what it
			// finds, and a wrong MTU is the usual cause of "connected but some sites
			// hang".
			Mtu: 1420,
			// No default route is claimed yet, so there is nothing to fail closed
			// around. This turns on with route groups (ADR-0011).
			FailClosed: false,
		},
	}

	for _, p := range peers {
		peer := &meshpv1.Peer{
			PublicKey:                  p.WireguardPublicKey,
			AllowedIps:                 allowedIPs(p.AddressV4, p.AddressV6),
			PersistentKeepaliveSeconds: keepaliveSeconds,
			DeviceName:                 p.DeviceName,
			Tags:                       p.Tags,
			// No endpoints and no relay yet: neither the relay nor endpoint discovery
			// exists, so an agent receiving this has peers it knows about and no way to
			// reach them. That is the honest state of the system and the next milestone.
		}
		delta.UpsertPeers = append(delta.UpsertPeers, peer)
	}

	return delta, nil
}

// allowedIPs renders a peer's addresses as single-host prefixes.
//
// A host route per address, never the whole pool: AllowedIPs is WireGuard's routing
// table, so a peer given 100.90.0.0/24 would receive traffic for every other device
// in the network. Widening it is how a mesh accidentally becomes a hub.
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
