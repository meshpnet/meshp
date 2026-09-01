package session

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
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
	//
	// A fallback rather than the answer. What is sent is read from the relay registry on
	// every build, so that taking a relay out of service takes effect (#128); this is what
	// a deployment gets when the registry cannot be read, which is the state MESHP_RELAYS
	// described before the table had a reader. Preferring stale configuration to no relays
	// at all is deliberate: a database hiccup should not tell every agent that relaying has
	// been switched off.
	relays *meshpv1.RelayConfig

	// log is where a condition that costs a device something, but does not stop state being
	// built, is reported. Never nil — a builder constructed without one discards, so a test
	// does not have to supply a logger to get a state.
	log *slog.Logger
}

// NewStateBuilder returns a builder reading from st.
func NewStateBuilder(st *store.Store) *StateBuilder {
	return &StateBuilder{store: st, log: slog.New(slog.DiscardHandler)}
}

// WithLogger reports conditions that cost a device something without failing the build.
func (b *StateBuilder) WithLogger(l *slog.Logger) *StateBuilder {
	if l != nil {
		b.log = l
	}
	return b
}

// WithRelays returns a builder that falls back to these relays.
//
// What configuration names, kept for the case where the registry cannot be read. The
// registry is seeded from the same source at startup, so on a healthy deployment the two
// agree and this is never reached.
func (b *StateBuilder) WithRelays(relays *meshpv1.RelayConfig) *StateBuilder {
	b.relays = relays
	return b
}

// relayConfig is what agents should be told about relays right now.
//
// Read per build, beside the DNS records, and for the same reason: it is desired state, and
// desired state that was decided at startup cannot be changed without a restart. A relay
// marked draining stops appearing here, so the next state any agent is sent no longer names
// it — and because a state change is what pushes state, marking one draining has to bump the
// networks it affects, which is what the API does.
//
// Falls back to configuration when the registry cannot be read. A database that is briefly
// unwell should not be reported to every agent as "this deployment has no relays", which
// would take away the only path they have to each other (ADR-0002).
func (b *StateBuilder) relayConfig(ctx context.Context) *meshpv1.RelayConfig {
	all, err := b.store.ListRelays(ctx)
	if err != nil {
		b.log.Error("could not read the relay registry; falling back to what was configured",
			"error", err)
		return b.relays
	}

	// A deployment that has never configured relaying has nothing to say about relays, and
	// says nothing: nil, which the agent reads as "no change". Distinct from a deployment
	// whose relays are all drained, below — the registry has rows in that case, and an
	// empty list is a different message from silence.
	if len(all) == 0 {
		return nil
	}

	relays := make([]store.Relay, 0, len(all))
	for _, relay := range all {
		if relay.State == store.RelayActive {
			relays = append(relays, relay)
		}
	}
	// Empty rather than nil when every relay is drained, and the difference is
	// load-bearing. The agent treats a nil relay list as "nothing changed" and a present
	// one as "replace what you have" (peerset.Apply), so nil here would leave every agent
	// still using the relay it was told to stop using. An empty list is the instruction to
	// let go of it.
	//
	// Distinct from the failed read above, which really does mean "nothing changed": a
	// database hiccup must not be reported to every agent as "this deployment has no
	// relays", which would take away the only path they have to each other (ADR-0002).
	cfg := &meshpv1.RelayConfig{}
	for _, relay := range relays {
		cfg.Relays = append(cfg.Relays, &meshpv1.RelayConfig_Relay{
			Id:        relay.Slug,
			Endpoints: relay.Endpoints,
		})
	}
	return cfg
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
		//
		// Carries the relay list, which is the one piece of desired state that changes
		// without a version bump: draining a relay is an operator decision about the
		// deployment rather than a change to any network's contents, and bumping every
		// network on a deployment to express it would be a fan-out for something no
		// network's peers care about.
		//
		// The trade that makes this safe is what draining means. A drained relay is still
		// running and still carrying what it has; an agent that misses this nudge keeps
		// using it, which delays the drain rather than breaking anything, and corrects
		// itself on the next state change or reconnect. That would not be an acceptable
		// trade for anything an agent must act on.
		return &meshpv1.StateDelta{
			FromVersion: fromVersion,
			ToVersion:   head,
			Relays:      b.relayConfig(ctx),
		}, nil
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
		return b.snapshotFromPeers(ctx, membership, peers)
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

	return b.snapshotFromPeers(ctx, membership, peers)
}

// snapshotFromPeers builds a complete snapshot.
//
// It takes a context and returns an error because a snapshot includes the compiled filter,
// and there is exactly one place that decides what a snapshot contains. There used to be
// two paths here — this one, and a wrapper that read the peers first — and attaching the
// filter to only the wrapper meant a network whose peer count dropped below its change
// count silently sent a snapshot with no policy in it.
func (b *StateBuilder) snapshotFromPeers(ctx context.Context, membership dbgen.GetMembershipForSessionRow, peers []dbgen.ListPeersForMembershipRow) (*meshpv1.StateDelta, error) {
	// Once per build, and used in three places: what the agent is told about relays, which
	// relay each peer is reached through, and the MTU, which is lower when anything is
	// relayed. Reading it three times could produce a state describing a relay in one field
	// and not in another, if a drain landed in between.
	relays := b.relayConfig(ctx)

	delta := &meshpv1.StateDelta{
		// Zero means a snapshot: the whole world rather than a change to it.
		FromVersion: 0,
		ToVersion:   uint64(membership.StateVersion),
		UpsertPeers: make([]*meshpv1.Peer, 0, len(peers)),
		Tunnel:      b.tunnelConfig(relays, membership),
		Dns:         b.dnsConfig(ctx, membership),
		Relays:      relays,
	}
	for _, p := range peers {
		delta.UpsertPeers = append(delta.UpsertPeers, b.peerFrom(relays,
			p.WireguardPublicKey, p.DeviceName, p.DnsLabel, p.Tags, p.AddressV4, p.AddressV6))
	}

	// A snapshot describes the whole world, so it carries the filter unconditionally. An
	// agent that reconnects and is sent one with no filter would have nothing to enforce
	// until the policy next changed.
	filter, err := b.filterFor(ctx, membership)
	if err != nil {
		return nil, err
	}
	delta.Filter = filter

	// And the route groups, for the same reason: a snapshot is the whole world, so an agent
	// reconnecting would otherwise carry no prefixes until one changed.
	assignments, withdrawn, advertised, err := b.routeGroupsFor(ctx, membership)
	if err != nil {
		return nil, err
	}
	delta.RouteGroups = assignments
	delta.RemovedRouteGroupIds = withdrawn
	delta.Advertised = advertised
	return delta, nil
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
	policyChanged := false
	routesChanged := false
	// Groups that no longer exist, so the builder below cannot find them by listing what
	// does. Collected rather than counted: the delta withdraws a group by naming it.
	deletedGroups := map[string]struct{}{}

	for _, change := range changes {
		switch change.Kind {
		case "policy":
			// Names no peer: it changes what every device may do, so the answer is to
			// recompile this one's filter rather than to touch the peer list.
			policyChanged = true

		case "routes":
			// Likewise: who carries a prefix is desired state for everyone, so this
			// recomputes the assignments rather than touching peers.
			routesChanged = true

		case "tunnel":
			// Nothing to set. TunnelConfig is attached to every delta below, so this row's
			// only job is to exist: it is what stops the builder short-circuiting on "nothing
			// in this window changed" and sending a version number with no contents. Handled
			// explicitly rather than by falling through the switch, so that a reader looking
			// for where 'tunnel' is dealt with finds this instead of concluding it was
			// forgotten.

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

		case "route_group_remove":
			// Names the group, because it is gone: routeGroupsFor works out withdrawals by
			// listing the groups that exist, and a deleted one is in no such list. Without
			// this the device is told nothing and keeps carrying it (#205).
			if change.RouteGroupID == nil {
				continue
			}
			routesChanged = true
			deletedGroups[change.RouteGroupID.String()] = struct{}{}
		}
	}

	relays := b.relayConfig(ctx)

	delta := &meshpv1.StateDelta{
		FromVersion: fromVersion,
		ToVersion:   head,
		// Sent with every delta, not only snapshots. It is small, it changes rarely, and an
		// agent that missed the snapshot carrying it would have peers naming a relay it
		// knows nothing about.
		Relays: relays,
		Tunnel: b.tunnelConfig(relays, membership),
		// Alongside the tunnel configuration and for the same reason: it is small, it
		// changes rarely, and an agent that missed the snapshot carrying it would have
		// peers it cannot name.
		Dns: b.dnsConfig(ctx, membership),
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
		delta.UpsertPeers = append(delta.UpsertPeers, b.peerFrom(relays,
			peer.WireguardPublicKey, peer.DeviceName, peer.DnsLabel, peer.Tags, peer.AddressV4, peer.AddressV6))
	}

	if routesChanged {
		// Only when they changed. Recomputing on every delta would resend the whole
		// assignment set for an unrelated peer change, and an agent diffing it would
		// reinstall routes it already has.
		assignments, withdrawn, advertised, err := b.routeGroupsFor(ctx, membership)
		if err != nil {
			return nil, err
		}
		delta.RouteGroups = assignments
		delta.RemovedRouteGroupIds = withdrawn
		delta.Advertised = advertised

		// And the ones that no longer exist. Appended rather than merged into routeGroupsFor,
		// because that function answers "what does this device get from the groups there are"
		// and a deleted group is not one of them — asking it to also remember what used to
		// exist would give it two jobs and one name.
		for id := range deletedGroups {
			if !slices.Contains(delta.RemovedRouteGroupIds, id) {
				delta.RemovedRouteGroupIds = append(delta.RemovedRouteGroupIds, id)
			}
		}
		// Ordered, so two deltas describing the same change are the same message. A map's
		// iteration order is not, and a delta that differs only by ordering would make an
		// agent's diff look like a change.
		slices.Sort(delta.RemovedRouteGroupIds)
	}

	if policyChanged {
		// Only when it changed. StateDelta.filter is documented as present only when it
		// differs from what the agent holds, and sending it on every delta would make each
		// unrelated peer change rewrite every device's firewall.
		filter, err := b.filterFor(ctx, membership)
		if err != nil {
			return nil, err
		}
		delta.Filter = filter
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

func (b *StateBuilder) peerFrom(relays *meshpv1.RelayConfig, publicKey, deviceName, dnsLabel string, tags []string, v4, v6 *netip.Addr) *meshpv1.Peer {
	peer := &meshpv1.Peer{
		PublicKey:                  publicKey,
		AllowedIps:                 allowedIPs(v4, v6),
		PersistentKeepaliveSeconds: keepaliveSeconds,
		DeviceName:                 deviceName,
		DnsLabel:                   dnsLabel,
		Tags:                       tags,
		// No endpoints. Nothing discovers where a peer is yet, so every peer is reached
		// through a relay — which is what relay-first means (ADR-0002) rather than a
		// limitation to apologise for. Endpoints arrive with discovery, and a peer that has
		// one will prefer it.
	}
	if relay := preferredRelay(relays); relay != nil {
		peer.RelayId = relay.GetId()
	}
	return peer
}

// preferredRelay is the relay this deployment offers, or nothing.
//
// Takes the list rather than reading a field, because the list is now decided per build: a
// relay that was active when this process started may have been drained since.
func preferredRelay(relays *meshpv1.RelayConfig) *meshpv1.RelayConfig_Relay {
	if relays == nil || len(relays.GetRelays()) == 0 {
		return nil
	}
	// One relay today. When there are several, this is where region and load belong — and
	// the agent is told all of them regardless, so it can fall back without asking.
	return relays.GetRelays()[0]
}

// tunnelConfig is what every delta and every snapshot tells a device about its tunnel.
//
// Takes the membership rather than reading the network again, and that is the load-bearing
// detail. TunnelConfig goes out with every delta, while route group assignments are only
// recomputed when routes changed — so anything here that needed its own query would be a
// query somebody could later decide to skip on the cheap path. The fail-closed answer would
// then be right on the deltas that mention routes and wrong on the ones that do not, and
// being wrong means telling a device that is still carrying a default route to stop
// refusing egress outside it. The membership row is loaded before any of this runs and
// already carries the column.
func (b *StateBuilder) tunnelConfig(relays *meshpv1.RelayConfig, membership dbgen.GetMembershipForSessionRow) *meshpv1.TunnelConfig {
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
	if preferredRelay(relays) != nil {
		mtu = uint32(relayproto.RelayedTunnelMTU)
	}

	return &meshpv1.TunnelConfig{
		Mtu:              mtu,
		FailClosedPolicy: failClosedPolicy(membership.EgressFailClosed),
	}
}

// failClosedPolicy renders the stored answer onto the wire.
//
// Only the opt-out is ever stated. The column defaults to true, so a network holding true is
// a network nobody has said anything about — and ENFORCED would report that as a decision an
// administrator made. UNSPECIFIED is the honest word for it, and the agent reads it as closed
// anyway (ADR-0011), so nothing about the device's behaviour turns on the difference. What
// turns on it is whether the control plane is describing the world accurately, which is worth
// more here than a symmetry between the two branches.
//
// DISABLED is stated explicitly, because there the difference does matter: the agent must be
// able to tell an administrator who chose to fail open from a control plane too old to have
// an opinion, and only one of those may take the lock off.
func failClosedPolicy(enforced bool) meshpv1.TunnelConfig_FailClosed {
	if enforced {
		return meshpv1.TunnelConfig_FAIL_CLOSED_UNSPECIFIED
	}
	return meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED
}

// DefaultDNSSuffix is what a network's names end with when nobody has said otherwise.
//
// ICANN reserved `.internal` for private use, so unlike a squatted TLD it cannot be
// delegated out from under a deployment, and unlike `.local` it does not belong to mDNS
// (ADR-0021).
const DefaultDNSSuffix = "internal"

// dnsConfig tells a device what its names look like, and the names nothing can derive.
//
// `nameservers` is deliberately left empty: the resolver is the agent's own, on a loopback
// port the kernel picks, so its address is something only the device knows — the server
// naming one would be inventing an address it cannot see.
//
// Records are read here rather than passed in, and a failure to read them is logged and
// dropped rather than failing the whole state. A device that gets its peers and loses two
// administrator-entered names has lost two names; one that gets nothing has lost its
// tunnel, and the second is much worse than the first (ADR-0008).
func (b *StateBuilder) dnsConfig(ctx context.Context, membership dbgen.GetMembershipForSessionRow) *meshpv1.DnsConfig {
	suffix := membership.NetworkSlug + "." + DefaultDNSSuffix

	records, err := b.store.ListDNSRecords(ctx, membership.NetworkID)
	if err != nil {
		b.log.Error("could not read this network's DNS records",
			"network_id", membership.NetworkID, "error", err)
	}
	out := make([]*meshpv1.DnsConfig_Record, 0, len(records))
	for _, record := range records {
		out = append(out, &meshpv1.DnsConfig_Record{
			Name:       record.Name,
			Type:       record.Type,
			Value:      record.Value,
			TtlSeconds: uint32(record.TTL),
		})
	}

	return &meshpv1.DnsConfig{
		SearchDomains: []string{suffix},
		Records:       out,
		// Split DNS, stated rather than implied: only this suffix goes to the mesh
		// resolver and everything else keeps using whatever the machine already used. A
		// resolver that captured every query would break split-horizon corporate DNS on
		// the first laptop that joined.
		Routes: []*meshpv1.DnsConfig_Route{{Domain: suffix}},
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
