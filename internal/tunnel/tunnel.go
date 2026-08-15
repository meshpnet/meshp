// Package tunnel converges one membership's WireGuard interface on what the control plane
// asked for.
//
// It is the join between three things that deliberately do not know about each other:
// peerset holds what the server said, wgplan decides what an interface should look like,
// and wglink talks to the kernel. This package translates and sequences, and holds no rules
// of its own — anything that looks like a rule belongs in wgplan, where it can be tested
// without privileges.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/routeprobe"
	"github.com/meshpnet/meshp/internal/wglink"
	"github.com/meshpnet/meshp/internal/wgplan"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// defaultMTU is used when the server has not said what the MTU should be.
//
// 1420 leaves room for WireGuard's overhead inside a 1500-byte path. A starting point
// rather than a measurement, and the same number the control plane sends today.
const defaultMTU = 1420

// Relay supplies the local endpoints that make relayed peers reachable.
//
// A kernel WireGuard socket cannot be intercepted, so a relayed peer is given an address
// the kernel is willing to send to: a loopback socket owned by the agent (ADR-0016). This
// package asks for one and configures it; what happens to a packet after that belongs to
// relayforward.
type Relay interface {
	// Endpoint is the local address to configure for a peer relayed through relayID.
	//
	// Creating a socket if there is not one already, which is why Desired has a side
	// effect and cannot be used to preview a configuration.
	Endpoint(publicKey, relayID string) (netip.AddrPort, error)

	// Retain stops serving every peer not named. Called only after the kernel has been
	// pointed elsewhere, because wgctrl cannot clear an endpoint and closing a socket the
	// kernel still sends to leaves a peer that looks configured and goes nowhere.
	Retain(publicKeys []string)

	// SetWireGuardPort says where inbound relayed packets should be delivered.
	//
	// The reconciler is where this becomes known: a device that has just joined asks the
	// kernel for any port, so nothing can be told the answer until the interface exists.
	SetWireGuardPort(port int)
}

// Membership is what this package needs to know about the device's place in a network.
type Membership struct {
	InterfaceName string

	// PrivateKey is this membership's WireGuard private key. One key per membership, never
	// shared (Invariant 19).
	PrivateKey string

	// AddressV4 and AddressV6 are this device's own addresses. Either may be empty.
	AddressV4 string
	AddressV6 string

	// ListenPort is the UDP port to ask for. Zero asks for any, which is what a membership
	// that has never come up says; the port the device settles on is reported back so it
	// can be kept for next time.
	ListenPort int

	// ControlURL is where this membership's control plane lives.
	//
	// Needed only to claim a default route, and not optional there: it is the address that
	// must stay reachable outside the tunnel, or the device locks itself away from the one
	// channel that could tell it to stop (ADR-0011).
	ControlURL string
}

// Reconciler applies desired state to a real interface.
//
// Safe for concurrent use: the daemon's status command reads what it last reported while a
// session may be applying the next state.
type Reconciler struct {
	link       wglink.Link
	membership Membership
	log        *slog.Logger

	// relay is nil where this build or this deployment has none. Relayed peers then get no
	// endpoint and are unreachable, which is what they were before there was a relay at all.
	relay Relay

	// filter enforces the network's policy, or is nil where this host cannot. A host that
	// cannot filter says so in its capabilities and the control plane decides what to do
	// about it (ADR-0007); what it must not do is accept a policy and ignore it.
	filter Filter

	// lastFilter is what was last successfully loaded, kept so an unchanged policy is not
	// reloaded on every reconcile. Reloading is atomic and cheap, but it resets the drop
	// counters an operator is reading.
	lastFilter *meshpv1.PacketFilter

	// chooser decides which candidate carries each group. Nil where local failover is not
	// wanted, in which case the server's order is taken verbatim — which is what this did
	// before there was a chooser.
	chooser *routeprobe.Chooser

	// egress claims the default route for a full tunnel, or is nil where this platform
	// cannot. Kept beside the filter because the two are applied together and in an order
	// that matters.
	egress Egress

	// claimed is whether this reconciler currently holds a default route, so releasing
	// happens once rather than on every pass through a state that does not want one.
	claimed bool

	// lastAdvertised is the same idea for forwarding, and matters more: reloading the NAT
	// table flushes its conntrack-independent counters and, on some kernels, disturbs
	// in-flight masqueraded flows. An unchanged assignment is left alone.
	lastAdvertised *meshpv1.AdvertisedRoutes

	mu       sync.Mutex
	kind     wglink.Kind
	up       bool
	lastErr  string
	appliedV uint64
	port     int
}

// Filter enforces a packet filter on this host.
//
// An interface so the reconciler can be tested without root, and so a platform with no
// implementation is a nil rather than a stub that pretends to enforce.
type Filter interface {
	// Apply makes the host enforce this filter. A nil filter means no policy, and must
	// remove whatever was enforced before rather than leaving it in place.
	Apply(ctx context.Context, iface string, filter *meshpv1.PacketFilter) error

	// ApplyForward makes the host carry what it advertises, or stop carrying. An empty
	// list means stop: a device that has been withdrawn must not go on being a gateway
	// nobody knows about.
	ApplyForward(ctx context.Context, iface string, groups []*meshpv1.AdvertisedRoutes_Group) error

	// ApplyLock makes the host refuse egress that does not go through the tunnel. An empty
	// interface name removes it, which is the only way it comes off: these rules are system
	// state and outlive the process on purpose (ADR-0011).
	ApplyLock(ctx context.Context, iface string, endpoints []netip.AddrPort, excluded []netip.Prefix) error
}

// Egress claims and releases a full tunnel's routing.
//
// Separate from Filter because they are different halves of the same guarantee and fail
// differently: the filter refuses traffic that would leave the wrong way, and this decides
// which way is the right one. Nil where the platform cannot do it, in which case a device
// asked for a default route reports the group unhonoured rather than half-claiming it.
type Egress interface {
	// Claim sends everything except the tunnel's own packets through the tunnel. Which
	// packets are the tunnel's own, and how they are recognised, belongs to the
	// implementation — this package has no business knowing about firewall marks.
	Claim(iface string) error

	// Release gives the routing back.
	Release() error
}

// New returns a Reconciler for one membership. relay and filter may be nil.
func New(link wglink.Link, m Membership, relay Relay, filter Filter, log *slog.Logger) *Reconciler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Reconciler{
		link: link, membership: m, relay: relay, filter: filter,
		log: log, kind: wglink.KindUnknown,
	}
}

// WithEgress gives the reconciler the ability to claim a default route.
//
// Nil is meaningful and is the ordinary case: most devices are not full-tunnel, and a host
// that cannot claim one reports the group unhonoured rather than half-claiming it.
func (r *Reconciler) WithEgress(e Egress) *Reconciler {
	r.egress = e
	return r
}

// WithChooser gives the reconciler local failover.
//
// Separate from New because a reconciler without one is a legitimate configuration — a
// build with no probing takes the server's order, which is what every device did before
// this existed — and because the chooser holds state that outlives one Apply.
func (r *Reconciler) WithChooser(c *routeprobe.Chooser) *Reconciler {
	r.chooser = c
	return r
}

// Status is what the daemon reports about this tunnel.
type Status struct {
	Up             bool
	Kind           wglink.Kind
	LastError      string
	AppliedVersion uint64

	// ListenPort is the port the interface is actually listening on, which is the kernel's
	// choice when none was asked for. Worth reporting: it is what an operator opening a
	// firewall needs, and what peers will eventually be told.
	ListenPort int
}

// Status reports the tunnel's current state.
func (r *Reconciler) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{Up: r.up, Kind: r.kind, LastError: r.lastErr,
		AppliedVersion: r.appliedV, ListenPort: r.port}
}

// Apply makes the interface match state.
//
// This is the sessionclient.Applier contract: it receives the whole desired state rather
// than a delta, because a reconciler given a target is idempotent by construction
// (Invariant 18), and the set it is given is its own to keep (Invariant 22).
//
// The returned components are the parts that did not converge, which the agent reports back
// so the control plane knows this device is not where it says it is.
func (r *Reconciler) Apply(ctx context.Context, state *peerset.Set) ([]string, error) {
	want, unhonoured, err := Desired(r.membership, state, r.relay, r.chooser, r.log)
	if err != nil {
		// A description the kernel would refuse, or one wgplan judged unsafe. Reported
		// rather than approximated: applying part of a rejected configuration is how an
		// agent ends up in a state nobody described.
		r.fail(err)
		return []string{"peers"}, err
	}

	observed, err := r.link.Observe(want.Name)
	if err != nil {
		r.fail(err)
		return []string{"interface"}, err
	}

	plan, err := wgplan.For(want, observed)
	if err != nil {
		r.fail(err)
		return []string{"peers"}, err
	}

	if !plan.Empty() {
		r.log.Debug("converging the interface", "interface", want.Name, "operations", len(plan.Ops))
		if err := wglink.ApplyPlan(r.link, want.Name, plan); err != nil {
			r.fail(err)
			return []string{"interface"}, err
		}
		r.log.Info("interface converged",
			"interface", want.Name,
			"version", state.Version(),
			"peers", len(want.Peers),
			"operations", len(plan.Ops))
	}

	// Every probe this pass costs is a read the reconciler already did. A device whose
	// gateway has gone silent therefore fails over on the next tick without sending a
	// single extra packet.
	r.observeAdvertisers(observed, state.RouteGroups())

	// Which implementation ended up behind it, read rather than assumed. ADR-0015 requires
	// this to be reportable: a silent userspace fallback makes a tenfold difference in
	// throughput an unanswerable question.
	kind, kindErr := r.link.Kind(want.Name)
	if kindErr != nil {
		kind = wglink.KindUnknown
	}

	// The port the device settled on, read rather than assumed: asking for any means the
	// kernel chose, and its choice is the thing worth keeping.
	port := want.ListenPort
	if after, err := r.link.Observe(want.Name); err == nil && after.ListenPort != 0 {
		port = after.ListenPort
	}

	// Now, and not before. The kernel has been given whatever endpoints this state calls
	// for, so a socket serving a peer that is no longer relayed is one nothing points at
	// and is safe to close (ADR-0016). On the failure paths above this is deliberately
	// skipped: a plan that did not fully apply may have left the kernel pointing at a
	// socket this would take away.
	//
	// The port is only knowable here too. A device that has just joined asks the kernel for
	// any port, so until the interface exists there is no answer to give and inbound
	// relayed packets have nowhere to be delivered.
	if r.relay != nil {
		r.relay.Retain(relayedKeys(want))
		r.relay.SetWireGuardPort(port)
	}

	// The policy last, once the interface it names exists. A ruleset referring to an
	// interface that is not there loads happily and matches nothing, so applying it first
	// would produce a host that reports a policy in force and enforces none of it.
	//
	// Reported as an unapplied component rather than as a failure of the whole apply: the
	// peers converged, and saying "this device has peers but not policy" is the honest
	// answer. The control plane can then see that this device is not where it should be
	// (ADR-0007) instead of being told the state applied cleanly.
	if unapplied := r.applyFilter(ctx, want.Name, state.Filter()); unapplied != nil {
		r.mu.Lock()
		r.kind, r.up, r.port = kind, true, port
		r.mu.Unlock()
		return unapplied, fmt.Errorf("tunnel: could not enforce this network's policy")
	}

	r.mu.Lock()
	r.kind = kind
	r.up = true
	r.lastErr = ""
	r.appliedV = state.Version()
	r.port = port
	r.mu.Unlock()

	// Named separately, because they are different failures with different fixes: a group
	// this device cannot route is a configuration problem, and a host that cannot forward is
	// a capability problem. Reporting both as one component would send an operator to the
	// wrong end of it.
	var unapplied []string
	if len(unhonoured) > 0 {
		r.log.Warn("some route groups are not being carried",
			"interface", want.Name, "groups", len(unhonoured))
		unapplied = append(unapplied, "route-groups")
	}
	// After the interface exists and before the filter, because claiming a default route
	// installs its own lock and the two must not fight over the order they load in.
	wantEgress, excluded := wantsEgress(state)
	if failed := r.applyEgress(ctx, want.Name, wantEgress, failClosedFor(state.Tunnel()),
		relayEndpointsOf(state.Relays()), excluded); failed != nil {
		unapplied = append(unapplied, failed...)
	}

	if failed := r.applyForwarding(ctx, want.Name, state.Advertised()); failed != nil {
		unapplied = append(unapplied, failed...)
	}

	// Unapplied without an error: the interface converged, and what did not is named so the
	// control plane can see this device is not where it says it is. An error here would
	// report the whole apply as failed and hide the part that worked.
	return unapplied, nil
}

// applyFilter enforces the policy, returning the components that did not apply.
//
// Skipped entirely when nothing changed. Loading is atomic and cheap, but it resets the
// counters on the drop rules, and an operator watching "is this policy denying anything"
// would see them return to zero on every reconcile tick.
func (r *Reconciler) applyFilter(ctx context.Context, iface string, want *meshpv1.PacketFilter) []string {
	if r.filter == nil {
		if want == nil {
			return nil
		}
		// A policy arrived for a host that cannot enforce one. Not an error to retry — no
		// amount of reapplying will make nftables appear — but it must be reported, or the
		// device would look converged while permitting everything its policy denies.
		r.log.Error("this network has a policy and this host cannot enforce it",
			"hint", "the control plane should not place a device with packet_filter: false in this network")
		return []string{"filter"}
	}

	if proto.Equal(r.lastFilter, want) {
		return nil
	}
	if err := r.filter.Apply(ctx, iface, want); err != nil {
		r.log.Error("could not apply this network's policy", "interface", iface, "error", err)
		return []string{"filter"}
	}

	r.lastFilter = proto.CloneOf(want)
	if want == nil {
		r.log.Info("policy withdrawn; nothing is filtered", "interface", iface)
		return nil
	}
	r.log.Info("policy applied",
		"interface", iface,
		"inbound_rules", len(want.GetInbound()),
		"outbound_rules", len(want.GetOutbound()),
		"default_deny", want.GetDefaultDeny())
	return nil
}

// observeAdvertisers folds what the interface shows into the chooser.
//
// Decisions are not acted on here. The chooser records them, and the next Apply configures
// whatever it now points at — which keeps "decide" and "converge" in the order the rest of
// this package uses, rather than reconfiguring an interface half way through reading it.
func (r *Reconciler) observeAdvertisers(observed wgplan.Observed, assignments []*meshpv1.RouteGroupAssignment) {
	if r.chooser == nil {
		return
	}
	// Deliberately not short-circuiting on an empty list. A device taken out of every route
	// group is the one case where forgetting matters most, and returning early here left it
	// holding a choice and an unsent verdict about prefixes it no longer carries.
	for _, assignment := range assignments {
		current := r.chooser.Current(assignment)
		if current == nil {
			continue
		}
		result, ok := probeFromHandshake(observed, current.GetPeerPublicKey())
		if !ok {
			continue
		}
		if decision := r.chooser.Observe(assignment, result); decision.Switched != "" {
			r.log.Info("moving to another advertiser",
				"group", logx.Safe(assignment.GetName()),
				"from", logx.Safe(decision.Switched), "to", logx.Safe(decision.Current),
				"reason", logx.Safe(decision.Reason))
		}
	}
	// A group no longer assigned should not be remembered, or a device that carried a
	// prefix for a while keeps its choice forever.
	r.chooser.Forget(assignments)
}

// applyForwarding makes this host carry what it advertises, or stop.
//
// Skipped when nothing changed, like the filter and for a sharper reason: rebuilding the NAT
// table is not free for traffic already crossing it.
//
// A nil advertisement means the control plane has said nothing about forwarding — a network
// with no route groups at all — and is left alone. An empty one means it has said this
// device carries nothing, which must reach the kernel.
func (r *Reconciler) applyForwarding(ctx context.Context, iface string, advertised *meshpv1.AdvertisedRoutes) []string {
	if advertised == nil || r.filter == nil {
		if advertised != nil && len(advertised.GetGroups()) > 0 {
			r.log.Error("this device is meant to carry prefixes and cannot forward",
				"hint", "forwarding needs nftables, which this host does not have")
			return []string{"forwarding"}
		}
		return nil
	}

	if proto.Equal(r.lastAdvertised, advertised) {
		return nil
	}
	if err := r.filter.ApplyForward(ctx, iface, advertised.GetGroups()); err != nil {
		r.log.Error("could not carry the prefixes this device advertises",
			"interface", iface, "error", err)
		return []string{"forwarding"}
	}

	r.lastAdvertised = proto.CloneOf(advertised)
	if n := len(advertised.GetGroups()); n > 0 {
		r.log.Info("carrying prefixes for the network", "interface", iface, "groups", n)
	} else {
		r.log.Info("no longer carrying anything", "interface", iface)
	}
	return nil
}

// Teardown removes everything this membership installed (Invariant 20).
func (r *Reconciler) Teardown() error {
	name := r.membership.InterfaceName

	// The policy and the forwarding first. A ruleset outliving the interface it names would
	// go on matching nothing while an operator reads a table meshp installed and no longer
	// maintains — and forwarding rules that outlived it would leave the host a gateway for a
	// network it has left.
	if r.filter != nil {
		if err := r.filter.Apply(context.Background(), name, nil); err != nil {
			r.log.Warn("could not remove this network's policy", "interface", name, "error", err)
		}
		if err := r.filter.ApplyForward(context.Background(), name, nil); err != nil {
			r.log.Warn("could not stop carrying prefixes", "interface", name, "error", err)
		}
		r.lastFilter, r.lastAdvertised = nil, nil
	}

	observed, err := r.link.Observe(name)
	if err != nil {
		return err
	}
	if err := wglink.ApplyPlan(r.link, name, wgplan.Teardown(observed)); err != nil {
		return err
	}
	r.mu.Lock()
	r.up = false
	r.kind = wglink.KindUnknown
	r.mu.Unlock()
	return nil
}

func (r *Reconciler) fail(err error) {
	r.mu.Lock()
	r.up = false
	r.lastErr = err.Error()
	r.mu.Unlock()

	// Unsupported is expected on platforms without an implementation, and logging it as an
	// error on every state update would bury the ones that matter.
	if errors.Is(err, wglink.ErrUnsupported) {
		r.log.Debug("no tunnel on this platform", "error", err)
		return
	}
	r.log.Error("could not converge the interface", "error", err)
}

// Desired turns a membership and the state it was sent into an interface description.
//
// Separate and exported so it can be tested without a kernel: everything here is a
// translation that can be wrong in a way no type would catch — an address rendered as a
// pool prefix instead of a host prefix, a peer's allowed IPs dropped because one entry
// failed to parse.
//
// Not free of side effects, despite reading like it: a relayed peer's endpoint is a socket,
// so asking relay for one creates it. That is the only order that works — the endpoint has
// to exist before the kernel can be told about it — and any socket created for a peer that
// then fails to convert is reclaimed by the next successful Retain.
//
// relay may be nil, and a relayed peer is then left without an endpoint rather than
// refused. One peer whose relay this device is not attached to must not take down the
// interface every other peer is reached through.
// The second return names route groups this device was assigned and could not carry. It is
// a translation result rather than part of the interface description, which is why it comes
// back separately: wgplan plans kernel operations, and "what is missing" is not one.
func Desired(m Membership, state *peerset.Set, relay Relay, chooser *routeprobe.Chooser, log *slog.Logger) (wgplan.Interface, []string, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if m.PrivateKey == "" {
		return wgplan.Interface{}, nil, errors.New("tunnel: this membership has no WireGuard private key")
	}

	iface := wgplan.Interface{
		Name:       m.InterfaceName,
		PrivateKey: wgplan.Key(m.PrivateKey),
		MTU:        defaultMTU,
		// The port this membership settled on before, or any if it has never come up. A
		// device in several networks needs an interface for each (ADR-0004), so they cannot
		// share one fixed port.
		ListenPort: m.ListenPort,
	}

	if mtu := int(state.Tunnel().GetMtu()); mtu > 0 {
		iface.MTU = mtu
	}

	for _, addr := range []string{m.AddressV4, m.AddressV6} {
		if addr == "" {
			continue
		}
		prefix, err := hostPrefix(addr)
		if err != nil {
			return wgplan.Interface{}, nil, fmt.Errorf("tunnel: this device's address %q: %w", addr, err)
		}
		iface.Addresses = append(iface.Addresses, prefix)
	}
	if len(iface.Addresses) == 0 {
		return wgplan.Interface{}, nil, errors.New("tunnel: this membership holds no addresses")
	}

	for _, peer := range state.Peers() {
		converted, err := peerFrom(peer, relay, log)
		if err != nil {
			// Refused rather than skipped. A peer quietly dropped is a device that cannot be
			// reached, with everything reporting success.
			return wgplan.Interface{}, nil, fmt.Errorf("tunnel: peer %s: %w",
				truncate(peer.GetPublicKey()), err)
		}
		iface.Peers = append(iface.Peers, converted)
	}

	// After the peers, because a carried prefix is added to the peer that carries it and
	// there has to be a peer to add it to.
	//
	// Reported rather than fatal: one group this device cannot honour must not cost it the
	// peers and prefixes it can.
	unhonoured := applyRouteGroups(&iface, state.RouteGroups(), chooser, log)
	return iface, unhonoured, nil
}

func peerFrom(p *meshpv1.Peer, relay Relay, log *slog.Logger) (wgplan.Peer, error) {
	peer := wgplan.Peer{
		PublicKey:        wgplan.Key(p.GetPublicKey()),
		KeepaliveSeconds: int(p.GetPersistentKeepaliveSeconds()),
	}
	for _, cidr := range p.GetAllowedIps() {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return wgplan.Peer{}, fmt.Errorf("allowed IP %q: %w", cidr, err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefix)
	}

	// A direct path wins. The list is ordered best-first and choosing between several is the
	// agent's job once there is something to choose with (ADR-0003); WireGuard holds one
	// endpoint per peer, so until then the server's first preference is the only answer.
	if endpoints := p.GetEndpoints(); len(endpoints) > 0 {
		if _, err := netip.ParseAddrPort(endpoints[0]); err != nil {
			return wgplan.Peer{}, fmt.Errorf("endpoint %q: %w", endpoints[0], err)
		}
		peer.Endpoint = endpoints[0]
		return peer, nil
	}

	// Otherwise a relay, if this device is attached to the one the peer names. meshp is
	// relay-first: this is the ordinary path, not a fallback (ADR-0002).
	relayID := p.GetRelayId()
	if relayID == "" || relay == nil {
		// No endpoint at all: reachable by nothing, which is what every peer was before
		// there was a relay. Left in the interface so its allowed IPs still resolve and the
		// device shows up as a peer without a handshake rather than not at all.
		return peer, nil
	}

	endpoint, err := relay.Endpoint(p.GetPublicKey(), relayID)
	if err != nil {
		// Not fatal. A peer relayed through somewhere this device is not attached to is
		// unreachable, and refusing the whole description would make one such peer take
		// down the interface every working peer is reached through.
		log.Warn("no relayed path to a peer",
			"peer", truncate(p.GetPublicKey()), "relay_id", logx.Safe(relayID),
			"error", logx.SafeError(err))
		return peer, nil
	}
	peer.Endpoint = endpoint.String()
	peer.Relayed = true
	return peer, nil
}

// hostPrefix renders an address as a single-host prefix.
//
// Accepts a bare address or one already carrying a prefix length, and requires the result
// to name exactly one host. A wider local address creates a connected route for the whole
// pool, so traffic to an unassigned address in it is swallowed by the tunnel rather than
// failing at once (ADR-0015).
func hostPrefix(addr string) (netip.Prefix, error) {
	if strings.Contains(addr, "/") {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return netip.Prefix{}, err
		}
		if prefix.Bits() != prefix.Addr().BitLen() {
			return netip.Prefix{}, fmt.Errorf("is not a single host")
		}
		return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Addr().BitLen()), nil
	}
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, err
	}
	parsed = parsed.Unmap()
	return netip.PrefixFrom(parsed, parsed.BitLen()), nil
}

// relayedKeys is the peers this interface reaches through a relay.
func relayedKeys(want wgplan.Interface) []string {
	out := make([]string, 0, len(want.Peers))
	for _, peer := range want.Peers {
		if peer.Relayed {
			out = append(out, string(peer.PublicKey))
		}
	}
	return out
}

func truncate(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12] + "…"
}
