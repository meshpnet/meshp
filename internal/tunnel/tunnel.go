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
	want, unhonoured, err := Desired(r.membership, state, r.relay, r.log)
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

	if len(unhonoured) > 0 {
		// Unapplied without an error: the interface converged, and what did not is named so
		// the control plane can see this device is not carrying everything it was assigned.
		// An error here would report the whole apply as failed and hide the part that worked.
		r.log.Warn("some route groups are not being carried",
			"interface", want.Name, "groups", len(unhonoured))
		return []string{"route-groups"}, nil
	}
	return nil, nil
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

// Teardown removes everything this membership installed (Invariant 20).
func (r *Reconciler) Teardown() error {
	name := r.membership.InterfaceName

	// The policy first. A ruleset outliving the interface it names would go on matching
	// nothing while an operator reads a table meshp installed and no longer maintains.
	if r.filter != nil {
		if err := r.filter.Apply(context.Background(), name, nil); err != nil {
			r.log.Warn("could not remove this network's policy", "interface", name, "error", err)
		}
		r.lastFilter = nil
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
func Desired(m Membership, state *peerset.Set, relay Relay, log *slog.Logger) (wgplan.Interface, []string, error) {
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
	unhonoured := applyRouteGroups(&iface, state.RouteGroups(), log)
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
