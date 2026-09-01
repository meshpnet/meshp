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
	"maps"
	"net/netip"
	"strings"
	"sync"
	"time"

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

	// lock refuses egress outside the tunnel, or is nil where this host cannot. Separate
	// from filter because a platform can have one and not the other — see EgressLock.
	lock EgressLock

	// lastFilter is what was last successfully loaded, kept so an unchanged policy is not
	// reloaded on every reconcile. Reloading is atomic and cheap, but it resets the drop
	// counters an operator is reading.
	lastFilter *meshpv1.PacketFilter

	// claims is shared with every other membership on this device, so a prefix two
	// networks both carry can be seen as contested from either side. Nil where nothing
	// shares it, which is every test that builds one reconciler.
	claims *Claims

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

	// prober sends real traffic through the tunnel to decide whether a path works, or is
	// nil where this platform cannot bind a socket to an interface. Nil means the handshake
	// is the whole verdict, which is what every device did before this existed.
	prober Prober

	// names is where this membership publishes what its network can resolve, shared with
	// every other membership on the device so a bare name matching two of them can be seen
	// as ambiguous from either side. Nil where nothing resolves.
	names Names

	// systemResolver points the host's own resolver at the agent for this network's names,
	// or is nil on a host where meshp cannot configure one and put it back.
	systemResolver SystemResolver

	// resolverAddr is where the agent answers, read at call time because the port is the
	// kernel's choice and is not known when this is built.
	resolverAddr func() netip.AddrPort

	// clock is overridable so the probe interval can be tested without waiting. Nil means
	// the wall clock.
	clock func() time.Time

	mu sync.Mutex

	// announced is what was last said about the host's resolver, so the log gets a line
	// when that changes rather than one on every reconcile tick. The ask itself is made
	// every pass — see applySystemResolver.
	announced systemResolverState

	// lastMapped is what was last installed, so an unchanged set is not reinstalled on every
	// reconcile. Rebuilding the table is atomic but not free, and it runs on a timer.
	lastMapped map[netip.Prefix]netip.Prefix

	// lastProbe is when each group was last probed, so a group can ask to be quieter than
	// the daemon's reconcile interval. Under mu because Apply is entered both from the
	// session's applier and from the reconcile ticker.
	lastProbe map[string]time.Time

	kind     wglink.Kind
	up       bool
	lastErr  string
	appliedV uint64
	port     int

	// relayed is the peers this membership reaches through a relay, by public key, as of
	// the last state applied. Kept so a path report can say how a peer is reached without
	// inferring it from the endpoint address (see notePaths).
	relayed map[string]bool
}

// EgressLock makes the host refuse traffic that does not go through the tunnel.
//
// Separate from Filter, which it was part of until macOS needed one without the other. They
// are both "the packet filter" on Linux and one implementation satisfies both, but they
// answer different questions and the reconciler has always treated them that way: a host
// with no filter cannot enforce a *policy* and reports `filter` unapplied, while a host with
// no lock cannot *fail closed* and reports `egress`. Those are separate capabilities with
// separate consequences, and combining them meant a platform had to have both or neither.
//
// The alternative was a macOS implementation of Filter that did the lock and refused
// everything else, which would have a device claim it can enforce a policy and then fail on
// every one — the dishonesty ADR-0007 and ADR-0011 are written against.
type EgressLock interface {
	// ApplyLock makes the host refuse egress that does not go through the tunnel. An empty
	// interface name removes it, which is the only way it comes off: these rules are system
	// state and outlive the process on purpose (ADR-0011).
	ApplyLock(ctx context.Context, iface string, endpoints []netip.AddrPort, excluded []netip.Prefix, preventDNSLeaks bool) error
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

	// ApplyMap makes this host reach colliding prefixes at the ranges allocated for them.
	// An empty map means nothing collides and must remove whatever was installed before,
	// or a device that left a network keeps rewriting for it.
	ApplyMap(ctx context.Context, iface string, mapped map[netip.Prefix]netip.Prefix) error

	// ForwardObstacles names anything else on this host that drops forwarded packets, as
	// strings an operator can go and look at. Empty means nothing was found, which is not
	// the same as nothing being there.
	//
	// Here rather than called directly, so this reconciler can be tested against a host
	// that refuses — a condition that otherwise needs root, a real ruleset, and a machine
	// nobody minds breaking.
	ForwardObstacles(ctx context.Context) ([]string, error)
}

// Egress claims and releases a full tunnel's routing.
//
// Separate from Filter because they are different halves of the same guarantee and fail
// differently: the filter refuses traffic that would leave the wrong way, and this decides
// which way is the right one. Nil where the platform cannot do it, in which case a device
// asked for a default route reports the group unhonoured rather than half-claiming it.
type Egress interface {
	// Claim sends everything except the tunnel's own packets through the tunnel.
	//
	// The carve-out is passed rather than left to the implementation, which it was until
	// macOS needed it. Linux recognises the tunnel's own packets by a firewall mark and so
	// needs nothing here; macOS has no equivalent, and keeps the tunnel reachable by
	// routing its endpoints around the tunnel explicitly. Both are "how this platform knows
	// which packets are its own", which is the implementation's business — but only one of
	// them can work it out unaided.
	//
	// endpoints are the control plane and the relays; excluded is everything else that must
	// stay off the tunnel. Losing either is how a device routes its own outer packets into
	// its own tunnel and disappears.
	Claim(iface string, endpoints []netip.AddrPort, excluded []netip.Prefix) error

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
		lastProbe: make(map[string]time.Time),
	}
}

// now is the reconciler's idea of the time.
func (r *Reconciler) now() time.Time {
	if r.clock == nil {
		return time.Now()
	}
	return r.clock()
}

// WithClaims lets this reconciler see what other memberships on the device carry.
//
// Nil is safe and means "nothing else is running here", which is true of a device in one
// network and of every test that builds a single reconciler.
func (r *Reconciler) WithClaims(c *Claims) *Reconciler {
	r.claims = c
	return r
}

// WithEgress gives the reconciler the ability to claim a default route.
//
// Nil is meaningful and is the ordinary case: most devices are not full-tunnel, and a host
// that cannot claim one reports the group unhonoured rather than half-claiming it.
// WithLock lets this reconciler make the host refuse traffic that leaves outside the tunnel.
//
// Nil means it cannot, and a network asking devices to fail closed is reported unhonoured
// rather than claimed and not enforced (ADR-0011). On Linux this is the same object as the
// filter; on a platform that has one and not the other it is not.
func (r *Reconciler) WithLock(l EgressLock) *Reconciler {
	r.lock = l
	return r
}

func (r *Reconciler) WithEgress(e Egress) *Reconciler {
	r.egress = e
	return r
}

// WithProber lets this reconciler send traffic through an advertiser to find out whether the
// path works, rather than only asking whether the advertiser answered a handshake.
//
// Nil is meaningful and is the ordinary case on anything but Linux: a host that cannot bind a
// socket to an interface has no way to guarantee the probe went through the tunnel, and a
// measurement of the wrong path is worse than none.
func (r *Reconciler) WithProber(p Prober) *Reconciler {
	r.prober = p
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
	want, unhonoured, err := Desired(r.membership, state, r.relay, r.chooser, r.claims, r.filter != nil, r.log)
	if err != nil {
		// A description the kernel would refuse, or one wgplan judged unsafe. Reported
		// rather than approximated: applying part of a rejected configuration is how an
		// agent ends up in a state nobody described.
		r.fail(err)
		return []string{"peers"}, err
	}

	// The names this network can answer for, before anything touches the kernel.
	//
	// Deliberately not after the interface converges. A name is desired state the agent
	// already holds — the same peer list it is about to hand to WireGuard — so it does not
	// depend on the kernel having accepted anything, and a host whose interface will not
	// come up should still be able to say what `fileserver` means. Publishing after the
	// convergence would have tied one to the other for no reason beyond where the line
	// happened to sit.
	r.publishNames(state)

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

	// The handshake half of this costs nothing — the reconciler has already read it from the
	// kernel — so a device whose gateway has gone silent fails over on the next tick without
	// sending a packet. The probe half does send traffic, and only for groups whose
	// administrator named targets, only when the handshake says the advertiser is up, and no
	// more often than that group's probe interval allows.
	r.observeAdvertisers(ctx, want.Name, observed, state.RouteGroups())

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
	relayedNow := relayedKeys(want)
	// Recorded whether or not there is a relay implementation behind it, because the
	// report describes what this state asked for and a build with no relay simply asks
	// for none.
	r.notePaths(relayedNow)
	if r.relay != nil {
		r.relay.Retain(relayedNow)
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
	if failed := r.applyEgress(ctx, want.Name, want.Addresses, wantEgress, failClosedFor(state.Tunnel()),
		state.DNS().GetPreventLeaks(), relayEndpointsOf(state.Relays()), excluded); failed != nil {
		unapplied = append(unapplied, failed...)
	}

	// Before the forwarding and after the interface, because the rules name an interface
	// that has to exist and rewrite traffic the routes above will start sending.
	if failed := r.applyMappings(ctx, want.Name, want.Mapped); failed != nil {
		unapplied = append(unapplied, failed...)
	}

	if failed := r.applyForwarding(ctx, want.Name, state.Advertised()); failed != nil {
		unapplied = append(unapplied, failed...)
	}

	// The host's resolver last, and after the interface exists: systemd-resolved configures
	// a link, so there has to be one. Reported as an unapplied component rather than as a
	// failed apply — a device with peers, policy and routes but no names is worse off than
	// one with all four, and much better off than one that reports the whole state as
	// failed and stops converging on the rest.
	if failed := r.applySystemResolver(ctx, want.Name, state); failed != nil {
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
func (r *Reconciler) observeAdvertisers(ctx context.Context, iface string, observed wgplan.Observed, assignments []*meshpv1.RouteGroupAssignment) {
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

		// The handshake first, and the probe only if it passed. A stale handshake already
		// says the advertiser is unreachable, so dialling through it would spend packets to
		// reach the same answer — and the tunnel the probe would travel through is the thing
		// the handshake just reported as gone.
		if result.Reachable {
			if probed, failed, ran := r.probeThroughAdvertiser(ctx, iface, assignment); ran {
				result = probed
				result.Failed = failed
				if !result.Reachable {
					// Said plainly, because this is the case the handshake gets wrong and the
					// reason this exists: the advertiser answered, and nothing behind it did.
					r.log.Warn("this advertiser is up but nothing gets through it",
						"group", logx.Safe(assignment.GetName()),
						"advertiser", logx.Safe(current.GetAdvertiserId()),
						"failed_targets", len(failed))
				}
			}
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

// applyMappings makes this host reach colliding prefixes at the ranges allocated for them.
//
// Applied whenever the set changes, and applied empty when it becomes empty: a device that
// left one of two colliding networks stops colliding, and rules left rewriting for a network
// it is no longer in would send its traffic to an address it can no longer reach.
//
// A host with no filter never gets here with anything to do. Desired refuses the mapping on a
// host that cannot translate, so want.Mapped is empty and the colliding groups were already
// reported unhonoured — the honest refusal rather than a route into nothing.
func (r *Reconciler) applyMappings(ctx context.Context, iface string, mapped map[netip.Prefix]netip.Prefix) []string {
	if r.filter == nil {
		return nil
	}
	if len(mapped) == 0 && len(r.lastMapped) == 0 {
		return nil
	}
	if maps.Equal(mapped, r.lastMapped) {
		return nil
	}
	if err := r.filter.ApplyMap(ctx, iface, mapped); err != nil {
		r.log.Error("could not reach colliding prefixes at the ranges allocated for them",
			"interface", iface, "error", logx.SafeError(err),
			"consequence", "the customers sharing those addresses are not reachable")
		return []string{"mapping"}
	}
	r.lastMapped = maps.Clone(mapped)
	if len(mapped) > 0 {
		r.log.Info("reaching colliding prefixes at their allocated ranges",
			"interface", iface, "mappings", len(mapped))
	} else {
		r.log.Info("no longer translating any prefixes", "interface", iface)
	}
	return nil
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
		// Installed is not the same as working, and this is the one place that difference
		// is invisible. Every base chain at a hook runs and a drop in any of them ends the
		// packet, so another table refusing forwarded traffic defeats a ruleset meshp
		// rendered correctly — and nothing above would notice: the rules are right, the
		// group is applied, and nothing crosses.
		return r.reportForwardObstacles(ctx)
	}
	r.log.Info("no longer carrying anything", "interface", iface)
	return nil
}

// reportForwardObstacles says when something else on the host will drop what this device
// carries, and reports the forwarding unapplied when it does.
//
// Unapplied rather than a warning alone, because the control plane is where an operator sees
// whether an advertiser is doing its job. An advertiser that renders a correct ruleset and
// carries nothing must not appear healthy — a route group would fail over to it and traffic
// would stop, with every diagnostic saying the group was applied.
//
// Only when this device actually carries something. A host with a strict forward policy and
// nothing to forward has no problem, and telling it otherwise is a warning that trains people
// to ignore warnings.
func (r *Reconciler) reportForwardObstacles(ctx context.Context) []string {
	found, err := r.filter.ForwardObstacles(ctx)
	if err != nil {
		// Not knowing is the state this was in before it could ask, so it is not a reason
		// to declare the forwarding broken. Said at debug because a host where nft cannot
		// be read has louder problems than this.
		r.log.Debug("could not check what else might refuse forwarded packets",
			"error", logx.SafeError(err))
		return nil
	}
	if len(found) == 0 {
		return nil
	}

	r.log.Error("something else on this host drops forwarded packets, so this device may carry nothing",
		"refused_by", logx.Safe(strings.Join(found, ", ")),
		"why", "every chain at a hook runs and a drop in any of them wins; meshp cannot undo it from its own table",
		"hint", "docker sets this policy by default; allow forwarding for this interface or remove the drop")
	return []string{"forwarding"}
}

// Teardown removes everything this membership installed (Invariant 20).
func (r *Reconciler) Teardown() error {
	name := r.membership.InterfaceName

	// The names first, because they are the only thing here that keeps answering after the
	// rest is gone. A device that left a network and went on resolving its names would send
	// somebody to `fileserver.acme.internal` and hand them an address it can no longer
	// reach — a confident wrong answer, which is the failure this whole subsystem is
	// arranged to avoid.
	if r.names != nil {
		r.names.Forget(name)
	}

	// Then the host's resolver, explicitly, before anything that can fail. Destroying the
	// link below does make systemd-resolved drop the link's configuration, so this is
	// belt and braces — but only for the path where the teardown completes. Observing the
	// interface can fail and return early, and leaving a live link pointed at a resolver
	// that has stopped answering for this network is worse than a stale rule: every query
	// for those names would go somewhere that no longer knows them.
	if r.systemResolver != nil {
		if err := r.systemResolver.Revert(context.Background(), name); err != nil {
			r.log.Warn("could not put this machine's resolver back",
				"interface", name, "error", logx.SafeError(err))
		}
		r.mu.Lock()
		r.announced = systemResolverState{}
		r.mu.Unlock()
	}

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
		// And the translation, or a device that left one of two colliding networks goes on
		// rewriting for it — sending traffic addressed to a range it no longer routes at a
		// customer it can no longer reach (Invariant 20).
		if err := r.filter.ApplyMap(context.Background(), name, nil); err != nil {
			r.log.Warn("could not stop translating for this network", "interface", name, "error", err)
		}
		r.lastFilter, r.lastAdvertised, r.lastMapped = nil, nil, nil
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
func Desired(m Membership, state *peerset.Set, relay Relay, chooser *routeprobe.Chooser, claims *Claims, canTranslate bool, log *slog.Logger) (wgplan.Interface, []string, error) {
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
	unhonoured := applyRouteGroups(&iface, state.RouteGroups(), chooser, claims, canTranslate, log)
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
