// Package wgplan turns desired and observed interface state into an ordered list of
// operations, without touching anything.
//
// It exists so that the rules about what a WireGuard interface should look like are
// decided somewhere that can be tested exhaustively, on any platform, without
// privileges. What is left for the platform layer is applying operations one at a time,
// which is thin enough to test against a real interface without enumerating cases there.
//
// Three properties matter, and all three are the kind that fail silently:
//
//   - Planning against state that already matches produces no operations at all
//     (Invariant 18). An agent that reconfigures an interface on every tick tears down
//     working sessions to arrive back where it was.
//   - Removals are emitted before additions. When a prefix moves from one peer to
//     another, additions first would hand it to the new peer and then the removal would
//     take it away again — leaving the address unreachable while both versions look
//     correct in isolation.
//   - Two peers may never hold overlapping allowed IPs. WireGuard gives a contested
//     prefix to whichever peer was configured last and silently takes it from the
//     other, so the check has to happen here rather than being discovered as an
//     unreachable device.
package wgplan

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Key is a WireGuard public or private key in its base64 form.
//
// A string rather than the 32 bytes, because this package never does anything with a key
// but compare it and pass it on. Parsing belongs where the key reaches the kernel.
type Key string

// Peer is one peer of an interface.
type Peer struct {
	PublicKey Key

	// AllowedIPs is the cryptokey routing table for this peer: which destinations are
	// encrypted to it, and which source addresses are accepted from it. Not a system
	// route — see ADR-0015 — and not something the agent widens on its own.
	AllowedIPs []netip.Prefix

	// Endpoint is where to send this peer's traffic, when anywhere is known. Unset means
	// the peer is configured and currently unreachable, which is a normal state before a
	// path has been found rather than an error.
	Endpoint string

	// Relayed says this endpoint is a loopback socket the agent itself serves, forwarding to
	// and from a relay (ADR-0016).
	//
	// Stated rather than inferred from the address. It would be tempting to test whether the
	// endpoint is a loopback address, but that would leave the important part unsaid: a
	// loopback endpoint requires a live socket behind it, and wgctrl cannot clear an
	// endpoint — writing a peer with none leaves whatever was there. So a peer pointing at
	// 127.0.0.1 must keep something serving that address until a different endpoint is
	// written, and only the agent knows whether it intends to.
	Relayed bool

	// PresharedKey is optional per-pair symmetric material.
	PresharedKey Key

	// KeepaliveSeconds keeps a NAT mapping open. Zero means none.
	KeepaliveSeconds int

	// HasHandshake and HandshakeAge describe whether this peer has completed a handshake
	// and how long ago. Reported by the device; meaningless in a desired peer and never
	// compared. They exist because whether a peer's current endpoint is working decides
	// whether replacing it is a repair or a regression.
	HasHandshake bool
	HandshakeAge time.Duration
}

// endpointGrace is how recently a peer must have handshaked for its endpoint to count as
// working.
//
// WireGuard abandons a session after REJECT_AFTER_TIME — 180 seconds — so a peer that has
// not handshaked within that is not reaching anyone at its current endpoint. Inside it, the
// endpoint is carrying traffic, and evidence beats the control plane's opinion.
const endpointGrace = 180 * time.Second

// Interface is the desired state of one membership's interface.
type Interface struct {
	Name       string
	PrivateKey Key

	// ListenPort is the UDP port to listen on. Zero means any, and is not the same as
	// "some particular port that happens to be zero": a device holding memberships in
	// several networks needs one interface per membership (ADR-0004), so they cannot all
	// ask for the same port, and until the port is distributed to peers there is nothing
	// to be gained by pinning it.
	//
	// Treated as "leave whatever is there" when comparing, because the kernel answers
	// with the port it chose. Requiring a match would rewrite the device on every
	// reconcile, and rewriting a device resets every session on it — the interface would
	// drop traffic once a tick, forever, for no reason.
	ListenPort int

	MTU int

	// Addresses are this device's own addresses, as host prefixes. See ADR-0015 for why
	// they are not the pool prefix.
	Addresses []netip.Prefix

	Peers []Peer
}

// Observed is what the platform reports an existing interface currently holds.
//
// Exists is false when there is no interface at all, which is different from an
// interface that exists and is empty: the first needs creating, the second does not.
type Observed struct {
	Exists bool

	// Up is whether the interface is administratively up. Tracked because an interface
	// that exists but is down needs bringing up, and a plan that only ever raised
	// interfaces it created itself would leave one down forever — after a restart, or
	// after anything else on the host took it down.
	Up bool

	PrivateKey Key
	ListenPort int
	MTU        int
	Addresses  []netip.Prefix
	Peers      []Peer

	// Routes currently pointing at this interface. Only these are candidates for
	// removal: a route through some other interface is not ours to withdraw, whatever it
	// covers (Invariant 20 is about removing what we installed, not what we found).
	Routes []netip.Prefix
}

// OpKind is what an operation does.
type OpKind int

const (
	// CreateDevice brings the interface into existence.
	CreateDevice OpKind = iota
	// SetDevice sets the private key, listen port and MTU.
	SetDevice
	// RemovePeer removes a peer by public key.
	RemovePeer
	// SetPeer adds a peer or replaces its configuration.
	SetPeer
	// RemoveAddress takes an address off the interface.
	RemoveAddress
	// AddAddress puts an address on the interface.
	AddAddress
	// RemoveRoute withdraws a route that pointed at the interface.
	RemoveRoute
	// AddRoute points a prefix at the interface.
	AddRoute
	// BringUp marks the interface up.
	//
	// Before the routes and after everything else, which is not a preference: the kernel
	// refuses to attach a route to a link that is down, and reports it as "network is
	// down" from the route call rather than from anywhere near the cause. By this point
	// the key, the peers and the addresses are set, so everything governing what may
	// enter or leave the interface is already in force — what is still missing are the
	// routes that let this host send, which is the safe thing to be missing.
	BringUp
	// DestroyDevice removes the interface entirely.
	DestroyDevice
)

func (k OpKind) String() string {
	switch k {
	case CreateDevice:
		return "create-device"
	case SetDevice:
		return "set-device"
	case RemovePeer:
		return "remove-peer"
	case SetPeer:
		return "set-peer"
	case RemoveAddress:
		return "remove-address"
	case AddAddress:
		return "add-address"
	case RemoveRoute:
		return "remove-route"
	case AddRoute:
		return "add-route"
	case BringUp:
		return "bring-up"
	case DestroyDevice:
		return "destroy-device"
	default:
		return fmt.Sprintf("op(%d)", int(k))
	}
}

// Device is the interface's own settings, as carried by a SetDevice operation.
type Device struct {
	PrivateKey Key
	ListenPort int
	MTU        int
}

// Op is one thing to do to the interface.
//
// Every operation carries what it needs. A plan is therefore applicable on its own, and
// whoever applies it cannot disagree with it: an operation that meant "set the device to
// whatever the caller happens to be holding" would let the plan and the values applied
// drift apart, which is the failure this package exists to make impossible.
type Op struct {
	Kind OpKind

	// Peer is set for SetPeer and RemovePeer. For RemovePeer only PublicKey is
	// meaningful.
	Peer Peer

	// Device is set for SetDevice.
	Device Device

	// Prefix is set for the address and route operations.
	Prefix netip.Prefix
}

// String renders an operation for logs and test failures.
func (o Op) String() string {
	switch o.Kind {
	case SetPeer, RemovePeer:
		return fmt.Sprintf("%s %s", o.Kind, o.Peer.PublicKey)
	case SetDevice:
		// The key is not printed. This renders into logs, and a private key in a log is
		// still a private key (Invariant 1).
		return fmt.Sprintf("%s port=%d mtu=%d", o.Kind, o.Device.ListenPort, o.Device.MTU)
	case AddAddress, RemoveAddress, AddRoute, RemoveRoute:
		return fmt.Sprintf("%s %s", o.Kind, o.Prefix)
	default:
		return o.Kind.String()
	}
}

// Plan is the ordered work needed to make an interface match what was asked for.
type Plan struct {
	Ops []Op
}

// Empty reports whether there is nothing to do.
func (p Plan) Empty() bool { return len(p.Ops) == 0 }

// String renders a plan one operation per line.
func (p Plan) String() string {
	if p.Empty() {
		return "(nothing to do)"
	}
	var b strings.Builder
	for i, op := range p.Ops {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(op.String())
	}
	return b.String()
}

// For returns the operations that turn observed into want.
//
// An error means want is not a configuration that should be applied at all, and nothing
// is returned to apply partially. Refusing outright is deliberate: the alternative is an
// agent that converges onto a broken interface and reports success, and the symptom of
// that arrives later as a device nobody can reach.
func For(want Interface, observed Observed) (Plan, error) {
	if err := want.Validate(); err != nil {
		return Plan{}, err
	}

	var plan Plan
	add := func(op Op) { plan.Ops = append(plan.Ops, op) }

	if !observed.Exists {
		add(Op{Kind: CreateDevice})
	}

	// The device's own settings. Compared rather than always written, so a steady state
	// produces no operations: setting a private key again resets every session on the
	// interface, which would drop traffic on a tick that had nothing to change.
	portWrong := want.ListenPort != 0 && observed.ListenPort != want.ListenPort
	if !observed.Exists ||
		observed.PrivateKey != want.PrivateKey ||
		portWrong ||
		observed.MTU != want.MTU {
		add(Op{Kind: SetDevice, Device: Device{
			PrivateKey: want.PrivateKey,
			ListenPort: want.ListenPort,
			MTU:        want.MTU,
		}})
	}

	// Peers. Removals first, so a prefix moving between peers is given up before it is
	// claimed.
	wantPeers := indexPeers(want.Peers)
	havePeers := indexPeers(observed.Peers)

	for _, key := range sortedKeys(havePeers) {
		if _, keep := wantPeers[key]; !keep {
			add(Op{Kind: RemovePeer, Peer: Peer{PublicKey: key}})
		}
	}
	for _, key := range sortedKeys(wantPeers) {
		desired := wantPeers[key]
		current, exists := havePeers[key]
		if !exists {
			add(Op{Kind: SetPeer, Peer: desired})
			continue
		}
		// Stopping relaying with nothing to replace the endpoint is the one change a single
		// SetPeer cannot express: wgctrl treats an absent endpoint as "leave it", so the peer
		// would keep pointing at a loopback socket about to stop existing. Removing and
		// re-adding is the only way to clear one. It costs that peer's session, which is
		// unavoidable and better than a silent black hole.
		if isLoopback(current.Endpoint) && !desired.Relayed && desired.Endpoint == "" {
			add(Op{Kind: RemovePeer, Peer: Peer{PublicKey: key}})
			add(Op{Kind: SetPeer, Peer: desired})
			continue
		}

		if write, peer := resolvePeer(current, desired); write {
			add(Op{Kind: SetPeer, Peer: peer})
		}
	}

	// Addresses before routes: a route needs the interface to hold an address in the
	// family it is for.
	addPrefixOps(&plan, observed.Addresses, want.Addresses, RemoveAddress, AddAddress)

	// Then up, because the kernel will not attach a route to a link that is down.
	if !observed.Exists || !observed.Up {
		add(Op{Kind: BringUp})
	}

	// Every peer's own addresses are routed at the interface. Derived rather than
	// supplied, because a route to a peer that is not configured would be a black hole,
	// and the two lists would then have to be kept in step by whoever calls this.
	addPrefixOps(&plan, observed.Routes, wantRoutes(want), RemoveRoute, AddRoute)

	return plan, nil
}

// Validate reports whether an interface is a configuration worth applying.
func (i Interface) Validate() error {
	if i.Name == "" {
		return fmt.Errorf("wgplan: an interface needs a name")
	}
	if i.PrivateKey == "" {
		return fmt.Errorf("wgplan: interface %s has no private key", i.Name)
	}
	if i.MTU <= 0 {
		return fmt.Errorf("wgplan: interface %s has MTU %d", i.Name, i.MTU)
	}
	if len(i.Addresses) == 0 {
		return fmt.Errorf("wgplan: interface %s has no addresses", i.Name)
	}
	for _, addr := range i.Addresses {
		if !addr.IsValid() {
			return fmt.Errorf("wgplan: interface %s has an invalid address", i.Name)
		}
		if addr.Bits() != addr.Addr().BitLen() {
			// A wider local address creates a connected route for the whole pool, so
			// traffic to an unassigned address in it would be sent into the tunnel and
			// dropped rather than failing at once (ADR-0015).
			return fmt.Errorf("wgplan: interface %s address %s is not a host prefix", i.Name, addr)
		}
	}

	own := make(map[netip.Addr]struct{}, len(i.Addresses))
	for _, addr := range i.Addresses {
		own[addr.Addr()] = struct{}{}
	}

	// Which peer claimed each prefix, so a collision can name both sides. An error that
	// says only "overlap" leaves the reader to find them.
	claimed := make(map[netip.Prefix]Key)
	seen := make(map[Key]struct{}, len(i.Peers))

	for _, peer := range i.Peers {
		if peer.PublicKey == "" {
			return fmt.Errorf("wgplan: interface %s has a peer with no public key", i.Name)
		}
		if _, dup := seen[peer.PublicKey]; dup {
			return fmt.Errorf("wgplan: interface %s lists peer %s twice", i.Name, peer.PublicKey)
		}
		seen[peer.PublicKey] = struct{}{}

		if peer.Relayed && peer.Endpoint == "" {
			return fmt.Errorf("wgplan: interface %s peer %s is relayed with no endpoint; "+
				"a relayed peer must point at the socket serving it", i.Name, peer.PublicKey)
		}
		if peer.Relayed && !isLoopback(peer.Endpoint) {
			return fmt.Errorf("wgplan: interface %s peer %s is relayed but points at %s, "+
				"which is not a socket this agent serves", i.Name, peer.PublicKey, peer.Endpoint)
		}
		if !peer.Relayed && isLoopback(peer.Endpoint) {
			return fmt.Errorf("wgplan: interface %s peer %s points at %s without being marked "+
				"relayed; nothing would keep that socket alive", i.Name, peer.PublicKey, peer.Endpoint)
		}
		if len(peer.AllowedIPs) == 0 {
			// A peer with no allowed IPs can neither be sent to nor accepted from. It is
			// not harmful, but it is never what anyone meant.
			return fmt.Errorf("wgplan: interface %s peer %s has no allowed IPs", i.Name, peer.PublicKey)
		}
		for _, prefix := range peer.AllowedIPs {
			if !prefix.IsValid() {
				return fmt.Errorf("wgplan: interface %s peer %s has an invalid allowed IP",
					i.Name, peer.PublicKey)
			}
			if _, mine := own[prefix.Addr()]; mine && prefix.Bits() == prefix.Addr().BitLen() {
				return fmt.Errorf("wgplan: interface %s peer %s claims this device's own address %s",
					i.Name, peer.PublicKey, prefix)
			}
			if other, taken := claimed[prefix]; taken {
				return fmt.Errorf("wgplan: interface %s peers %s and %s both claim %s",
					i.Name, other, peer.PublicKey, prefix)
			}
			claimed[prefix] = peer.PublicKey
		}
	}

	// Overlaps that are not exact duplicates: one peer holding 10.0.0.0/24 and another
	// holding 10.0.0.5/32 is the same silent theft, and comparing prefixes for equality
	// alone would miss it.
	// Between peers, never within one. A single peer holding both 0.0.0.0/0 and its own
	// /32 is redundant and entirely legal — every full-tunnel WireGuard config written by
	// hand looks like that — and there is no theft to detect, because both prefixes lead to
	// the same place.
	prefixes := sortedPrefixes(claimed)
	for a := range prefixes {
		for b := a + 1; b < len(prefixes); b++ {
			if claimed[prefixes[a]] == claimed[prefixes[b]] {
				continue
			}
			if prefixes[a].Overlaps(prefixes[b]) {
				return fmt.Errorf("wgplan: interface %s peer %s has %s, which overlaps %s held by %s",
					i.Name, claimed[prefixes[a]], prefixes[a], prefixes[b], claimed[prefixes[b]])
			}
		}
	}
	return nil
}

// Teardown returns the operations that remove everything this interface installed.
//
// Invariant 20: everything the agent installs, the agent can remove. Routes go first,
// because a route pointing at an interface that no longer exists is the state a host is
// left in when this is done in the wrong order — and on some platforms it lingers.
func Teardown(observed Observed) Plan {
	var plan Plan
	if !observed.Exists {
		return plan
	}
	for _, route := range sortPrefixes(observed.Routes) {
		plan.Ops = append(plan.Ops, Op{Kind: RemoveRoute, Prefix: route})
	}
	for _, addr := range sortPrefixes(observed.Addresses) {
		plan.Ops = append(plan.Ops, Op{Kind: RemoveAddress, Prefix: addr})
	}
	plan.Ops = append(plan.Ops, Op{Kind: DestroyDevice})
	return plan
}

// wantRoutes is every peer address that should be routed at the interface.
//
// A default route is deliberately not among them. A full tunnel needs 0.0.0.0/0 in a peer's
// allowed IPs, because WireGuard will not send a packet to a peer whose allowed IPs do not
// cover the destination — but the matching system route must not go into the main table,
// where it would capture the outer packets carrying the tunnel and route them into it. That
// route belongs in the egress table, installed with the rules that exempt the tunnel's own
// traffic (ADR-0019).
func wantRoutes(want Interface) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(want.Peers))
	for _, peer := range want.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Bits() == 0 {
				continue
			}
			out = append(out, prefix)
		}
	}
	return out
}

// addPrefixOps emits removals for prefixes no longer wanted and additions for new ones.
func addPrefixOps(plan *Plan, have, want []netip.Prefix, removeKind, addKind OpKind) {
	haveSet := prefixSet(have)
	wantSet := prefixSet(want)

	for _, prefix := range sortPrefixes(have) {
		if _, keep := wantSet[prefix]; !keep {
			plan.Ops = append(plan.Ops, Op{Kind: removeKind, Prefix: prefix})
		}
	}
	for _, prefix := range sortPrefixes(want) {
		if _, exists := haveSet[prefix]; !exists {
			plan.Ops = append(plan.Ops, Op{Kind: addKind, Prefix: prefix})
		}
	}
}

func prefixSet(prefixes []netip.Prefix) map[netip.Prefix]struct{} {
	out := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, p := range prefixes {
		out[p] = struct{}{}
	}
	return out
}

// sortPrefixes returns the prefixes deduplicated and in a stable order.
//
// Sorted because two plans for the same state must be identical: a plan whose order
// depends on Go's map iteration would make every comparison, log line and test flake.
func sortPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].String() < out[b].String() })
	return out
}

func sortedPrefixes(claimed map[netip.Prefix]Key) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(claimed))
	for p := range claimed {
		out = append(out, p)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].String() < out[b].String() })
	return out
}

func indexPeers(peers []Peer) map[Key]Peer {
	out := make(map[Key]Peer, len(peers))
	for _, p := range peers {
		out[p.PublicKey] = p
	}
	return out
}

func sortedKeys(peers map[Key]Peer) []Key {
	out := make([]Key, 0, len(peers))
	for k := range peers {
		out = append(out, k)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// resolvePeer decides whether an existing peer needs rewriting, and with what.
//
// Everything but the endpoint is a straightforward comparison. The endpoint is not, because
// it is the one field the device changes on its own: WireGuard updates a peer's endpoint to
// the source of the most recent authenticated packet, which is how roaming works. So the
// value the kernel holds is frequently one nobody configured, and it is better information
// than the control plane has — it is where that peer actually is, as opposed to where it was
// last thought to be.
//
// The returned peer carries an empty endpoint to mean "leave the endpoint alone", which is
// how a peer can have its allowed IPs corrected without having a working path taken away
// from it at the same time.
func resolvePeer(have, want Peer) (bool, Peer) {
	keep := keepObservedEndpoint(have, want)

	out := want
	if keep {
		out.Endpoint = ""
	}

	if !sameApartFromEndpoint(have, want) {
		return true, out
	}
	if !keep && have.Endpoint != want.Endpoint {
		return true, out
	}
	return false, out
}

// keepObservedEndpoint reports whether the device's endpoint should be left as it is.
func keepObservedEndpoint(have, want Peer) bool {
	switch {
	case want.Relayed:
		// Ours by construction: the agent is serving that socket, so nothing the device
		// reports is better information. Notably a loopback endpoint always looks alive —
		// a local socket answers — so the evidence rule below would pin a relayed peer to
		// the relay forever and no direct path could ever replace it.
		return false

	case isLoopback(have.Endpoint):
		// The device points at a socket we no longer intend to serve. Whatever we do now,
		// leaving it there is not an option: it is a black hole with a live-looking endpoint.
		return false

	case want.Endpoint == "":
		// Nothing to offer. Whatever the device has — configured earlier, or learned from
		// traffic — is more than we know, and this is every peer's state until endpoint
		// discovery exists.
		return true
	case have.Endpoint == "":
		return false // nothing there; ours is the only candidate
	case have.Endpoint == want.Endpoint:
		return false // identical, so writing and keeping are the same thing
	default:
		// They differ. If the current one is carrying traffic, replacing it with a guess is
		// a regression rather than a repair — the peer has moved and told us so. If it is
		// not, the candidate is worth trying, which is as much failover as exists until the
		// agent consumes candidate lists (ADR-0003).
		return have.HasHandshake && have.HandshakeAge <= endpointGrace
	}
}

// isLoopback reports whether an endpoint is one of ours.
//
// A loopback address can never be learned from the network — the kernel only has it because
// something local wrote it — so it is never evidence about where a peer is.
func isLoopback(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	addr, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return false
	}
	return addr.Addr().IsLoopback()
}

// sameApartFromEndpoint compares everything the control plane decides outright.
//
// Allowed IPs are compared as sets: the order they arrive in is not something the kernel
// preserves or cares about, so comparing slices directly would rewrite every peer on
// every tick and reset its session each time.
func sameApartFromEndpoint(have, want Peer) bool {
	if have.PresharedKey != want.PresharedKey ||
		have.KeepaliveSeconds != want.KeepaliveSeconds {
		return false
	}
	a := sortPrefixes(have.AllowedIPs)
	b := sortPrefixes(want.AllowedIPs)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
