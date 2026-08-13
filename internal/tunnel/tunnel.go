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

	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/wglink"
	"github.com/meshpnet/meshp/internal/wgplan"
)

// defaultMTU is used when the server has not said what the MTU should be.
//
// 1420 leaves room for WireGuard's overhead inside a 1500-byte path. A starting point
// rather than a measurement, and the same number the control plane sends today.
const defaultMTU = 1420

// Membership is what this package needs to know about the device's place in a network.
type Membership struct {
	InterfaceName string

	// PrivateKey is this membership's WireGuard private key. One key per membership, never
	// shared (Invariant 19).
	PrivateKey string

	// AddressV4 and AddressV6 are this device's own addresses. Either may be empty.
	AddressV4 string
	AddressV6 string
}

// Reconciler applies desired state to a real interface.
//
// Safe for concurrent use: the daemon's status command reads what it last reported while a
// session may be applying the next state.
type Reconciler struct {
	link       wglink.Link
	membership Membership
	log        *slog.Logger

	mu       sync.Mutex
	kind     wglink.Kind
	up       bool
	lastErr  string
	appliedV uint64
}

// New returns a Reconciler for one membership.
func New(link wglink.Link, m Membership, log *slog.Logger) *Reconciler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Reconciler{link: link, membership: m, log: log, kind: wglink.KindUnknown}
}

// Status is what the daemon reports about this tunnel.
type Status struct {
	Up             bool
	Kind           wglink.Kind
	LastError      string
	AppliedVersion uint64
}

// Status reports the tunnel's current state.
func (r *Reconciler) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{Up: r.up, Kind: r.kind, LastError: r.lastErr, AppliedVersion: r.appliedV}
}

// Apply makes the interface match state.
//
// This is the sessionclient.Applier contract: it receives the whole desired state rather
// than a delta, because a reconciler given a target is idempotent by construction
// (Invariant 18), and the set it is given is its own to keep (Invariant 22).
//
// The returned components are the parts that did not converge, which the agent reports back
// so the control plane knows this device is not where it says it is.
func (r *Reconciler) Apply(_ context.Context, state *peerset.Set) ([]string, error) {
	want, err := Desired(r.membership, state)
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

	r.mu.Lock()
	r.kind = kind
	r.up = true
	r.lastErr = ""
	r.appliedV = state.Version()
	r.mu.Unlock()
	return nil, nil
}

// Teardown removes everything this membership installed (Invariant 20).
func (r *Reconciler) Teardown() error {
	name := r.membership.InterfaceName
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
func Desired(m Membership, state *peerset.Set) (wgplan.Interface, error) {
	if m.PrivateKey == "" {
		return wgplan.Interface{}, errors.New("tunnel: this membership has no WireGuard private key")
	}

	iface := wgplan.Interface{
		Name:       m.InterfaceName,
		PrivateKey: wgplan.Key(m.PrivateKey),
		MTU:        defaultMTU,
		// Any port. A device in several networks needs an interface for each (ADR-0004), so
		// they cannot all ask for one port, and nothing distributes ports yet.
		ListenPort: 0,
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
			return wgplan.Interface{}, fmt.Errorf("tunnel: this device's address %q: %w", addr, err)
		}
		iface.Addresses = append(iface.Addresses, prefix)
	}
	if len(iface.Addresses) == 0 {
		return wgplan.Interface{}, errors.New("tunnel: this membership holds no addresses")
	}

	for _, peer := range state.Peers() {
		converted, err := peerFrom(peer.GetPublicKey(), peer.GetAllowedIps(),
			peer.GetEndpoints(), int(peer.GetPersistentKeepaliveSeconds()))
		if err != nil {
			// Refused rather than skipped. A peer quietly dropped is a device that cannot be
			// reached, with everything reporting success.
			return wgplan.Interface{}, fmt.Errorf("tunnel: peer %s: %w",
				truncate(peer.GetPublicKey()), err)
		}
		iface.Peers = append(iface.Peers, converted)
	}
	return iface, nil
}

func peerFrom(publicKey string, allowedIPs, endpoints []string, keepalive int) (wgplan.Peer, error) {
	peer := wgplan.Peer{
		PublicKey:        wgplan.Key(publicKey),
		KeepaliveSeconds: keepalive,
	}
	for _, cidr := range allowedIPs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return wgplan.Peer{}, fmt.Errorf("allowed IP %q: %w", cidr, err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefix)
	}

	// The first endpoint only. The list is ordered best-first and choosing between them is
	// the agent's job once there is something to choose with (ADR-0003); WireGuard holds one
	// endpoint per peer, so until then the server's first preference is the only answer.
	// Empty is normal and means relay-only, which today means unreachable.
	if len(endpoints) > 0 {
		if _, err := netip.ParseAddrPort(endpoints[0]); err != nil {
			return wgplan.Peer{}, fmt.Errorf("endpoint %q: %w", endpoints[0], err)
		}
		peer.Endpoint = endpoints[0]
	}
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

func truncate(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12] + "…"
}
