//go:build linux

package wglink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/jsimonetti/rtnetlink/v2"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// linux manages interfaces through rtnetlink and wgctrl.
//
// Two sockets rather than one because they answer different questions. rtnetlink owns the
// interface as a network device — existence, MTU, addresses, routes. wgctrl owns what
// makes it a WireGuard device — keys and peers — and speaks netlink to a kernel device or
// the UAPI socket to a userspace one, so the same code configures either (ADR-0015).
type linux struct {
	rt *rtnetlink.Conn
	wg *wgctrl.Client
}

// New returns a Link for this host.
func New() (Link, error) {
	rt, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("wglink: opening rtnetlink: %w", err)
	}
	wg, err := wgctrl.New()
	if err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("wglink: opening the WireGuard control socket: %w", err)
	}
	return &linux{rt: rt, wg: wg}, nil
}

func (l *linux) Close() error {
	return errors.Join(l.wg.Close(), l.rt.Close())
}

func (l *linux) Kind(name string) (Kind, error) {
	dev, err := l.wg.Device(name)
	if err != nil {
		return KindUnknown, fmt.Errorf("wglink: reading %s: %w", name, err)
	}
	switch dev.Type {
	case wgtypes.LinuxKernel:
		return KindKernel, nil
	case wgtypes.Userspace:
		return KindUserspace, nil
	default:
		return KindUnknown, nil
	}
}

// Observe reports what the interface currently holds.
func (l *linux) Observe(name string) (wgplan.Observed, error) {
	iface, gone, err := lookup(name)
	if err != nil {
		return wgplan.Observed{}, err
	}
	if gone {
		// Not an error: this is what the planner needs in order to decide to create it.
		return wgplan.Observed{}, nil
	}

	obs := wgplan.Observed{
		Exists: true,
		Up:     iface.Flags&net.FlagUp != 0,
		MTU:    iface.MTU,
	}

	dev, err := l.wg.Device(name)
	if err != nil {
		// An interface of this name that is not a WireGuard device is not something to
		// take over. Adopting it would mean configuring keys on someone else's interface.
		return wgplan.Observed{}, fmt.Errorf("wglink: %s is not a WireGuard interface: %w", name, err)
	}
	obs.ListenPort = dev.ListenPort
	if dev.PrivateKey != (wgtypes.Key{}) {
		obs.PrivateKey = wgplan.Key(dev.PrivateKey.String())
	}
	for _, peer := range dev.Peers {
		obs.Peers = append(obs.Peers, peerFromDevice(peer))
	}

	if obs.Addresses, err = l.addresses(uint32(iface.Index)); err != nil {
		return wgplan.Observed{}, err
	}
	if obs.Routes, err = l.routes(uint32(iface.Index)); err != nil {
		return wgplan.Observed{}, err
	}
	return obs, nil
}

// addresses lists the interface's own addresses as host prefixes.
func (l *linux) addresses(index uint32) ([]netip.Prefix, error) {
	msgs, err := l.rt.Address.List()
	if err != nil {
		return nil, fmt.Errorf("wglink: listing addresses: %w", err)
	}
	var out []netip.Prefix
	for _, msg := range msgs {
		if msg.Index != index || msg.Attributes == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(msg.Attributes.Address)
		if !ok {
			continue
		}
		out = append(out, netip.PrefixFrom(addr.Unmap(), int(msg.PrefixLength)))
	}
	return out, nil
}

// routes lists only the routes meshp installed.
//
// Filtered by table and protocol, not by "points at our interface". The kernel adds
// routes of its own the moment an address is assigned — a local route for the address and,
// for IPv6, a multicast route — and both point at our interface. Reporting those as ours
// would have the reconciler withdraw them on every pass, and on IPv6 that breaks
// neighbour discovery on the link. Verified against a real interface: assigning one /32
// produced three routes, two of them the kernel's.
func (l *linux) routes(index uint32) ([]netip.Prefix, error) {
	msgs, err := l.rt.Route.List()
	if err != nil {
		return nil, fmt.Errorf("wglink: listing routes: %w", err)
	}
	var out []netip.Prefix
	for _, msg := range msgs {
		if msg.Attributes.OutIface != index ||
			msg.Table != unix.RT_TABLE_MAIN ||
			msg.Protocol != RouteProtocol {
			continue
		}
		dst, ok := netip.AddrFromSlice(msg.Attributes.Dst)
		if !ok {
			continue
		}
		out = append(out, netip.PrefixFrom(dst.Unmap(), int(msg.DstLength)))
	}
	return out, nil
}

// Apply carries out one operation.
func (l *linux) Apply(name string, op wgplan.Op) error {
	switch op.Kind {
	case wgplan.CreateDevice:
		return l.createDevice(name)
	case wgplan.DestroyDevice:
		return l.destroyDevice(name)
	case wgplan.SetDevice:
		return l.setDevice(name, op.Device)
	case wgplan.SetPeer:
		return l.setPeer(name, op.Peer)
	case wgplan.RemovePeer:
		return l.removePeer(name, op.Peer)
	case wgplan.AddAddress:
		return l.address(name, op.Prefix, true)
	case wgplan.RemoveAddress:
		return l.address(name, op.Prefix, false)
	case wgplan.AddRoute:
		return l.route(name, op.Prefix, true)
	case wgplan.RemoveRoute:
		return l.route(name, op.Prefix, false)
	case wgplan.BringUp:
		return l.bringUp(name)
	default:
		return fmt.Errorf("wglink: unknown operation %s", op.Kind)
	}
}

func (l *linux) createDevice(name string) error {
	err := l.rt.Link.New(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Attributes: &rtnetlink.LinkAttributes{
			Name: name,
			Info: &rtnetlink.LinkInfo{Kind: "wireguard"},
		},
	})
	if err != nil {
		// No kernel module is the one failure with an action attached to it, so it is
		// named rather than passed through as an errno (ADR-0015: report which
		// implementation is in use, and why).
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) {
			return fmt.Errorf("wglink: this kernel cannot create WireGuard interfaces "+
				"(no wireguard module); a userspace implementation is needed here: %w", err)
		}
		return fmt.Errorf("wglink: creating %s: %w", name, err)
	}
	return nil
}

func (l *linux) destroyDevice(name string) error {
	iface, gone, err := lookup(name)
	if err != nil {
		return err
	}
	if gone {
		return nil // already the state this asks for
	}
	if err := l.rt.Link.Delete(uint32(iface.Index)); err != nil {
		return fmt.Errorf("wglink: deleting %s: %w", name, err)
	}
	return nil
}

func (l *linux) setDevice(name string, dev wgplan.Device) error {
	key, err := wgtypes.ParseKey(string(dev.PrivateKey))
	if err != nil {
		return fmt.Errorf("wglink: the private key for %s is not a WireGuard key: %w", name, err)
	}

	cfg := wgtypes.Config{PrivateKey: &key}
	if dev.ListenPort != 0 {
		port := dev.ListenPort
		cfg.ListenPort = &port
	}
	if err := l.wg.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("wglink: configuring %s: %w", name, err)
	}

	if dev.MTU > 0 {
		if err := l.setMTU(name, dev.MTU); err != nil {
			return err
		}
	}
	return nil
}

func (l *linux) setMTU(name string, mtu int) error {
	iface, gone, err := lookup(name)
	if err != nil {
		return err
	}
	if gone {
		return fmt.Errorf("wglink: cannot set the MTU: there is no interface %s", name)
	}
	err = l.rt.Link.Set(&rtnetlink.LinkMessage{
		Family:     unix.AF_UNSPEC,
		Index:      uint32(iface.Index),
		Attributes: &rtnetlink.LinkAttributes{MTU: uint32(mtu)},
	})
	if err != nil {
		return fmt.Errorf("wglink: setting the MTU of %s to %d: %w", name, mtu, err)
	}
	return nil
}

func (l *linux) bringUp(name string) error {
	iface, gone, err := lookup(name)
	if err != nil {
		return err
	}
	if gone {
		return fmt.Errorf("wglink: cannot bring up an interface that is not there: %s", name)
	}
	err = l.rt.Link.Set(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Index:  uint32(iface.Index),
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
	})
	if err != nil {
		return fmt.Errorf("wglink: bringing up %s: %w", name, err)
	}
	return nil
}

func (l *linux) setPeer(name string, peer wgplan.Peer) error {
	cfg, err := peerConfig(peer)
	if err != nil {
		return fmt.Errorf("wglink: %s: %w", name, err)
	}
	// Replacing rather than merging: the plan states what this peer's allowed IPs are, and
	// adding to whatever was there would leave a prefix the peer is no longer entitled to
	// still routed to it.
	cfg.ReplaceAllowedIPs = true
	if err := l.wg.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{cfg}}); err != nil {
		return fmt.Errorf("wglink: configuring peer on %s: %w", name, err)
	}
	return nil
}

func (l *linux) removePeer(name string, peer wgplan.Peer) error {
	key, err := wgtypes.ParseKey(string(peer.PublicKey))
	if err != nil {
		return fmt.Errorf("wglink: %s: peer key is not a WireGuard key: %w", name, err)
	}
	err = l.wg.ConfigureDevice(name, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}},
	})
	if err != nil {
		return fmt.Errorf("wglink: removing a peer from %s: %w", name, err)
	}
	return nil
}

func (l *linux) address(name string, prefix netip.Prefix, add bool) error {
	iface, gone, err := lookup(name)
	if err != nil {
		return err
	}
	if gone {
		if add {
			return fmt.Errorf("wglink: cannot add %s: there is no interface %s", prefix, name)
		}
		// Nothing to take off an interface that is not there. Teardown has to be safe to
		// repeat: an agent cleaning up after a crash does not know how far it got, and a
		// second pass that errors leaves it unable to finish (Invariant 20).
		return nil
	}

	family := uint8(unix.AF_INET)
	if prefix.Addr().Is6() {
		family = unix.AF_INET6
	}
	ip := net.IP(prefix.Addr().AsSlice())
	msg := &rtnetlink.AddressMessage{
		Family:       family,
		PrefixLength: uint8(prefix.Bits()),
		Scope:        unix.RT_SCOPE_UNIVERSE,
		Index:        uint32(iface.Index),
		Attributes: &rtnetlink.AddressAttributes{
			Address: ip,
			Local:   ip,
		},
	}

	if add {
		if err := l.rt.Address.New(msg); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return nil // already there, which is what was asked for
			}
			return fmt.Errorf("wglink: adding %s to %s: %w", prefix, name, err)
		}
		return nil
	}
	if err := l.rt.Address.Delete(msg); err != nil {
		if errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENOENT) {
			return nil // already gone
		}
		return fmt.Errorf("wglink: removing %s from %s: %w", prefix, name, err)
	}
	return nil
}

func (l *linux) route(name string, prefix netip.Prefix, add bool) error {
	iface, gone, err := lookup(name)
	if err != nil {
		return err
	}
	if gone {
		if add {
			return fmt.Errorf("wglink: cannot route %s: there is no interface %s", prefix, name)
		}
		// The interface is gone, and every route through it went with it.
		return nil
	}

	family := uint8(unix.AF_INET)
	if prefix.Addr().Is6() {
		family = unix.AF_INET6
	}
	msg := &rtnetlink.RouteMessage{
		Family: family,
		Table:  unix.RT_TABLE_MAIN,
		// Marked as ours, which is what makes removal exact rather than a guess.
		Protocol:  RouteProtocol,
		Scope:     unix.RT_SCOPE_LINK,
		Type:      unix.RTN_UNICAST,
		DstLength: uint8(prefix.Bits()),
		Attributes: rtnetlink.RouteAttributes{
			Dst:      net.IP(prefix.Addr().AsSlice()),
			OutIface: uint32(iface.Index),
		},
	}

	if add {
		if err := l.rt.Route.Add(msg); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return nil
			}
			return fmt.Errorf("wglink: routing %s via %s: %w", prefix, name, err)
		}
		return nil
	}
	if err := l.rt.Route.Delete(msg); err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("wglink: withdrawing the route to %s via %s: %w", prefix, name, err)
	}
	return nil
}

// peerConfig turns a planned peer into what wgctrl wants.
func peerConfig(peer wgplan.Peer) (wgtypes.PeerConfig, error) {
	key, err := wgtypes.ParseKey(string(peer.PublicKey))
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("peer key is not a WireGuard key: %w", err)
	}
	cfg := wgtypes.PeerConfig{PublicKey: key}

	for _, prefix := range peer.AllowedIPs {
		cfg.AllowedIPs = append(cfg.AllowedIPs, net.IPNet{
			IP:   net.IP(prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		})
	}

	if peer.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", peer.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("endpoint %q: %w", peer.Endpoint, err)
		}
		cfg.Endpoint = addr
	}
	if peer.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(string(peer.PresharedKey))
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("preshared key is not a WireGuard key: %w", err)
		}
		cfg.PresharedKey = &psk
	}
	if peer.KeepaliveSeconds > 0 {
		d := time.Duration(peer.KeepaliveSeconds) * time.Second
		cfg.PersistentKeepaliveInterval = &d
	}
	return cfg, nil
}

// peerFromDevice turns what the kernel reports back into a planned peer, so the two can be
// compared. Anything not represented here is invisible to the diff and would never be
// corrected, so this and peerConfig have to stay in step.
func peerFromDevice(peer wgtypes.Peer) wgplan.Peer {
	out := wgplan.Peer{
		PublicKey:        wgplan.Key(peer.PublicKey.String()),
		KeepaliveSeconds: int(peer.PersistentKeepaliveInterval.Seconds()),
	}
	if peer.Endpoint != nil {
		out.Endpoint = peer.Endpoint.String()
	}
	if peer.PresharedKey != (wgtypes.Key{}) {
		out.PresharedKey = wgplan.Key(peer.PresharedKey.String())
	}
	for _, ipnet := range peer.AllowedIPs {
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		out.AllowedIPs = append(out.AllowedIPs, netip.PrefixFrom(addr.Unmap(), ones))
	}
	return out
}

// lookup finds an interface, reporting "not there" separately from "the lookup failed".
//
// The distinction is the whole point. An absent interface is a normal state — before
// creation, and after teardown — while a lookup that fails for any other reason is not,
// and collapsing the two would turn a broken netlink socket into a silent no-op. Asked of
// the kernel's interface list rather than inferred from the error text, which varies.
func lookup(name string) (*net.Interface, bool, error) {
	iface, err := net.InterfaceByName(name)
	if err == nil {
		return iface, false, nil
	}
	ifaces, listErr := net.Interfaces()
	if listErr != nil {
		return nil, false, fmt.Errorf("wglink: looking up %s: %w", name, err)
	}
	for _, candidate := range ifaces {
		if candidate.Name == name {
			// It is there, so the failure was the lookup itself.
			return nil, false, fmt.Errorf("wglink: looking up %s: %w", name, err)
		}
	}
	return nil, true, nil
}

// privileged reports whether this process can manage interfaces at all, used by tests to
// skip rather than fail.
func privileged() bool { return os.Geteuid() == 0 }
