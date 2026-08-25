package wglink

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// Translating between a plan's peers and wgctrl's, which is the same job on every platform
// because wgctrl is the same on every platform — netlink to a kernel device, the UAPI socket
// to a userspace one, one set of types either way (ADR-0015).
//
// Kept out of the platform files for that reason. It lived beside the Linux implementation
// while that was the only one, and the moment a second arrived the choice was to move it or
// to have two copies of the one function whose halves must stay in step.

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
	// Whether this peer's current endpoint is working, which is what decides whether
	// replacing it would be a repair or would undo roaming.
	if !peer.LastHandshakeTime.IsZero() {
		out.HasHandshake = true
		out.HandshakeAge = time.Since(peer.LastHandshakeTime)
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
