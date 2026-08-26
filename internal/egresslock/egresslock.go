// Package egresslock finds this host's way of refusing egress that does not go through the
// tunnel.
//
// One question — "can this machine fail closed, and how does a person undo it by hand" —
// asked in one place, because the answer is different on every platform and the callers
// asking it are not platform code. Before this package, `cmd/meshpd` and `meshp doctor` both
// reached for internal/nftables directly, which was true while Linux was the only data
// plane and became a bug the moment macOS grew a lock of its own: a device would be told to
// run `nft delete table` on a machine that has never had nftables.
//
// That failure has a name in this repository. #156 is `meshp doctor` recommending
// `systemctl` where there is no systemd, for the same reason — the command was written where
// it was printed rather than where it was decided. wglink.EgressUndo answers the routing
// half of exactly this question, and this is the filtering half.
package egresslock

import (
	"context"
	"net/netip"
)

// Lock is what a host that can refuse egress provides.
//
// Declared here rather than imported from internal/tunnel so this package does not depend on
// the reconciler to describe a firewall. It is deliberately the same method set as
// tunnel.EgressLock, so what New returns satisfies it without any conversion.
type Lock interface {
	// ApplyLock makes the host refuse egress that does not go through the tunnel. An empty
	// interface name removes it, which is the only way it comes off: these rules are system
	// state and outlive the process on purpose (ADR-0011).
	ApplyLock(ctx context.Context, iface string, endpoints []netip.AddrPort, excluded []netip.Prefix, preventDNSLeaks bool) error
}
