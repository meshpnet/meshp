//go:build linux

package pathprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultTimeout is how long one target has to answer.
//
// Three seconds is chosen against the reconcile interval rather than against any network:
// every target is dialled at once, so a whole round costs this much at worst, and a minute
// between rounds leaves the reconciler nothing to notice. Long enough for a satellite link
// and a slow TLS-terminating middlebox; short enough that a black-holed target does not hold
// a reconcile open while an operator waits to see the failover they are testing.
const DefaultTimeout = 3 * time.Second

// BoundDialer probes by opening TCP connections through a named interface.
//
// TCP rather than ICMP, which is the choice worth defending. A completed handshake proves a
// bidirectional path all the way to a listening service — the thing a user is actually going
// to do — while ICMP proves that something along the way was willing to answer a ping, and is
// deprioritised or dropped outright by a large fraction of the internet. A probe whose
// failures are mostly policy is worse than no probe, because a fleet learns to ignore it.
//
// SO_BINDTODEVICE rather than the routing table, which is the other one. A dial that consulted
// the routing table would leave by the physical interface whenever the route through the
// tunnel is missing — during the gap after a claim fails, or for a group that is not being
// carried — and would then report the advertiser healthy while measuring the local network.
// That is a false positive that pins a device to a dead gateway, and it is precisely the
// failure this exists to remove. Binding to the interface means the packet either goes through
// the tunnel or does not go at all.
//
// Once bound, WireGuard's own cryptokey routing decides which peer receives it: the target
// falls inside the carried prefix, and the carried prefix is in exactly one peer's AllowedIPs
// because wgplan refuses two peers claiming the same one. So "through the interface" and
// "through the chosen advertiser" are the same thing, without this package having to know
// which peer that is.
type BoundDialer struct {
	// Timeout bounds one target. Zero means DefaultTimeout.
	Timeout time.Duration
}

// NewDialer returns a prober for this host, or nil where the platform cannot bind one.
//
// Nil rather than a stub, following the same rule as the egress router and the filter: a
// capability this host does not have must be absent, so the caller falls back to the
// handshake instead of trusting a measurement that did not go where it claims.
func NewDialer() *BoundDialer { return &BoundDialer{} }

// Probe dials every target at once and reports how each went.
//
// Concurrently, so a round costs one timeout rather than one per target. Sequential dials
// would make a policy with four targets and a black hole among them hold the reconciler open
// for twelve seconds, and the reconciler is what applies desired state.
func (d *BoundDialer) Probe(ctx context.Context, iface string, targets []netip.AddrPort) []Outcome {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	outcomes := make([]Outcome, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcomes[i] = d.dial(ctx, iface, target, timeout)
		}()
	}
	wg.Wait()
	return outcomes
}

func (d *BoundDialer) dial(ctx context.Context, iface string, target netip.AddrPort, timeout time.Duration) Outcome {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var bindErr error
			if err := c.Control(func(fd uintptr) {
				bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			return bindErr
		},
	}

	started := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target.String())
	if err != nil {
		// A refused connection is not a failed path.
		//
		// The packet reached the target and the target answered — with a RST rather than a
		// SYN-ACK, but it answered, which is everything this is asking. Counting it as a
		// failure would make the verdict depend on whether that host happens to still run
		// something on that port, so an administrator whose target closed port 443 would
		// watch their whole fleet fail over for a reason nothing reports.
		if isRefused(err) {
			return Outcome{Target: target, RTT: time.Since(started)}
		}
		return Outcome{Target: target, Err: err}
	}
	rtt := time.Since(started)
	// Closed immediately: nothing is sent, and holding it open would leave a connection per
	// target per round on a device that probes forever.
	_ = conn.Close()
	return Outcome{Target: target, RTT: rtt}
}

// isRefused reports whether the far end answered by saying no.
//
// Here rather than in a shared file, even though it has nothing platform-specific in it: a
// helper only the Linux build calls is dead code everywhere else, and the linter runs on
// whatever the developer is sitting at.
func isRefused(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == unix.ECONNREFUSED || errno == unix.ECONNRESET
}
