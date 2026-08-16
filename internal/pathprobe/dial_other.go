//go:build !linux

package pathprobe

import (
	"context"
	"net/netip"
	"time"
)

// BoundDialer exists so the wiring compiles everywhere. It is never constructed on this
// platform, because NewDialer returns nil.
type BoundDialer struct{ Timeout time.Duration }

// NewDialer returns nothing on a platform that cannot bind a socket to an interface.
//
// Nil rather than a dialer that would use the routing table. A probe that left by the
// physical interface would report the advertiser healthy while measuring the local network,
// which pins a device to a dead gateway — strictly worse than falling back to the handshake,
// which at least measures something it can name.
func NewDialer() *BoundDialer { return nil }

// Probe fails every target rather than passing them.
//
// Unreachable: nothing constructs a BoundDialer here. It fails rather than returning nothing
// because "nothing" reads as a group with no targets, which the reconciler treats as "the
// probe did not run" and quietly falls back — so a wiring mistake on a new platform would
// look exactly like working software. This way it shows up as an advertiser that will not
// pass, which is wrong but visible.
func (d *BoundDialer) Probe(_ context.Context, _ string, targets []netip.AddrPort) []Outcome {
	out := make([]Outcome, 0, len(targets))
	for _, t := range targets {
		out = append(out, Outcome{Target: t, Err: ErrUnsupported})
	}
	return out
}
