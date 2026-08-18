//go:build !linux

package nftables

import (
	"context"
	"net/netip"
)

// ApplyCarry does nothing off Linux, where meshp does not forward at all.
//
// Nil rather than ErrUnsupported: a host that cannot carry a prefix is refused earlier, by
// Available, so reporting a failure here would put an error in front of an operator about
// something that was never going to be attempted.
func ApplyCarry(context.Context, string, []netip.Prefix) error { return nil }

// RemoveCarry likewise has nothing to take back out.
func RemoveCarry(context.Context) error { return nil }
