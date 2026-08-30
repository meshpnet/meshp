//go:build !linux && !darwin && !windows

package resolved

import (
	"context"
	"errors"
	"net/netip"
)

// ErrUnsupported means this platform has no resolver meshp knows how to configure safely.
var ErrUnsupported = errors.New("resolved: no supported resolver on this platform")

// System is declared so the wiring compiles everywhere, and is never constructed here.
// Empty rather than mirroring a real implementation's fields: an unused field is dead
// weight the linter is right to object to.
type System struct{}

// New returns nothing on a platform whose resolver meshp has no safe way to configure.
//
// Nil rather than a stub that reports success. ADR-0021 requires a host that cannot
// configure its resolver to say so and leave the system's DNS alone; a stub reporting
// success would leave the agent believing names work while every lookup went to whatever
// the machine used before.
//
// Linux and macOS have implementations. What is left here is Windows and the mobile
// platforms, where the mechanism exists and nothing has been written for it yet.
func New(context.Context) *System { return nil }

// Configure fails rather than silently doing nothing.
//
// Unreachable, because New returns nil here. It refuses rather than returning success for
// the reason the pathprobe stub does: "nothing happened" and "it worked" must not look the
// same to a caller, or a wiring mistake on a new platform reads as working software.
func (r *System) Configure(context.Context, string, netip.AddrPort, []string) error {
	return ErrUnsupported
}

// Revert is a no-op that succeeds: there is nothing this platform could have installed, and
// a teardown path that errors would report a failure to remove something that was never
// there.
func (r *System) Revert(context.Context, string) error { return nil }
