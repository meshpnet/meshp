//go:build !linux

package resolved

import (
	"context"
	"errors"
	"net/netip"
)

// ErrUnsupported means this platform has no resolver meshp knows how to configure safely.
var ErrUnsupported = errors.New("resolved: no supported resolver on this platform")

// Resolvectl is declared so the wiring compiles everywhere, and is never constructed here.
// Empty rather than mirroring the Linux type's fields: an unused field is dead weight the
// linter is right to object to.
type Resolvectl struct{}

// New returns nothing on a platform where systemd-resolved is not what answers names.
//
// Nil rather than a stub that reports success. ADR-0021 requires a host that cannot
// configure its resolver to say so and leave the system's DNS alone; a stub reporting
// success would leave the agent believing names work while every lookup went to whatever
// the machine used before.
func New(context.Context) *Resolvectl { return nil }

// Configure fails rather than silently doing nothing.
//
// Unreachable, because New returns nil here. It refuses rather than returning success for
// the reason the pathprobe stub does: "nothing happened" and "it worked" must not look the
// same to a caller, or a wiring mistake on a new platform reads as working software.
func (r *Resolvectl) Configure(context.Context, string, netip.AddrPort, []string) error {
	return ErrUnsupported
}

// Revert is a no-op that succeeds: there is nothing this platform could have installed, and
// a teardown path that errors would report a failure to remove something that was never
// there.
func (r *Resolvectl) Revert(context.Context, string) error { return nil }
