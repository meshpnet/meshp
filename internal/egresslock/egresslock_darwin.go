//go:build darwin

package egresslock

import (
	"context"

	"github.com/meshpnet/meshp/internal/pf"
)

// New returns this host's lock, or nil where it has none — which on macOS includes an agent
// without the privilege to read the packet filter, and a macOS whose anchor arrangement has
// moved out from under ADR-0026.
//
// Nil returned explicitly for the reason the Linux file gives: a nil *pf.Lock assigned
// straight to an interface is a non-nil interface holding a nil pointer.
func New(ctx context.Context) Lock {
	if l := pf.New(ctx); l != nil {
		return l
	}
	return nil
}

// Held reports whether a lock left by any process is currently installed.
func Held(ctx context.Context) bool { return pf.Held(ctx) }

// Undo is the exact commands that take the lock off by hand.
//
// Flushing the anchor is the whole of it. meshp's reference on pf being enabled is not
// released here and does not need to be: pf running with no meshp rules in it refuses
// nothing, and the count is cleared by a reboot in any case.
func Undo() []string {
	return []string{"sudo pfctl -a " + pf.AnchorName + " -F rules"}
}
