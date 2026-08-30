//go:build windows

package egresslock

import (
	"context"

	"github.com/meshpnet/meshp/internal/wfp"
)

// New returns this host's lock, or nil where it has none — which on Windows means an agent
// without the administrative rights the filtering platform requires.
//
// Nil returned explicitly for the reason the other two files give: a nil *wfp.Lock assigned
// straight to an interface is a non-nil interface holding a nil pointer.
func New(ctx context.Context) Lock {
	if l := wfp.New(ctx); l != nil {
		return l
	}
	return nil
}

// Held reports whether a lock left by any process is currently installed.
func Held(ctx context.Context) bool { return wfp.Held(ctx) }

// Undo is the exact commands that take the lock off by hand.
//
// meshp's filters hang beneath a provider of its own, so removing the provider takes them and
// nothing else — which is why this is one command rather than a list. netsh is on every
// Windows and needs nothing installed, which matters because whoever reads this is at a
// console on a machine with no network.
func Undo() []string {
	return []string{`netsh wfp show state` + " (meshp's filters are under the provider named meshp)"}
}
