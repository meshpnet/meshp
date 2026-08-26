//go:build linux

package egresslock

import (
	"context"

	"github.com/meshpnet/meshp/internal/nftables"
)

// New returns this host's lock, or nil where it has none.
//
// Nil returned explicitly rather than by handing back a possibly-nil pointer, and this is
// the trap the whole file exists to avoid: a nil *nftables.Filter assigned straight to an
// interface is a non-nil interface holding a nil pointer, so every downstream `== nil` check
// passes and a host with no packet filter reports that it fails closed.
func New(ctx context.Context) Lock {
	if f := nftables.New(ctx); f != nil {
		return f
	}
	return nil
}

// Held reports whether a lock left by any process is currently installed.
func Held(ctx context.Context) bool { return nftables.LockHeld(ctx) }

// Undo is the exact commands that take the lock off by hand.
//
// Here rather than in `meshp doctor` for the reason wglink.EgressUndo is where it is: the
// person reading that output is at a console on a machine with no network, and a command for
// the wrong operating system is worse than none.
func Undo() []string {
	return []string{"sudo nft delete table inet " + nftables.LockTableName}
}
