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

// Undo is the exact command that takes the lock off by hand.
//
// A restart, which is not a cop-out on this platform: the filtering platform has no
// command-line interface that deletes anything. netsh can show the state and not change it,
// and PowerShell has no cmdlet for a WFP provider — the objects are reachable only through
// the API meshp calls.
//
// What makes a restart an answer rather than a shrug is that meshp's filters are deliberately
// not persistent (ADR-0030). They are lost when the filter engine stops, so a reboot clears
// them exactly as it clears an nftables table on Linux or a pf anchor on macOS. The
// difference is only that on those platforms there is also a command, and here there is not.
//
// Printed second, after `meshp doctor` has already said that starting meshpd removes it —
// which is the answer that does not cost somebody their open windows.
func Undo() []string { return []string{"shutdown /r /t 0"} }
