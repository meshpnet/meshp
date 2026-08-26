//go:build !linux && !darwin

package egresslock

import "context"

// New returns nothing here: this platform has no way to refuse egress, so a device asked to
// fail closed reports the group unhonoured rather than claiming a property it does not have.
func New(context.Context) Lock { return nil }

// Held is false where nothing could have installed a lock to begin with.
func Held(context.Context) bool { return false }

// Undo has nothing to undo, and says so by returning nothing rather than a command from
// another operating system.
func Undo() []string { return nil }
