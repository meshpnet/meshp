//go:build !darwin && !linux && !windows

package netwatch

import "context"

// Watch returns nothing on a platform with no way to be told about a change.
//
// Nil rather than a channel that never fires, so the caller can say which it got: the
// reconcile timer is the whole of the recovery there, and an agent reporting prompt recovery
// it does not have would be the dishonesty this project is written against.
func Watch(context.Context) <-chan struct{} { return nil }
