//go:build !linux && !darwin

package wglink

import "net/netip"

// Router is unavailable here: no policy routing, and no way to claim a default route without
// taking somebody else's.
type Router struct{}

// NewRouter returns nothing, so a device asked for a full tunnel reports the group
// unhonoured rather than claiming one it cannot enforce.
func NewRouter() *Router { return nil }

// Claim is unsupported here.
func (r *Router) Claim(string, []netip.AddrPort, []netip.Prefix) error { return ErrUnsupported }

// Release is unsupported off Linux.
func (r *Router) Release() error { return ErrUnsupported }

// EgressHeld is false everywhere but Linux, where nothing could have claimed one.
func EgressHeld() (bool, error) { return false, nil }

// egressUndo has nothing to undo: nothing here can claim a default route.
func egressUndo() []string { return nil }
