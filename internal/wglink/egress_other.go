//go:build !linux

package wglink

// Router is unavailable off Linux, where there is no policy routing to claim with.
type Router struct{}

// NewRouter returns nothing, so a device asked for a full tunnel reports the group
// unhonoured rather than claiming one it cannot enforce.
func NewRouter() *Router { return nil }

// Claim is unsupported off Linux.
func (r *Router) Claim(string) error { return ErrUnsupported }

// Release is unsupported off Linux.
func (r *Router) Release() error { return ErrUnsupported }

// EgressHeld is false everywhere but Linux, where nothing could have claimed one.
func EgressHeld() (bool, error) { return false, nil }
