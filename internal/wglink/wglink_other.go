//go:build !linux

package wglink

// New reports that this platform has no data plane in this build.
//
// A clear error rather than a build failure, so meshpd still compiles and runs everywhere:
// a device can enrol, hold an address and report honestly that it has no tunnel. That is
// the state macOS and Windows are in until their implementations land, and it is more
// useful than a daemon that cannot be built there at all.
func New() (Link, error) { return nil, ErrUnsupported }
