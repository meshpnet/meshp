//go:build !linux && !darwin

package wglink

// New reports that this platform has no data plane in this build.
//
// A clear error rather than a build failure, so meshpd still compiles and runs everywhere:
// a device can enrol, hold an address and report honestly that it has no tunnel. That is
// the state Windows and the mobile platforms are in until their implementations land, and
// it is more useful than a daemon that cannot be built there at all.
//
// macOS left this stub behind when wglink_darwin.go landed.
func New() (Link, error) { return nil, ErrUnsupported }
