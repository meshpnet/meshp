// Package version carries build metadata stamped in by the linker.
package version

import (
	"fmt"
	"runtime"
)

var (
	version = "dev"
	commit  = "unknown"
)

// Version returns the semantic version of this build.
func Version() string { return version }

// Commit returns the git commit this build came from.
func Commit() string { return commit }

// String renders the full build identity, used by every binary's --version.
func String(binary string) string {
	return fmt.Sprintf("%s %s (%s) %s/%s %s",
		binary, version, commit, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
