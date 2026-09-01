//go:build !windows

package main

import (
	"io"
	"os"

	"github.com/meshpnet/meshp/internal/logfile"
)

// logWriter is stderr unless somebody named a file.
//
// systemd captures stderr into the journal and rotates it there, so a Linux unit names no
// file and this is the whole story. launchd captures it too — into a path that grows forever
// and that nothing can rotate from outside, because a rename does not move the descriptor
// launchd is holding (see internal/logfile). So the macOS daemon passes --log-file and the
// process rotates its own log, and the plist keeps StandardErrorPath only for what escapes
// the logger entirely: a panic, or a runtime failure before any of this runs.
func logWriter(path, _ string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stderr, func() {}, nil
	}
	f, err := logfile.Open(path, logMaxBytes, logKeepFiles)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}
