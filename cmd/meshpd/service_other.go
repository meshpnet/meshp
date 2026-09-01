//go:build !windows

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// logWriter is stderr everywhere but Windows.
//
// systemd captures it into the journal and launchd redirects it to the file named in the
// plist (ADR-0011's undo commands are only useful if somebody can see what happened), so the
// daemon has nothing to arrange for itself. Windows has no such mechanism and opens a file.
func logWriter(string) (io.Writer, func(), error) { return os.Stderr, func() {}, nil }

// supervise runs the daemon. Nothing here supervises a process from inside it: systemd and
// launchd both send a signal, which main already listens for.
func supervise(ctx context.Context, _ context.CancelFunc, _ *slog.Logger, do func(context.Context) error) error {
	return do(ctx)
}
