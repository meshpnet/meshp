//go:build !windows

package main

import (
	"context"
	"log/slog"
)

// supervise runs the daemon. Nothing here supervises a process from inside it: systemd and
// launchd both send a signal, which main already listens for.
func supervise(ctx context.Context, _ context.CancelFunc, _ *slog.Logger, do func(context.Context) error) error {
	return do(ctx)
}
