//go:build darwin

package netwatch

import (
	"context"
	"syscall"
)

// Watch reports when this machine's networking changes, or returns nil where it cannot tell.
//
// Over PF_ROUTE, which this project already reads: internal/wglink parses the routing table
// from the same socket family on every Observe. Here nothing is parsed — any message at all
// means something about this machine's networking moved, and deciding what changed is the
// reconciler's job rather than the watcher's. That keeps the watcher small enough to be
// obviously correct, which matters for a thing whose failure mode is silence.
func Watch(ctx context.Context) <-chan struct{} {
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, 0)
	if err != nil {
		// A host that cannot open the socket keeps the behaviour it had before this existed:
		// the reconcile timer, and up to a minute to notice. Nil rather than an error,
		// because that is a degradation rather than a failure.
		return nil
	}

	raw := make(chan struct{}, 1)
	out := make(chan struct{}, 1)

	go func() {
		defer func() { _ = syscall.Close(fd) }()
		defer close(raw)
		buf := make([]byte, 4096)
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				// Closed, or the context ended and took the socket with it.
				return
			}
			if n <= 0 {
				continue
			}
			select {
			case raw <- struct{}{}:
			default:
			}
		}
	}()

	// The socket is what the reading goroutine blocks on, so closing it is how the goroutine
	// ends. Nothing else can interrupt a blocking read.
	go func() {
		<-ctx.Done()
		_ = syscall.Close(fd)
	}()

	go debounce(ctx, raw, out)
	return out
}
