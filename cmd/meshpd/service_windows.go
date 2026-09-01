//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows/svc"

	"github.com/meshpnet/meshp/internal/agentapi"
	"github.com/meshpnet/meshp/internal/logfile"
)

// underServiceControl reports whether this process was started by the service control
// manager, answered once because both the logger and the supervisor need to know and the
// answer cannot change while a process runs.
var underServiceControl = sync.OnceValue(func() bool {
	is, err := svc.IsWindowsService()
	// An error here means the check itself failed, not that this is a service. Running in
	// the foreground is the safe reading: it logs to the console and responds to Ctrl-C,
	// which is wrong for a service but visible, where the reverse is a process that answers
	// nothing and writes its log where nobody looks.
	return err == nil && is
})

// logWriter is where this process's log goes.
//
// A service has no console, so stderr is discarded and an agent whose log goes nowhere can
// only be debugged by somebody already watching it — the gap #195 is about. Unlike launchd
// and systemd there is nothing outside the process to capture it, so the daemon opens the
// file itself and rotates it (internal/logfile).
//
// --log-file wins where it is given. Where it is not, a service still gets a file rather than
// nothing, beside the state directory: that is already this device's private place with the
// mode this deserves, since the log names networks, peers and addresses.
func logWriter(path, stateDir string) (io.Writer, func(), error) {
	if path == "" {
		if !underServiceControl() {
			return os.Stderr, func() {}, nil
		}
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("meshpd: preparing %s for the log: %w", stateDir, err)
		}
		path = filepath.Join(stateDir, "meshpd.log")
	}
	f, err := logfile.Open(path, logMaxBytes, logKeepFiles)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

// supervise runs the daemon under whatever is supervising this process.
//
// Started by hand, that is nothing, and this is a plain call. Started by the service control
// manager, it is svc.Run: a service that does not report Running within its timeout is killed,
// and one that does not answer Stop is killed after it too. Neither failure looks like a bug
// in meshp from the outside — the service simply refuses to start, or hangs when stopped —
// which is why this is a real handler rather than a wrapper that ignores the channel.
func supervise(ctx context.Context, cancel context.CancelFunc, log *slog.Logger, do func(context.Context) error) error {
	if !underServiceControl() {
		return do(ctx)
	}
	return svc.Run(agentapi.WindowsServiceName, &handler{ctx: ctx, cancel: cancel, log: log, do: do})
}

type handler struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger
	do     func(context.Context) error
}

// Execute is the service control manager's side of the daemon's life.
//
// The order is what the manager requires and not a style: StartPending before any work,
// Running only once the daemon is actually up, StopPending before waiting for it to finish.
// Reporting Stopped while the daemon is still holding an interface would let the manager
// start a second one.
func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	exited := make(chan error, 1)
	go func() { exited <- h.do(h.ctx) }()

	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				// Answered with what was asked, which is what the manager expects: this is
				// a poll for liveness, not a request to change anything.
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				h.log.Info("the service control manager asked meshpd to stop")
				status <- svc.Status{State: svc.StopPending}
				h.cancel()
				// Waited for rather than assumed. Releasing an interface, a route claim and
				// a filter takes as long as it takes, and a service that reports Stopped
				// early is one the manager may immediately start again on top of itself.
				if err := <-exited; err != nil {
					h.log.Error("meshpd exited with error", "error", err)
					return false, 1
				}
				return false, 0
			}
		case err := <-exited:
			// Gone without being asked. Reported as a failure so the manager's restart
			// policy applies, which is the Windows equivalent of Restart=always.
			if err != nil {
				h.log.Error("meshpd exited with error", "error", err)
				return false, 1
			}
			h.log.Warn("meshpd stopped without being asked to")
			return false, 1
		}
	}
}
