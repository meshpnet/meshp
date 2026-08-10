// Command meshpd is the privileged device agent.
//
// It owns the WireGuard private key, which never leaves this process's host
// (Invariant 1). It holds one long-lived control-channel session per network
// membership, reconciles the local system toward the desired state the server
// sends, and answers meshp over a local unix socket.
//
// Two properties matter more than features here:
//
//   - It keeps working when the control plane is unreachable. Existing peers,
//     routes, DNS and route-group candidates are all persisted locally
//     (Invariant 15).
//   - Everything it installs, it can remove. An agent crash or uninstall must
//     never leave a host without networking (Invariant 20).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/meshpnet/meshp/internal/version"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print build information and exit")
		statePath   = flag.String("state-dir", defaultStateDir(), "where to persist local state")
		socketPath  = flag.String("socket", defaultSocketPath(), "unix socket meshp connects to")
		logLevel    = flag.String("log-level", "info", "debug, info, warn or error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("meshpd"))
		return
	}

	log := newLogger(*logLevel)
	log.Info("meshpd starting",
		"version", version.Version(),
		"state_dir", *statePath,
		"socket", *socketPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log); err != nil {
		log.Error("meshpd exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshpd stopped cleanly")
}

func run(ctx context.Context, log *slog.Logger) error {
	// Reconciler, control-channel client, WireGuard device manager and the
	// local socket server are wired up here. Until they exist, meshpd runs as
	// a no-op supervisor so the process lifecycle and signal handling are
	// exercised from the first commit.
	log.Warn("no subsystems registered yet; idling until interrupted")
	<-ctx.Done()
	return nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func defaultStateDir() string {
	if v := os.Getenv("MESHP_STATE_DIR"); v != "" {
		return v
	}
	switch osName() {
	case "windows":
		return `C:\ProgramData\meshp`
	case "darwin":
		return "/Library/Application Support/meshp"
	default:
		return "/var/lib/meshp"
	}
}

func defaultSocketPath() string {
	if v := os.Getenv("MESHP_SOCKET"); v != "" {
		return v
	}
	if osName() == "windows" {
		return `\\.\pipe\meshpd`
	}
	return "/var/run/meshpd.sock"
}
