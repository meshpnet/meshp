// Command meshpd is the privileged device agent.
//
// It owns the WireGuard private key, which never leaves this process's host
// (Invariant 1). It holds one long-lived control-channel session per network
// membership, reconciles the local system toward the desired state the server sends,
// and answers meshp over a local unix socket.
//
// The socket is a privilege boundary, not a convenience. meshpd runs as root and holds
// the device's keys; meshp is a command an ordinary user types. Enrolment, key
// generation and eventually every change to the network stack happen on this side of
// the line, and the CLI asks rather than acts.
//
// Two properties matter more than features here:
//
//   - It keeps working when the control plane is unreachable. Peers, routes, DNS and
//     route-group candidates are all persisted locally (Invariant 15).
//   - Everything it installs, it can remove. An agent crash or uninstall must never
//     leave a host without networking (Invariant 20).
//
// Neither is exercised yet, because nothing here touches the network stack. What this
// build does is hold sessions and record what it is told, which is what makes the
// convergence machinery testable before there is anything to converge.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/meshpnet/meshp/internal/agentapi"
	"github.com/meshpnet/meshp/internal/agentstate"
	"github.com/meshpnet/meshp/internal/version"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print build information and exit")
		stateDir    = flag.String("state-dir", defaultStateDir(), "where to persist local state")
		socketPath  = flag.String("socket", defaultSocketPath(), "unix socket meshp connects to")
		socketGroup = flag.String("socket-group", os.Getenv("MESHP_SOCKET_GROUP"),
			"system group allowed to use the socket; empty means owner only")
		logLevel = flag.String("log-level", envOr("MESHP_LOG_LEVEL", "info"), "debug, info, warn or error")

		// How often the interface is checked against desired state even when nothing has
		// changed. A minute is a compromise: drift is corrected without waiting for the
		// next state update, and a converged interface costs two netlink reads to confirm
		// (Invariant 18 is what makes that true). Zero switches it off.
		reconcileEvery = flag.Duration("reconcile-interval",
			envDuration("MESHP_RECONCILE_INTERVAL", time.Minute),
			"how often to re-apply desired state to the interface; 0 disables")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("meshpd"))
		return
	}

	log := newLogger(*logLevel)
	log.Info("meshpd starting",
		"version", version.Version(),
		"state_dir", *stateDir,
		"socket", *socketPath,
		"reconcile_interval", *reconcileEvery)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log, *stateDir, *socketPath, *socketGroup, *reconcileEvery); err != nil {
		log.Error("meshpd exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshpd stopped cleanly")
}

// dnsListenAddr is where the resolver listens.
//
// Loopback, because the kill switch permits loopback unconditionally and a resolver anybody
// on the café Wi-Fi could query would tell them what machines are in your customers'
// networks. Port zero: the kernel picks, and what it picked is read back and reported,
// because 53 is almost always already taken by whatever the machine was using before and
// fighting it would break the host's existing DNS to install ours.
var dnsListenAddr = netip.MustParseAddrPort("127.0.0.1:0")

func run(ctx context.Context, log *slog.Logger, stateDir, socketPath, socketGroup string, reconcileEvery time.Duration) error {
	agent := newAgent(ctx, log, stateDir, reconcileEvery)

	// Before the state is read, not after. Reading it can fail — a truncated write, a disk
	// that filled, a file somebody edited — and that failure returns from here and exits.
	// A device whose egress is being refused by rules a dead predecessor left behind would
	// then stay that way for as long as the state file stayed broken, which is a machine
	// bricked by a corrupt JSON file (ADR-0011, Invariant 20).
	agent.reclaimEgressLock()

	if err := agent.load(); err != nil {
		return err
	}

	// The socket comes up before the sessions do, so that a device with no state at all
	// can still be joined. Binding is also the only thing here that can fail in a way
	// worth exiting for: two daemons sharing a state directory would fight over the same
	// keys.
	server := agentapi.NewServer(agent, agentapi.ServerConfig{
		SocketPath: socketPath,
		Group:      socketGroup,
		Log:        log,
	})
	if err := server.Listen(); err != nil {
		return err
	}

	// The resolver, bound before anything else runs and served afterwards.
	//
	// Synchronously on purpose. Binding in a goroutine meant everything below this line ran
	// before the sockets existed, so `meshp status` could truthfully report no resolver on a
	// device that was about to have one — which is what broke the end-to-end assertion
	// guarding this feature, on a machine slower than the one it was written on.
	//
	// Its failure is not fatal. A port already taken, or a host that will not let this
	// process bind, costs names and nothing else: the tunnel, the policy and the routes are
	// all unaffected, and exiting here would take them down over a convenience.
	if err := agent.resolver.Bind(dnsListenAddr); err != nil {
		log.Error("no name resolution on this device",
			"error", err, "addr", dnsListenAddr.String(),
			"hint", "meshp status reports the resolver; addresses still work")
	} else {
		go agent.resolver.Serve(ctx)
	}

	agent.startAll()

	return server.Serve(ctx)
}

// isNotEnrolled reports whether an error means there is simply no local state.
func isNotEnrolled(err error) bool {
	return errors.Is(err, agentstate.ErrNotEnrolled) || errors.Is(err, fs.ErrNotExist)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// envDuration reads a Go duration from the environment, falling back rather than refusing
// to start: a malformed interval is a cosmetic mistake and should not keep a device offline.
func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshpd: %s=%q is not a duration; using %s\n", key, v, fallback)
		return fallback
	}
	return d
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func defaultStateDir() string {
	if v := os.Getenv("MESHP_STATE_DIR"); v != "" {
		return v
	}
	switch runtime.GOOS {
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
	// AF_UNIX works on Windows 10 1803 and later, so the same mechanism serves every
	// platform; only the conventional location differs.
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\meshp\meshpd.sock`
	}
	return agentapi.DefaultSocketPath
}
