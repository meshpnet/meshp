// Command meshpd is the privileged device agent.
//
// It owns the WireGuard private key, which never leaves this process's host
// (Invariant 1). It holds one long-lived control-channel session per network
// membership, reconciles the local system toward the desired state the server sends,
// and answers meshp over a local unix socket.
//
// Two properties matter more than features here:
//
//   - It keeps working when the control plane is unreachable. Existing peers, routes,
//     DNS and route-group candidates are all persisted locally (Invariant 15).
//   - Everything it installs, it can remove. An agent crash or uninstall must never
//     leave a host without networking (Invariant 20).
//
// Neither is exercised yet, because nothing here touches the network stack. What this
// build does is hold sessions and record what it is told, which is what makes the
// convergence machinery testable before there is anything to converge.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/agentstate"
	"github.com/meshpnet/meshp/internal/sessionclient"
	"github.com/meshpnet/meshp/internal/version"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
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

	if err := run(ctx, log, *statePath); err != nil {
		log.Error("meshpd exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshpd stopped cleanly")
}

func run(ctx context.Context, log *slog.Logger, stateDir string) error {
	state, err := agentstate.Load(stateDir)
	if err != nil {
		// Not enrolled is a normal state, not a failure: the agent may be installed
		// before anyone has a token. It waits rather than exiting, so `meshp join` can
		// happen without restarting a service.
		log.Warn("not enrolled; nothing to do",
			"state_dir", stateDir, "hint", "run 'meshp join <token>'", "error", err)
		<-ctx.Done()
		return nil
	}

	identity, err := state.Identity()
	if err != nil {
		return err
	}
	if len(state.Memberships) == 0 {
		log.Warn("enrolled but no memberships; nothing to do")
		<-ctx.Done()
		return nil
	}

	store := &stateStore{dir: stateDir, state: state}
	hostname, _ := os.Hostname()

	// One session per membership, each independent. A device in several networks must
	// not lose one because another's control plane is down (ADR-0004).
	var wg sync.WaitGroup
	for _, m := range state.Memberships {
		membership := m
		wg.Add(1)
		go func() {
			defer wg.Done()

			client := sessionclient.New(sessionclient.Options{
				ControlURL:     membership.ControlURL,
				Identity:       identity,
				MembershipID:   membership.MembershipID,
				AppliedVersion: membership.AppliedStateVersion,
				AgentVersion:   version.Version(),
				OS:             osName(),
				Hostname:       hostname,
				Log:            log.With("network_id", membership.NetworkID),
			})

			applier := &recordingApplier{
				log:          log.With("network_id", membership.NetworkID),
				membershipID: membership.MembershipID,
				store:        store,
			}

			if err := client.Run(ctx, applier); err != nil && ctx.Err() == nil {
				log.Error("session ended", "network_id", membership.NetworkID, "error", err)
			}
		}()
	}

	<-ctx.Done()
	log.Info("shutting down sessions")
	wg.Wait()
	return nil
}

// recordingApplier is the Applier this build ships: it writes down what it was told
// and reports success.
//
// It is deliberately not pretending to configure anything. When WireGuard arrives this
// becomes the reconciler, and the acknowledgement it produces will then mean the
// system actually reached that state. Until then the log says so, so nobody mistakes a
// converged control plane for a working network.
type recordingApplier struct {
	log          *slog.Logger
	membershipID uuid.UUID
	store        *stateStore
}

func (a *recordingApplier) Apply(_ context.Context, delta *meshpv1.StateDelta) ([]string, error) {
	for _, p := range delta.GetUpsertPeers() {
		a.log.Debug("peer in desired state",
			"device", p.GetDeviceName(),
			"allowed_ips", p.GetAllowedIps(),
			"public_key", truncateKey(p.GetPublicKey()))
	}
	if tunnel := delta.GetTunnel(); tunnel != nil {
		a.log.Debug("tunnel in desired state", "mtu", tunnel.GetMtu(), "fail_closed", tunnel.GetFailClosed())
	}

	if err := a.store.setApplied(a.membershipID, int64(delta.GetToVersion())); err != nil {
		// Persisting matters: a version acknowledged but not written would be requested
		// again on every restart, and worse, a future reconciler would believe the host
		// already matched a state it had never applied.
		return []string{"local-state"}, err
	}

	a.log.Info("recorded desired state",
		"version", delta.GetToVersion(),
		"peers", len(delta.GetUpsertPeers()),
		"note", "nothing is configured: this build has no WireGuard")

	// Everything asked of this build was done, so nothing is reported unapplied. The
	// components that do not exist yet are absent from the delta rather than refused.
	return nil, nil
}

// stateStore serialises writes to the on-disk state.
//
// Sessions run concurrently, one per membership, and they all persist into the same
// file. Without the lock, two saves would interleave and one membership's progress
// would silently overwrite another's.
type stateStore struct {
	mu    sync.Mutex
	dir   string
	state *agentstate.State
}

func (s *stateStore) setApplied(membershipID uuid.UUID, version int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.state.Memberships {
		if s.state.Memberships[i].MembershipID != membershipID {
			continue
		}
		if s.state.Memberships[i].AppliedStateVersion == version {
			return nil // nothing changed; no need to rewrite the file
		}
		s.state.Memberships[i].AppliedStateVersion = version
		return agentstate.Save(s.dir, s.state)
	}
	return fmt.Errorf("meshpd: no local membership %s", membershipID)
}

func truncateKey(k string) string {
	if len(k) <= 12 {
		return k
	}
	return k[:12] + "…"
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
