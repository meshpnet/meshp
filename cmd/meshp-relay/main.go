// Command meshp-relay forwards encrypted packets between peers that cannot
// reach each other directly.
//
// It is deliberately dumb. It authenticates that a sender is allowed to use it,
// then forwards opaque bytes to a destination public key. It never holds a
// WireGuard key for a user's tunnel and never needs to decrypt payloads
// (Invariant 3) — which is what makes it safe for a customer to run their own
// relay next to their users, and what keeps the blast radius of a compromised
// relay small.
//
// meshp is relay-first: a new session starts on a relay and upgrades to a
// direct path only if hole punching succeeds (ADR-0002). Connectivity therefore
// never depends on NAT traversal working.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/meshpnet/meshp/internal/version"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print build information and exit")
		relayAddr   = flag.String("listen", envOr("MESHP_RELAY_LISTEN_ADDR", ":3478"), "UDP address for relayed traffic")
		adminAddr   = flag.String("admin-listen", envOr("MESHP_RELAY_ADMIN_ADDR", ":9090"), "HTTP address for health and metrics")
		controlURL  = flag.String("control-url", os.Getenv("MESHP_CONTROL_URL"), "control plane URL used to verify relay tokens")
		logLevel    = flag.String("log-level", envOr("MESHP_LOG_LEVEL", "info"), "debug, info, warn or error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("meshp-relay"))
		return
	}

	log := newLogger(*logLevel)
	log.Info("meshp-relay starting", "relay_addr", *relayAddr, "admin_addr", *adminAddr, "control_url", *controlURL)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log, *adminAddr); err != nil {
		log.Error("meshp-relay exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshp-relay stopped cleanly")
}

func run(ctx context.Context, log *slog.Logger, adminAddr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"status":"ok","version":%q}`+"\n", version.Version())
	})

	srv := &http.Server{
		Addr:              adminAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	log.Warn("packet forwarding not implemented yet; admin endpoint only")

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
