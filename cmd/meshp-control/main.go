// Command meshp-control is the control plane.
//
// It computes desired state, holds identity, policy and IPAM, and terminates
// the device control channel. It never carries user traffic: packets go device
// to device, device to relay, or device to route advertiser (Invariant 2).
//
// It also must build and run with no reference to any proprietary component.
// The commercial MSP layer talks to this process over its HTTP API and is never
// linked into it (Invariant 12, enforced by `make standalone-check`).
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/meshpnet/meshp/internal/version"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print build information and exit")
		listenAddr  = flag.String("listen", envOr("MESHP_LISTEN_ADDR", ":8080"), "address to listen on")
		databaseURL = flag.String("database-url", os.Getenv("MESHP_DATABASE_URL"), "PostgreSQL connection string")
		logLevel    = flag.String("log-level", envOr("MESHP_LOG_LEVEL", "info"), "debug, info, warn or error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("meshp-control"))
		return
	}

	log := newLogger(*logLevel)

	if *databaseURL == "" {
		log.Warn("no database configured; starting in degraded mode",
			"hint", "set MESHP_DATABASE_URL or pass --database-url")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log, *listenAddr); err != nil {
		log.Error("meshp-control exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshp-control stopped cleanly")
}

func run(ctx context.Context, log *slog.Logger, addr string) error {
	// ready flips once migrations have run and the control channel hub is
	// accepting sessions. Liveness and readiness are deliberately separate: a
	// process that is up but cannot serve agents must fail readiness rather
	// than take traffic.
	var ready atomic.Bool

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`+"\n", version.Version())
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"status":"not_ready","reason":"subsystems not registered"}`+"\n")
			return
		}
		fmt.Fprint(w, `{"status":"ready"}`+"\n")
	})

	// The device control channel and the versioned admin API mount here. The
	// admin API is the only interface the commercial layer is permitted to use.
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprint(w, `{"error":"not_implemented"}`+"\n")
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received; draining")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	if envOr("MESHP_LOG_FORMAT", "text") == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
