// Command meshp-control is the control plane.
//
// It computes desired state, holds identity, policy and IPAM, and terminates the
// device control channel. It never carries user traffic: packets go device to
// device, device to relay, or device to route advertiser (Invariant 2).
//
// It also must build and run with no reference to any proprietary component. The
// commercial layer talks to this process over its HTTP API and is never linked
// into it (Invariant 12, enforced by `make standalone-check`).
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

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
	"github.com/meshpnet/meshp/internal/version"
	"github.com/meshpnet/meshp/migrations"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print build information and exit")
		listenAddr  = flag.String("listen", envOr("MESHP_LISTEN_ADDR", ":8080"), "address to listen on")
		databaseURL = flag.String("database-url", os.Getenv("MESHP_DATABASE_URL"), "PostgreSQL connection string")
		skipMigrate = flag.Bool("skip-migrations", envBool("MESHP_SKIP_MIGRATIONS"),
			"do not apply migrations at startup; readiness still requires the schema to be current")
		logLevel = flag.String("log-level", envOr("MESHP_LOG_LEVEL", "info"), "debug, info, warn or error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("meshp-control"))
		return
	}

	log := newLogger(*logLevel)

	// A missing database URL is a configuration mistake rather than a transient
	// condition, so it fails now and loudly. An unreachable database is the
	// opposite: it is retried, because a control plane that exits when PostgreSQL
	// restarts turns a brief database blip into an outage that needs a human.
	if *databaseURL == "" {
		log.Error("no database configured", "hint", "set MESHP_DATABASE_URL or pass --database-url")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log, *listenAddr, *databaseURL, *skipMigrate); err != nil {
		log.Error("meshp-control exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshp-control stopped cleanly")
}

func run(ctx context.Context, log *slog.Logger, addr, databaseURL string, skipMigrate bool) error {
	// The store is published once it is connected and migrated. Until then the
	// process is alive but not ready, which is exactly what an orchestrator needs
	// to know: keep it running, send it no traffic.
	var current atomic.Pointer[store.Store]

	srv := &http.Server{
		Addr:              addr,
		Handler:           newMux(log, &current),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr)
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	// Connecting happens alongside serving rather than before it, so the liveness
	// probe answers while the database is still coming up.
	go func() {
		s, err := connect(ctx, log, databaseURL, skipMigrate)
		if err != nil {
			if ctx.Err() == nil {
				log.Error("giving up connecting to the database", "error", err)
			}
			return
		}
		current.Store(s)
	}()

	defer func() {
		if s := current.Load(); s != nil {
			s.Close()
		}
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received; draining")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// connect opens the store and applies migrations, retrying while the database is
// unreachable. It returns only once it has succeeded or ctx is done.
func connect(ctx context.Context, log *slog.Logger, databaseURL string, skipMigrate bool) (*store.Store, error) {
	const (
		initialBackoff = 500 * time.Millisecond
		maxBackoff     = 15 * time.Second
	)

	backoff := initialBackoff
	for attempt := 1; ; attempt++ {
		s, err := open(ctx, log, databaseURL, skipMigrate)
		if err == nil {
			return s, nil
		}

		// A schema mismatch is not going to fix itself by waiting: either the
		// migrations were edited after being applied, or this binary is older than
		// the database. Both need a person.
		if errors.Is(err, store.ErrSchemaModified) || errors.Is(err, store.ErrMigrationOutOfOrder) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		log.Warn("database not ready; will retry",
			"attempt", attempt, "retry_in", backoff, "error", err)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func open(ctx context.Context, log *slog.Logger, databaseURL string, skipMigrate bool) (*store.Store, error) {
	s, err := store.Open(ctx, store.DefaultConfig(databaseURL), migrations.FS, log)
	if err != nil {
		return nil, err
	}

	if skipMigrate {
		log.Info("skipping migrations at operator request")
	} else {
		res, err := s.Migrate(ctx)
		if err != nil {
			s.Close()
			return nil, err
		}
		switch {
		case res.AlreadyAtHead:
			log.Info("schema is current", "version", res.Version)
		default:
			for _, m := range res.Applied {
				log.Info("migration applied", "version", m.Version, "name", m.Name)
			}
			log.Info("schema migrated", "version", res.Version, "applied", len(res.Applied))
		}
	}

	// Readiness is not assumed from a successful migration: an operator running
	// with --skip-migrations against an older database must still be told no.
	if h := s.Health(ctx); !h.Ready() {
		s.Close()
		return nil, fmt.Errorf("database is not usable: %s", h.Error)
	}
	log.Info("control plane ready")
	return s, nil
}

func newMux(log *slog.Logger, current *atomic.Pointer[store.Store]) *http.ServeMux {
	mux := http.NewServeMux()

	// Liveness. This answers as long as the process is running, whatever the
	// database is doing — restarting a control plane because PostgreSQL is slow
	// makes an outage worse, not better.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, log, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": version.Version(),
		})
	})

	// Readiness. Reports the database and schema state, because "not ready" with
	// no reason is useless to whoever is paged.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		s := current.Load()
		if s == nil {
			httpx.Error(w, log, http.StatusServiceUnavailable,
				"connecting", "still connecting to the database")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		h := s.Health(ctx)
		status := http.StatusOK
		if !h.Ready() {
			status = http.StatusServiceUnavailable
		}
		httpx.WriteJSON(w, log, status, h)
	})

	// The device control channel and the versioned admin API mount here. The admin
	// API is the only interface the commercial layer is permitted to use.
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, log, http.StatusNotImplemented,
			"not_implemented", "no handler for "+r.Method+" "+r.URL.Path)
	})

	return mux
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

func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "yes":
		return true
	}
	return false
}
