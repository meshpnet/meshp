// Command meshp-control is the control plane.
//
// It computes desired state, holds identity, policy and IPAM, and terminates the
// device control channel. It never carries user traffic: packets go device to
// device, device to relay, or device to route advertiser (Invariant 2).
//
// It also must build and run with no reference to any proprietary component. The
// commercial layer talks to this process over its HTTP API and is never linked into
// it (Invariant 12, enforced by `make standalone-check`).
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

	"github.com/meshpnet/meshp/internal/api"
	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/enroll"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/session"
	"github.com/meshpnet/meshp/internal/store"
	"github.com/meshpnet/meshp/internal/version"
	"github.com/meshpnet/meshp/migrations"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print build information and exit")
		listenAddr  = flag.String("listen", envOr("MESHP_LISTEN_ADDR", ":8080"), "address to listen on")
		databaseURL = flag.String("database-url", os.Getenv("MESHP_DATABASE_URL"), "PostgreSQL connection string")
		secretKey   = flag.String("secret-key", os.Getenv("MESHP_SECRET_KEY"), "master secret for enrolment challenges and sessions")
		adminToken  = flag.String("admin-token", os.Getenv("MESHP_ADMIN_TOKEN"), "bootstrap secret for the administrative API")
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

	// Missing configuration is a mistake rather than a transient condition, so it
	// fails now and loudly. An unreachable database is the opposite and is retried.
	if *databaseURL == "" {
		log.Error("no database configured", "hint", "set MESHP_DATABASE_URL or pass --database-url")
		os.Exit(2)
	}
	if len(*secretKey) < 16 {
		log.Error("no usable secret key",
			"hint", "set MESHP_SECRET_KEY to at least 16 bytes; generate one with: openssl rand -base64 32")
		os.Exit(2)
	}
	if *adminToken == "" {
		// Running with the administrative API switched off is a legitimate
		// configuration, but it is not what most operators intend, so say so once.
		log.Warn("administrative API disabled: MESHP_ADMIN_TOKEN is not set",
			"effect", "enrolment tokens cannot be minted over HTTP")
	} else if len(*adminToken) < 24 {
		log.Error("administrative token is too short",
			"hint", "MESHP_ADMIN_TOKEN should be at least 24 characters of randomness")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := runConfig{
		addr:        *listenAddr,
		databaseURL: *databaseURL,
		secretKey:   []byte(*secretKey),
		adminToken:  *adminToken,
		skipMigrate: *skipMigrate,
	}
	if err := run(ctx, log, cfg); err != nil {
		log.Error("meshp-control exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshp-control stopped cleanly")
}

type runConfig struct {
	addr        string
	databaseURL string
	secretKey   []byte
	adminToken  string
	skipMigrate bool
}

func run(ctx context.Context, log *slog.Logger, cfg runConfig) error {
	// The served handler is swapped once the database is ready. Until then only the
	// probes answer, so the API cannot be reached half-initialised — an enrolment
	// against a store that does not exist yet would be a nil dereference, and a
	// control plane that panics on its first request is worse than one that says
	// "not yet".
	var handler atomic.Pointer[http.Handler]
	var current atomic.Pointer[store.Store]

	var bootstrap http.Handler = probeMux(log, &current)
	handler.Store(&bootstrap)

	srv := &http.Server{
		Addr: cfg.addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			(*handler.Load()).ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.addr)
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	// Connecting happens alongside serving rather than before it, so the liveness
	// probe answers while the database is still coming up.
	go func() {
		st, err := connect(ctx, log, cfg)
		if err != nil {
			if ctx.Err() == nil {
				log.Error("giving up connecting to the database", "error", err)
			}
			return
		}
		current.Store(st)

		challenger, err := enroll.NewChallenger(cfg.secretKey, enroll.DefaultChallengeTTL, clock.System{})
		if err != nil {
			log.Error("could not derive the enrolment challenge key", "error", err)
			return
		}
		sessionServer, err := session.NewServer(st, session.NewHub(), session.Config{
			MasterSecret: cfg.secretKey,
			Clock:        clock.System{},
			Log:          log,
		})
		if err != nil {
			log.Error("could not start the control channel", "error", err)
			return
		}

		apiServer := api.New(st, enroll.NewService(st, challenger, clock.System{}, log), sessionServer, api.Config{
			AdminToken: cfg.adminToken,
			Clock:      clock.System{},
			Log:        log,
		})

		mux := probeMux(log, &current)
		apiServer.Routes(mux)
		var full http.Handler = mux
		handler.Store(&full)
		log.Info("api serving", "admin_enabled", cfg.adminToken != "")
	}()

	defer func() {
		if st := current.Load(); st != nil {
			st.Close()
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
func connect(ctx context.Context, log *slog.Logger, cfg runConfig) (*store.Store, error) {
	const (
		initialBackoff = 500 * time.Millisecond
		maxBackoff     = 15 * time.Second
	)

	backoff := initialBackoff
	for attempt := 1; ; attempt++ {
		st, err := open(ctx, log, cfg)
		if err == nil {
			return st, nil
		}

		// A schema mismatch will not fix itself by waiting: either the migrations were
		// edited after being applied, or this binary is older than the database. Both
		// need a person.
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

func open(ctx context.Context, log *slog.Logger, cfg runConfig) (*store.Store, error) {
	st, err := store.Open(ctx, store.DefaultConfig(cfg.databaseURL), migrations.FS, log)
	if err != nil {
		return nil, err
	}

	if cfg.skipMigrate {
		log.Info("skipping migrations at operator request")
	} else {
		res, err := st.Migrate(ctx)
		if err != nil {
			st.Close()
			return nil, err
		}
		if res.AlreadyAtHead {
			log.Info("schema is current", "version", res.Version)
		} else {
			for _, m := range res.Applied {
				log.Info("migration applied", "version", m.Version, "name", m.Name)
			}
			log.Info("schema migrated", "version", res.Version, "applied", len(res.Applied))
		}
	}

	// Readiness is not assumed from a successful migration: an operator running with
	// --skip-migrations against an older database must still be told no.
	if h := st.Health(ctx); !h.Ready() {
		st.Close()
		return nil, fmt.Errorf("database is not usable: %s", h.Error)
	}
	log.Info("control plane ready")
	return st, nil
}

// probeMux builds a mux carrying only the health endpoints.
func probeMux(log *slog.Logger, current *atomic.Pointer[store.Store]) *http.ServeMux {
	mux := http.NewServeMux()

	// Liveness. Answers as long as the process is running, whatever the database is
	// doing — restarting a control plane because PostgreSQL is slow makes an outage
	// worse, not better.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, log, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": version.Version(),
		})
	})

	// Readiness. Reports the database and schema state, because "not ready" with no
	// reason is useless to whoever is paged.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		st := current.Load()
		if st == nil {
			httpx.Error(w, log, http.StatusServiceUnavailable,
				"connecting", "still connecting to the database")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		h := st.Health(ctx)
		status := http.StatusOK
		if !h.Ready() {
			status = http.StatusServiceUnavailable
		}
		httpx.WriteJSON(w, log, status, h)
	})

	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, log, http.StatusServiceUnavailable,
			"not_ready", "the control plane is still starting up")
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
