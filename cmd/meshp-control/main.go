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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/meshpnet/meshp/internal/api"
	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/enroll"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/relaytoken"
	"github.com/meshpnet/meshp/internal/session"
	"github.com/meshpnet/meshp/internal/store"
	"github.com/meshpnet/meshp/internal/tlsconf"
	"github.com/meshpnet/meshp/internal/version"
	"github.com/meshpnet/meshp/migrations"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print build information and exit")
		listenAddr  = flag.String("listen", envOr("MESHP_LISTEN_ADDR", ":8080"), "address to listen on")

		tlsCert = flag.String("tls-cert", os.Getenv("MESHP_TLS_CERT"),
			"path to a TLS certificate; serves HTTPS")
		tlsKey = flag.String("tls-key", os.Getenv("MESHP_TLS_KEY"),
			"path to the TLS certificate's private key")
		tlsDomains = flag.String("tls-domains", os.Getenv("MESHP_TLS_DOMAINS"),
			"comma-separated names to obtain certificates for automatically (Let's Encrypt)")
		tlsCacheDir = flag.String("tls-cache-dir", envOr("MESHP_TLS_CACHE_DIR", "/var/lib/meshp/certs"),
			"where automatically obtained certificates are kept between restarts")
		databaseURL = flag.String("database-url", os.Getenv("MESHP_DATABASE_URL"), "PostgreSQL connection string")
		secretKey   = flag.String("secret-key", os.Getenv("MESHP_SECRET_KEY"), "master secret for enrolment challenges and sessions")
		adminToken  = flag.String("admin-token", os.Getenv("MESHP_ADMIN_TOKEN"), "bootstrap secret for the administrative API")
		skipMigrate = flag.Bool("skip-migrations", envBool("MESHP_SKIP_MIGRATIONS"),
			"do not apply migrations at startup; readiness still requires the schema to be current")
		logLevel = flag.String("log-level", envOr("MESHP_LOG_LEVEL", "info"), "debug, info, warn or error")

		// The Ed25519 key this deployment signs relay tokens with. Relays are configured
		// with the public half and can therefore verify without being able to issue
		// (ADR-0016). Absent means relaying is not offered: devices still enrol and
		// converge, and an agent asking for a token is told so.
		relayKey = flag.String("relay-signing-key", os.Getenv("MESHP_RELAY_SIGNING_KEY"),
			"base64 Ed25519 seed or private key for signing relay tokens; empty disables relaying")
		generateRelayKey = flag.Bool("generate-relay-key", false,
			"print a new relay signing keypair and exit")

		// Where this deployment's relays are, as id=host:port[,host:port];id=... Several
		// addresses per relay because one port is not enough: the agent tries them in order,
		// so the port most likely to get through belongs first.
		relays = flag.String("relays", os.Getenv("MESHP_RELAYS"),
			"relays to offer agents, as id=host:port[,host:port][;id=...]")

		// How far back deltas can be built. An agent offline longer than this is sent a
		// snapshot when it returns, which is correct but expensive — so this is the
		// trade-off between the size of the change log and how cheap a reconnection is
		// after an outage, a weekend, or a closed laptop.
		deltaRetention = flag.Duration("delta-retention", envDuration("MESHP_DELTA_RETENTION", 72*time.Hour),
			"how long to keep the state change log; agents behind it are sent a snapshot")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("meshp-control"))
		return
	}

	if *generateRelayKey {
		// Here rather than in a README, because the alternative is an openssl incantation
		// that people copy from a search result and get subtly wrong.
		if err := printRelayKeypair(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "meshp-control:", err)
			os.Exit(1)
		}
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

	signer, err := parseRelaySigningKey(*relayKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshp-control: relay signing key: %v\n", err)
		os.Exit(2)
	}

	relayConfig, err := session.ParseRelays(*relays)
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshp-control: %v\n", err)
		os.Exit(2)
	}

	tlsOpts := tlsconf.Options{
		CertFile:     *tlsCert,
		KeyFile:      *tlsKey,
		ACMECacheDir: *tlsCacheDir,
	}
	for _, domain := range strings.Split(*tlsDomains, ",") {
		if d := strings.TrimSpace(domain); d != "" {
			tlsOpts.ACMEDomains = append(tlsOpts.ACMEDomains, d)
		}
	}

	cfg := runConfig{
		tls:             tlsOpts,
		relays:          relayConfig,
		relaySigningKey: signer,
		addr:            *listenAddr,
		databaseURL:     *databaseURL,
		secretKey:       []byte(*secretKey),
		adminToken:      *adminToken,
		skipMigrate:     *skipMigrate,
		deltaRetention:  *deltaRetention,
	}
	if err := run(ctx, log, cfg); err != nil {
		log.Error("meshp-control exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshp-control stopped cleanly")
}

type runConfig struct {
	relays          *meshpv1.RelayConfig
	relaySigningKey ed25519.PrivateKey
	tls             tlsconf.Options
	addr            string
	databaseURL     string
	secretKey       []byte
	adminToken      string
	skipMigrate     bool
	deltaRetention  time.Duration
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

	tlsConfig, acmeWrap, err := tlsconf.Config(cfg.tls)
	switch {
	case errors.Is(err, tlsconf.ErrNoTLS):
		// Serving plaintext is a legitimate way to run this — behind a tunnel, or behind
		// something else terminating TLS — but it is never what someone wants by accident,
		// and agents refuse a plaintext control URL that is not loopback. So it is said
		// loudly rather than left to be discovered.
		log.Warn("serving without TLS",
			"note", "enrolment tokens and session signatures cross the network in the clear",
			"hint", "set MESHP_TLS_CERT and MESHP_TLS_KEY, or MESHP_TLS_DOMAINS for automatic certificates")
	case err != nil:
		return fmt.Errorf("meshp-control: %w", err)
	}
	if tlsConfig != nil {
		srv.TLSConfig = tlsConfig
	}

	// The ACME challenge responder, on port 80. Only with automatic certificates, and only
	// ever serving the challenge: it redirects everything else rather than exposing the API
	// over plaintext on a second port.
	var challengeSrv *http.Server
	if acmeWrap != nil {
		challengeSrv = &http.Server{
			Addr:              ":80",
			Handler:           acmeWrap(http.HandlerFunc(redirectToHTTPS)),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := challengeSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn("the certificate challenge listener stopped",
					"error", err, "hint", "port 80 must be reachable to obtain certificates")
			}
		}()
		defer func() { _ = challengeSrv.Close() }()
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.addr, "tls", tlsConfig != nil)
		var err error
		if tlsConfig != nil {
			// The certificate and key are already in the TLS config, loaded and checked
			// before anything started listening.
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
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
		issuer, err := session.NewRelayIssuer(cfg.relaySigningKey, relaytoken.DefaultTTL)
		if err != nil {
			log.Error("could not prepare the relay issuer", "error", err)
			return
		}
		for _, relay := range cfg.relays.GetRelays() {
			log.Info("offering a relay to agents",
				"id", relay.GetId(), "endpoints", strings.Join(relay.GetEndpoints(), ","))
		}
		if cfg.relays == nil {
			log.Warn("no relays configured: peers will know about each other and be unable to reach each other",
				"hint", "set MESHP_RELAYS to id=host:port")
		}

		if issuer == nil {
			log.Warn("relaying is disabled: no signing key configured",
				"hint", "meshp-control --generate-relay-key prints a pair; give the private half here and the public half to each relay")
		} else {
			// Logged so an operator can see what to configure a relay with, and can check a
			// relay's configuration matches without reading a secret anywhere.
			log.Info("relay tokens will be signed by this deployment",
				"public_key", base64.StdEncoding.EncodeToString(issuer.PublicKey()))
		}

		sessionServer, err := session.NewServer(st, session.NewHub(), session.Config{
			MasterSecret: cfg.secretKey,
			RelayIssuer:  issuer,
			Relays:       cfg.relays,
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

		go pruneDeltaLog(ctx, log, st, cfg.deltaRetention)
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

	// The built-in roles are a projection of the permission catalogue in internal/authz, so
	// they are brought up to date on every boot rather than seeded once by a migration. A
	// route added in this release becomes reachable by an owner here; without this it would
	// need a migration, and the permission list would have two homes that drift.
	//
	// After the readiness check on purpose: on a schema older than the one that created the
	// rows, this would fail with something about a missing constraint, and "your database is
	// out of date" is the more useful of the two messages.
	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		st.Close()
		return nil, err
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

// pruneDeltaLog keeps the state change log bounded.
//
// Hourly rather than on every change: the log only has to be smaller than unbounded, and
// a sweep that ran on each mutation would spend more time deleting than the deletions save.
//
// Retention of zero switches this off, which is a deliberate choice an operator can make
// while debugging — the log is then the record of what happened. It is not the default,
// because a table nobody prunes is one nobody notices until it is too big to prune.
func pruneDeltaLog(ctx context.Context, log *slog.Logger, st *store.Store, retention time.Duration) {
	if retention <= 0 {
		log.Warn("the state change log will not be pruned", "delta_retention", retention)
		return
	}

	const sweepInterval = time.Hour
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Bounded on its own, so a sweep cannot outlive the interval and overlap the next
		// one.
		sweepCtx, cancel := context.WithTimeout(ctx, sweepInterval/2)
		res, err := st.PruneDeltaLog(sweepCtx, time.Now().Add(-retention))
		cancel()
		if err != nil {
			// A failed sweep is not fatal: the log grows until the next one succeeds.
			log.Error("could not prune the state change log",
				"error", err, "networks_pruned", res.Networks, "rows_pruned", res.Rows)
			continue
		}
		if res.Rows > 0 {
			log.Info("pruned the state change log",
				"networks", res.Networks, "rows", res.Rows, "retention", retention)
		}
	}
}

// parseRelaySigningKey accepts either a 32-byte seed or a full 64-byte private key.
//
// Both, because `--generate-relay-key` prints a seed and someone will inevitably paste the
// longer form from somewhere else; refusing one of them would be a papercut with no benefit.
func parseRelaySigningKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not base64: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("%d bytes, want a %d-byte seed or a %d-byte private key",
			len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// printRelayKeypair writes a fresh pair, labelled so the halves cannot be confused.
func printRelayKeypair(w io.Writer) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("reading randomness: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// One write, one error to check. Writing a keypair half-way and reporting success would
	// hand someone a secret with no matching public key.
	_, err := fmt.Fprintf(w,
		"# Keep this secret. Give it to meshp-control only.\n"+
			"MESHP_RELAY_SIGNING_KEY=%s\n\n"+
			"# Not secret. Give this to every relay.\n"+
			"MESHP_RELAY_ISSUER_KEY=%s\n",
		base64.StdEncoding.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return err
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envDuration reads a Go duration from the environment.
//
// An unparseable value falls back rather than failing to start, and says so: a control
// plane that refuses to boot over a malformed retention setting has turned a cosmetic
// mistake into an outage.
func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshp-control: %s=%q is not a duration; using %s\n", key, v, fallback)
		return fallback
	}
	return d
}

func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "yes":
		return true
	}
	return false
}

// redirectToHTTPS sends a plaintext caller to the same URL over TLS.
//
// The port-80 listener exists to answer certificate challenges, and answering anything
// else there would put the API on a plaintext port that nobody configured. A redirect is
// the least surprising thing to do with the rest.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}
