// Package store is meshp-control's access to PostgreSQL.
//
// PostgreSQL is the sole source of truth for desired state. Presence and health
// are high-frequency and ephemeral and deliberately do not live here — see
// ADR-0012 — so nothing in this package should acquire a write on every device
// heartbeat.
//
// Queries are hand-written SQL in queries/ and turned into Go by sqlc. There is
// no ORM and no query builder: the SQL a reviewer reads is the SQL that runs, and
// tenant scoping is visible in the query text rather than assembled at runtime
// from something that might be empty.
package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// Config describes a connection pool.
type Config struct {
	DatabaseURL string

	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	ConnectTimeout  time.Duration

	// StatementTimeout caps any single query. A control plane that lets one bad
	// query hold a connection indefinitely runs out of connections and stops
	// answering agents, which is a much larger outage than the failed query.
	// Migrations override this on their own connection.
	StatementTimeout time.Duration

	// IdleInTransactionTimeout kills sessions that open a transaction and then
	// stop doing anything. Those sessions hold locks, and the locks are what turn
	// one stuck request into a stalled control plane.
	IdleInTransactionTimeout time.Duration

	// ApplicationName shows up in pg_stat_activity, which is where an operator
	// looks first when the database is busy and they want to know who is asking.
	ApplicationName string
}

// DefaultConfig returns sensible settings for a single control-plane replica.
func DefaultConfig(databaseURL string) Config {
	return Config{
		DatabaseURL:              databaseURL,
		MaxConns:                 16,
		MinConns:                 2,
		MaxConnLifetime:          time.Hour,
		MaxConnIdleTime:          30 * time.Minute,
		ConnectTimeout:           10 * time.Second,
		StatementTimeout:         30 * time.Second,
		IdleInTransactionTimeout: 60 * time.Second,
		ApplicationName:          "meshp-control",
	}
}

// Store owns the connection pool and the migrations this binary carries.
type Store struct {
	pool       *pgxpool.Pool
	migrations fs.FS
	log        *slog.Logger
	queries    *dbgen.Queries
}

// Open connects and verifies the connection. It does not migrate; callers decide
// when that happens, because applying a schema is a deploy-time decision and not
// something that should happen as a side effect of opening a pool.
func Open(ctx context.Context, cfg Config, migrationsFS fs.FS, log *slog.Logger) (*Store, error) {
	if cfg.DatabaseURL == "" {
		return nil, errors.New("store: no database URL configured")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: parsing database URL: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	// Server-side settings travel with every connection the pool opens, so they
	// apply to code that has never heard of this package.
	params := poolCfg.ConnConfig.RuntimeParams
	if params == nil {
		params = map[string]string{}
		poolCfg.ConnConfig.RuntimeParams = params
	}
	if cfg.ApplicationName != "" {
		params["application_name"] = cfg.ApplicationName
	}
	if cfg.StatementTimeout > 0 {
		params["statement_timeout"] = msString(cfg.StatementTimeout)
	}
	if cfg.IdleInTransactionTimeout > 0 {
		params["idle_in_transaction_session_timeout"] = msString(cfg.IdleInTransactionTimeout)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("store: creating pool: %w", err)
	}

	s := &Store{pool: pool, migrations: migrationsFS, log: log, queries: dbgen.New(pool)}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connecting to database: %w", err)
	}

	log.Info("database connected",
		"max_conns", cfg.MaxConns,
		"statement_timeout", cfg.StatementTimeout)
	return s, nil
}

func msString(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10)
}

// Close releases every connection. Safe to call more than once.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Pool exposes the underlying pool for code that needs LISTEN/NOTIFY or a
// specific session. Prefer Queries and InTx.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Queries returns generated queries bound to the pool.
func (s *Store) Queries() *dbgen.Queries { return s.queries }

// Ping checks the database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	return nil
}

// InTx runs fn inside a transaction, committing when it returns nil and rolling
// back on an error or a panic.
//
// Every mutation that changes what an agent should do belongs in one of these
// together with the state-version bump, so that a device can never observe the
// change and the old version, or the new version without the change.
func (s *Store) InTx(ctx context.Context, fn func(*dbgen.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	// Rollback after a successful commit reports ErrTxClosed, which is why the
	// error is discarded here rather than tracked with a flag.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(s.queries.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// Health describes the database from a readiness probe's point of view.
type Health struct {
	Reachable       bool          `json:"reachable"`
	SchemaVersion   int64         `json:"schema_version"`
	ExpectedVersion int64         `json:"expected_version"`
	UpToDate        bool          `json:"up_to_date"`
	Latency         time.Duration `json:"-"`
	LatencyMS       int64         `json:"latency_ms"`
	Error           string        `json:"error,omitempty"`

	// Stats worth having in a probe response: an exhausted pool and a slow
	// database look identical from outside and need different responses.
	AcquiredConns int32 `json:"acquired_conns"`
	TotalConns    int32 `json:"total_conns"`
	MaxConns      int32 `json:"max_conns"`
}

// Ready reports whether the control plane should accept traffic. A reachable
// database running an older schema than the binary expects is deliberately not
// ready: serving agents from a schema the code was not written against produces
// errors that are far harder to diagnose than a failed readiness check.
func (h Health) Ready() bool { return h.Reachable && h.UpToDate }

// Health probes the database. It never returns an error; a failed probe is a
// result, and the caller is a readiness endpoint that has to answer either way.
func (s *Store) Health(ctx context.Context) Health {
	stats := s.pool.Stat()
	h := Health{
		AcquiredConns: stats.AcquiredConns(),
		TotalConns:    stats.TotalConns(),
		MaxConns:      stats.MaxConns(),
	}

	start := time.Now()
	if err := s.Ping(ctx); err != nil {
		h.Error = err.Error()
		h.Latency = time.Since(start)
		h.LatencyMS = h.Latency.Milliseconds()
		return h
	}
	h.Reachable = true
	h.Latency = time.Since(start)
	h.LatencyMS = h.Latency.Milliseconds()

	head, err := s.HeadVersion()
	if err != nil {
		h.Error = err.Error()
		return h
	}
	h.ExpectedVersion = head

	version, err := s.SchemaVersion(ctx)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	h.SchemaVersion = version
	h.UpToDate = version == head
	if !h.UpToDate {
		h.Error = fmt.Sprintf("schema is at version %d, this build expects %d", version, head)
	}
	return h
}

// ErrNoRows is returned by generated queries when nothing matched. Re-exported so
// callers do not have to import pgx to tell "not found" from a real failure.
var ErrNoRows = pgx.ErrNoRows

// IsNotFound reports whether err means nothing matched.
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// IsUniqueViolation reports whether err is a PostgreSQL unique-constraint
// violation. Callers use it to turn a race into a specific, actionable message —
// "already enrolled in this network" rather than "constraint 23505".
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// ConstraintName returns the constraint a database error violated, or "".
// Different unique constraints on the same table mean different things, and this is
// how a caller tells them apart.
func ConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}
