package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// advisoryLockKey serialises migration runs. Any number works as long as every
// process uses the same one; this is "mesh" in ASCII, which makes it
// recognisable when someone is staring at pg_locks wondering what is holding
// things up.
const advisoryLockKey int64 = 0x6d657368

// migrationFilePattern is enforced rather than merely expected. Migrations are
// applied in filename order, so a name that sorts unpredictably against its
// neighbours is a schema applied in the wrong order.
var migrationFilePattern = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// downMarker separates the two halves of a migration file.
const downMarker = "-- +goose Down"

const upMarker = "-- +goose Up"

// ErrSchemaModified means a migration already applied to this database no longer
// matches the file of the same version.
//
// This is the runtime half of the append-only policy. CI refuses a pull request
// that edits a merged migration; this refuses to start against a database whose
// history disagrees with the code, which is the case CI cannot see — a database
// that ran the old version of a file that has since been changed, or a binary
// carrying migrations from a different branch.
var ErrSchemaModified = errors.New("store: an applied migration no longer matches its file")

// ErrMigrationOutOfOrder means a migration is unapplied while a later one is
// already applied, which happens when two branches add migrations and merge in
// the wrong order.
var ErrMigrationOutOfOrder = errors.New("store: migration is older than the applied schema")

// Migration is one parsed migration file.
type Migration struct {
	Version int64
	Name    string
	Up      string
	// Checksum covers the Up section only. Editing the Down section does not
	// change the schema a database actually has, and treating a reworded comment
	// down there as a reason to refuse startup would be brittle enough that
	// somebody would switch the check off.
	Checksum string
}

// MigrateResult describes what a migration run did.
type MigrateResult struct {
	Applied       []Migration
	AlreadyAtHead bool
	Version       int64
}

// ParseMigrations reads and validates every migration in fsys.
func ParseMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("store: listing migrations: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("store: no migrations found")
	}

	out := make([]Migration, 0, len(entries))
	seen := map[int64]string{}

	for _, name := range entries {
		base := filepath.Base(name)
		m := migrationFilePattern.FindStringSubmatch(base)
		if m == nil {
			return nil, fmt.Errorf("store: %q does not match NNNN_lower_snake_case.sql", base)
		}
		version, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("store: %q has an unparseable version: %w", base, err)
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("store: version %d used by both %q and %q", version, prev, base)
		}
		seen[version] = base

		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("store: reading %q: %w", base, err)
		}
		up, err := extractUp(string(body), base)
		if err != nil {
			return nil, err
		}

		sum := sha256.Sum256([]byte(up))
		out = append(out, Migration{
			Version:  version,
			Name:     m[2],
			Up:       up,
			Checksum: hex.EncodeToString(sum[:]),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// extractUp returns the Up half of a migration file.
func extractUp(body, name string) (string, error) {
	if !strings.Contains(body, downMarker) {
		// A migration with no Down cannot be rolled back, and the moment that
		// matters is the moment nobody has time to write one.
		return "", fmt.Errorf("store: %q has no %q section", name, downMarker)
	}
	up := body[:strings.Index(body, downMarker)]
	if i := strings.Index(up, upMarker); i >= 0 {
		up = up[i+len(upMarker):]
	}
	up = strings.TrimSpace(up)
	if up == "" {
		return "", fmt.Errorf("store: %q has an empty Up section", name)
	}
	return up, nil
}

// Migrate applies every unapplied migration, in order, under an advisory lock so
// that several control-plane replicas starting at once cannot race.
func (s *Store) Migrate(ctx context.Context) (MigrateResult, error) {
	migrations, err := ParseMigrations(s.migrations)
	if err != nil {
		return MigrateResult{}, err
	}
	head := migrations[len(migrations)-1].Version

	// Everything below runs on one connection, because an advisory lock is held
	// by a session rather than by the pool.
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return MigrateResult{}, fmt.Errorf("store: acquiring a connection to migrate: %w", err)
	}
	defer conn.Release()

	// A statement timeout suited to serving requests will kill a large DDL
	// statement halfway through a deploy. A lock timeout, by contrast, is wanted
	// here: an ALTER that queues behind a long-running query blocks every query
	// that arrives after it, so failing fast and retrying beats piling up.
	if _, err := conn.Exec(ctx, "SET statement_timeout = 0"); err != nil {
		return MigrateResult{}, fmt.Errorf("store: clearing statement_timeout: %w", err)
	}
	if _, err := conn.Exec(ctx, "SET lock_timeout = '10s'"); err != nil {
		return MigrateResult{}, fmt.Errorf("store: setting lock_timeout: %w", err)
	}

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return MigrateResult{}, fmt.Errorf("store: taking the migration lock: %w", err)
	}
	defer func() {
		// Best effort: releasing the session also releases the lock.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", advisoryLockKey)
	}()

	if _, err := conn.Exec(ctx, createSchemaMigrations); err != nil {
		return MigrateResult{}, fmt.Errorf("store: creating schema_migrations: %w", err)
	}

	applied, err := loadApplied(ctx, conn.Conn())
	if err != nil {
		return MigrateResult{}, err
	}

	// Highest applied version, used to catch a migration arriving out of order.
	var highest int64
	for v := range applied {
		if v > highest {
			highest = v
		}
	}

	result := MigrateResult{Version: highest}
	for _, m := range migrations {
		if got, ok := applied[m.Version]; ok {
			if got != m.Checksum {
				return result, fmt.Errorf(
					"%w: %04d_%s.sql was applied as %s but is now %s",
					ErrSchemaModified, m.Version, m.Name, got[:12], m.Checksum[:12])
			}
			continue
		}
		if m.Version < highest {
			return result, fmt.Errorf(
				"%w: %04d_%s.sql is unapplied but version %d is already applied; renumber it above %d",
				ErrMigrationOutOfOrder, m.Version, m.Name, highest, highest)
		}

		if err := applyOne(ctx, conn.Conn(), m); err != nil {
			return result, err
		}
		result.Applied = append(result.Applied, m)
		result.Version = m.Version
		highest = m.Version
	}

	result.AlreadyAtHead = len(result.Applied) == 0 && result.Version == head
	return result, nil
}

const createSchemaMigrations = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    bigint PRIMARY KEY,
    name       text NOT NULL,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

func loadApplied(ctx context.Context, conn *pgx.Conn) (map[int64]string, error) {
	rows, err := conn.Query(ctx, "SELECT version, checksum FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("store: reading schema_migrations: %w", err)
	}
	defer rows.Close()

	out := map[int64]string{}
	for rows.Next() {
		var version int64
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("store: scanning schema_migrations: %w", err)
		}
		out[version] = checksum
	}
	return out, rows.Err()
}

// applyOne runs a migration and records it in the same transaction. PostgreSQL
// has transactional DDL, so a failure leaves neither the schema change nor the
// bookkeeping behind — there is no dirty state to clean up by hand.
func applyOne(ctx context.Context, conn *pgx.Conn, m Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: beginning migration %d: %w", m.Version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, m.Up); err != nil {
		return fmt.Errorf("store: applying %04d_%s.sql: %w", m.Version, m.Name, err)
	}
	_, err = tx.Exec(ctx,
		"INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
		m.Version, m.Name, m.Checksum)
	if err != nil {
		return fmt.Errorf("store: recording migration %d: %w", m.Version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: committing migration %d: %w", m.Version, err)
	}
	return nil
}

// SchemaVersion returns the highest applied migration version, or 0 when none
// have been applied.
func (s *Store) SchemaVersion(ctx context.Context) (int64, error) {
	var version *int64
	err := s.pool.QueryRow(ctx,
		"SELECT max(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("store: reading schema version: %w", err)
	}
	if version == nil {
		return 0, nil
	}
	return *version, nil
}

// HeadVersion returns the newest migration this binary carries.
func (s *Store) HeadVersion() (int64, error) {
	migrations, err := ParseMigrations(s.migrations)
	if err != nil {
		return 0, err
	}
	return migrations[len(migrations)-1].Version, nil
}
