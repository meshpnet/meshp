// Package testdb hands each test package a PostgreSQL database of its own.
//
// It exists because `go test ./...` runs packages in parallel, and every package
// that tests against a database begins by dropping the schema. Sharing one
// database means two packages truncate each other's fixtures halfway through, which
// surfaces as tests that pass alone and fail together — the worst kind of failure
// to chase, because the output blames whichever test happened to be running.
//
// Serialising with `go test -p 1` would also fix it, at the cost of slowing every
// package down for the sake of two. A database per package costs one CREATE
// DATABASE and keeps the suite parallel.
package testdb

import (
	"context"
	"errors"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// EnvVar names the base connection string. CI always sets it; a laptop usually
// does not, which is why callers skip rather than fail without it.
const EnvVar = "MESHP_TEST_DATABASE_URL"

// safeSuffix keeps a caller from constructing an identifier that would need
// quoting, since CREATE DATABASE cannot take a bound parameter.
var safeSuffix = regexp.MustCompile(`^[a-z][a-z0-9_]{0,32}$`)

// URL returns a connection string for a database named after suffix, creating it if
// it does not exist. The database is left in place between runs: recreating it every
// time would mean re-running migrations from nothing on every invocation, and tests
// that care about starting empty already drop the schema themselves.
func URL(t *testing.T, suffix string) string {
	t.Helper()

	base := os.Getenv(EnvVar)
	if base == "" {
		t.Skipf("set %s to run tests that need PostgreSQL", EnvVar)
	}
	if !safeSuffix.MatchString(suffix) {
		t.Fatalf("testdb: suffix %q must be lowercase letters, digits and underscores", suffix)
	}

	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatalf("testdb: %s is not a URL: %v", EnvVar, err)
	}
	baseName := parsed.Path
	if len(baseName) > 0 && baseName[0] == '/' {
		baseName = baseName[1:]
	}
	if baseName == "" {
		t.Fatalf("testdb: %s names no database", EnvVar)
	}
	target := baseName + "_" + suffix

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("testdb: connecting to %s: %v", baseName, err)
	}
	defer func() { _ = admin.Close(ctx) }()

	// CREATE DATABASE has no IF NOT EXISTS and cannot be parameterised, so the
	// duplicate is caught rather than avoided. The suffix is validated above, which
	// is what makes the interpolation safe.
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+target+`"`); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P04" { // duplicate_database
			t.Fatalf("testdb: creating %s: %v", target, err)
		}
	}

	out := *parsed
	out.Path = "/" + target
	return out.String()
}
