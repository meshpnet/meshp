package store

import (
	"context"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/testdb"
	"github.com/meshpnet/meshp/migrations"
)

// These tests need a real PostgreSQL. They are skipped when
// MESHP_TEST_DATABASE_URL is unset, so `go test ./...` stays useful on a laptop
// with nothing running; CI always sets it, so the coverage is not optional there.
//
// A fake or an in-memory shim would be worse than skipping. Almost everything
// interesting in this package is behaviour PostgreSQL provides — advisory locks,
// transactional DDL, statement timeouts — and a test against a fake would assert
// only that the fake agrees with itself.
//
// None of these use t.Parallel: they share one database and each begins by
// dropping the schema.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	// A database of this package's own. `go test ./...` runs packages in parallel
	// and every database-backed package drops the schema on the way in, so sharing
	// one database means tests that pass alone and fail together.
	return testdb.URL(t, "store")
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// openStore connects without migrating.
func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(testContext(t), DefaultConfig(testDatabaseURL(t)), migrations.FS, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// dropAll removes every table in the public schema, schema_migrations included,
// so the next migration run starts from nothing.
func dropAll(t *testing.T, s *Store) {
	t.Helper()
	ctx := testContext(t)

	rows, err := s.pool.Query(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		t.Fatalf("listing tables: %v", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			t.Fatalf("scanning table name: %v", err)
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("listing tables: %v", err)
	}

	for _, n := range names {
		if _, err := s.pool.Exec(ctx, `DROP TABLE IF EXISTS "`+n+`" CASCADE`); err != nil {
			t.Fatalf("dropping %s: %v", n, err)
		}
	}
}

// freshStore returns a store against an empty database with the schema applied.
func freshStore(t *testing.T) *Store {
	t.Helper()
	s := openStore(t)
	dropAll(t, s)
	if _, err := s.Migrate(testContext(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}
