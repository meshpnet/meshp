package store

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/meshpnet/meshp/migrations"
)

// --- parsing, which needs no database ---------------------------------------

func TestParseMigrationsRealFiles(t *testing.T) {
	got, err := ParseMigrations(migrations.FS)
	if err != nil {
		t.Fatalf("ParseMigrations on the shipped migrations: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no migrations parsed")
	}
	for i, m := range got {
		if i > 0 && m.Version <= got[i-1].Version {
			t.Errorf("migrations are not in ascending order at %d: %d after %d", i, m.Version, got[i-1].Version)
		}
		if m.Checksum == "" {
			t.Errorf("%04d_%s has no checksum", m.Version, m.Name)
		}
		// The Up half must not contain the Down half, or applying a migration
		// would immediately undo it.
		if strings.Contains(m.Up, "DROP TABLE") && strings.Contains(m.Up, "CREATE TABLE") {
			t.Errorf("%04d_%s: Up section appears to contain the Down section", m.Version, m.Name)
		}
	}
}

func TestParseMigrationsRejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		files   fstest.MapFS
		wantErr string
	}{
		{
			name:    "no migrations at all",
			files:   fstest.MapFS{},
			wantErr: "no migrations found",
		},
		{
			name: "filename that would sort unpredictably",
			files: fstest.MapFS{
				"1_init.sql": &fstest.MapFile{Data: []byte("-- +goose Up\nSELECT 1;\n-- +goose Down\n")},
			},
			wantErr: "does not match",
		},
		{
			name: "capitals in the name",
			files: fstest.MapFS{
				"0001_Init.sql": &fstest.MapFile{Data: []byte("-- +goose Up\nSELECT 1;\n-- +goose Down\n")},
			},
			wantErr: "does not match",
		},
		{
			name: "missing Down section",
			files: fstest.MapFS{
				"0001_init.sql": &fstest.MapFile{Data: []byte("-- +goose Up\nSELECT 1;\n")},
			},
			wantErr: "has no",
		},
		{
			name: "empty Up section",
			files: fstest.MapFS{
				"0001_init.sql": &fstest.MapFile{Data: []byte("-- +goose Up\n\n-- +goose Down\nSELECT 1;\n")},
			},
			wantErr: "empty Up section",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMigrations(tt.files)
			if err == nil {
				t.Fatalf("ParseMigrations accepted it")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseMigrationsChecksumIgnoresTheDownSection(t *testing.T) {
	// The checksum exists to detect a change to the SQL that produced a live
	// database. Rewording the Down half changes nothing about that database, and
	// a check that refuses to start over a comment is a check somebody disables.
	base := fstest.MapFS{
		"0001_init.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE t (id int);\n-- +goose Down\nDROP TABLE t;\n"),
		},
	}
	edited := fstest.MapFS{
		"0001_init.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE t (id int);\n-- +goose Down\n-- reworded\nDROP TABLE t;\n"),
		},
	}

	a, err := ParseMigrations(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseMigrations(edited)
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Checksum != b[0].Checksum {
		t.Error("editing the Down section changed the checksum")
	}
}

func TestParseMigrationsChecksumCatchesAnUpEdit(t *testing.T) {
	a, err := ParseMigrations(fstest.MapFS{
		"0001_init.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE t (id int);\n-- +goose Down\nDROP TABLE t;\n"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseMigrations(fstest.MapFS{
		"0001_init.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE t (id bigint);\n-- +goose Down\nDROP TABLE t;\n"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Checksum == b[0].Checksum {
		t.Error("changing a column type did not change the checksum")
	}
}

// --- applying, which needs a database ---------------------------------------

func TestMigrateFromEmpty(t *testing.T) {
	s := openStore(t)
	dropAll(t, s)
	ctx := testContext(t)

	// Before migrating, the control plane must not report itself ready. Serving
	// agents from a schema the code was not written against produces failures
	// that are far harder to diagnose than a failed readiness probe.
	if h := s.Health(ctx); h.Ready() {
		t.Error("Health reports ready against an unmigrated database")
	}

	res, err := s.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(res.Applied) == 0 {
		t.Fatal("Migrate applied nothing to an empty database")
	}

	head, err := s.HeadVersion()
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != head {
		t.Errorf("after migrating, version = %d, want head %d", res.Version, head)
	}
	if h := s.Health(ctx); !h.Ready() {
		t.Errorf("Health still not ready after migrating: %+v", h)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := freshStore(t)
	ctx := testContext(t)

	res, err := s.Migrate(ctx)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(res.Applied) != 0 {
		t.Errorf("second Migrate applied %d migrations, want 0", len(res.Applied))
	}
	if !res.AlreadyAtHead {
		t.Error("AlreadyAtHead = false on a database that is at head")
	}
}

// The runtime half of the append-only policy: a database that ran one version of
// a migration must refuse a binary carrying a different version of it.
func TestMigrateDetectsAnEditedMigration(t *testing.T) {
	s := freshStore(t)
	ctx := testContext(t)

	real, err := ParseMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	first := real[0]

	// Same version, different SQL — exactly what editing a merged migration and
	// deploying it looks like from the database's point of view.
	s.migrations = fstest.MapFS{
		"0001_init.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE tampered (id int);\n-- +goose Down\nDROP TABLE tampered;\n"),
		},
	}

	_, err = s.Migrate(ctx)
	if !errors.Is(err, ErrSchemaModified) {
		t.Fatalf("Migrate error = %v, want ErrSchemaModified", err)
	}
	// The message has to name the file, because the person reading it is midway
	// through a failing deploy.
	if !strings.Contains(err.Error(), "0001_") {
		t.Errorf("error does not name the migration: %v", err)
	}
	_ = first
}

func TestMigrateRejectsAnOutOfOrderMigration(t *testing.T) {
	s := openStore(t)
	dropAll(t, s)
	ctx := testContext(t)

	// Apply version 2 only.
	s.migrations = fstest.MapFS{
		"0002_second.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE second (id int);\n-- +goose Down\nDROP TABLE second;\n"),
		},
	}
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatalf("applying 0002: %v", err)
	}

	// Then a branch merges an older version 1. Applying it now would produce a
	// schema no other database has, so it is refused.
	s.migrations = fstest.MapFS{
		"0001_first.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE first (id int);\n-- +goose Down\nDROP TABLE first;\n"),
		},
		"0002_second.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE second (id int);\n-- +goose Down\nDROP TABLE second;\n"),
		},
	}
	_, err := s.Migrate(ctx)
	if !errors.Is(err, ErrMigrationOutOfOrder) {
		t.Fatalf("Migrate error = %v, want ErrMigrationOutOfOrder", err)
	}
	if !strings.Contains(err.Error(), "renumber") {
		t.Errorf("error does not say what to do about it: %v", err)
	}
}

// Several control-plane replicas start at once during a deploy. The advisory lock
// is what stops them applying the same DDL concurrently; without it this test
// fails with duplicate-object errors rather than merely being slow.
func TestMigrateIsSafeUnderConcurrency(t *testing.T) {
	s := openStore(t)
	dropAll(t, s)

	const replicas = 6
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		applied int
		errs    []error
	)
	for range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.Migrate(testContext(t))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if len(res.Applied) > 0 {
				applied++
			}
		}()
	}
	wg.Wait()

	for _, err := range errs {
		t.Errorf("a replica failed to migrate: %v", err)
	}
	if applied != 1 {
		t.Errorf("%d replicas applied migrations, want exactly 1", applied)
	}

	if h := s.Health(testContext(t)); !h.Ready() {
		t.Errorf("not ready after concurrent migration: %+v", h)
	}
}

func TestMigrateFailureLeavesNothingBehind(t *testing.T) {
	s := openStore(t)
	dropAll(t, s)
	ctx := testContext(t)

	// The second statement fails, so the whole migration must roll back —
	// PostgreSQL has transactional DDL, which is why there is no dirty state to
	// repair by hand.
	s.migrations = fstest.MapFS{
		"0001_broken.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE ok (id int);\nCREATE TABLE ok (id int);\n-- +goose Down\nDROP TABLE ok;\n"),
		},
	}
	if _, err := s.Migrate(ctx); err == nil {
		t.Fatal("Migrate succeeded on a broken migration")
	}

	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='ok')`).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("a failed migration left its first statement applied")
	}

	version, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Errorf("schema version = %d after a failed migration, want 0", version)
	}
}
