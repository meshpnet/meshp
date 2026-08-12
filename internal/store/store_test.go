package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	"github.com/meshpnet/meshp/migrations"
)

func TestOpenRejectsBadConfiguration(t *testing.T) {
	// No database at all is a configuration mistake, not a transient failure, so
	// it fails immediately rather than being retried forever at startup.
	if _, err := Open(context.Background(), DefaultConfig(""), migrations.FS, nil); err == nil {
		t.Error("Open accepted an empty database URL")
	}
	if _, err := Open(context.Background(), DefaultConfig("not://a valid url at all"), migrations.FS, nil); err == nil {
		t.Error("Open accepted an unparseable database URL")
	}
}

func TestOpenAppliesServerSideSettings(t *testing.T) {
	s := openStore(t)
	ctx := testContext(t)

	// These travel with every connection the pool opens, which means they also
	// apply to code that has never heard of this package.
	var statementTimeout, idleTimeout, appName string
	if err := s.pool.QueryRow(ctx, "SHOW statement_timeout").Scan(&statementTimeout); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, "SHOW idle_in_transaction_session_timeout").Scan(&idleTimeout); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, "SHOW application_name").Scan(&appName); err != nil {
		t.Fatal(err)
	}

	if statementTimeout == "0" {
		t.Error("statement_timeout is unset; one bad query can hold a connection indefinitely")
	}
	if idleTimeout == "0" {
		t.Error("idle_in_transaction_session_timeout is unset; a leaked transaction holds its locks forever")
	}
	// pg_stat_activity is where an operator looks first when the database is busy.
	if appName != "meshp-control" {
		t.Errorf("application_name = %q, want meshp-control", appName)
	}
}

// Migrations must not inherit the request-serving statement timeout: a large DDL
// statement would be killed halfway through a deploy.
func TestMigrationsAreNotSubjectToTheStatementTimeout(t *testing.T) {
	cfg := DefaultConfig(testDatabaseURL(t))
	cfg.StatementTimeout = 50 * time.Millisecond

	s, err := Open(testContext(t), cfg, migrations.FS, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	dropAll(t, s)

	// With a 50ms timeout inherited, applying two dozen tables would fail.
	if _, err := s.Migrate(testContext(t)); err != nil {
		t.Fatalf("Migrate under a 50ms statement_timeout: %v", err)
	}
}

func TestInTxCommits(t *testing.T) {
	s := freshStore(t)
	ctx := testContext(t)
	orgID, networkID := insertOrgAndNetwork(t, s)

	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		if _, err := q.BumpNetworkStateVersion(ctx, networkID); err != nil {
			return err
		}
		_, err := q.BumpNetworkStateVersion(ctx, networkID)
		return err
	})
	if err != nil {
		t.Fatalf("InTx: %v", err)
	}

	n, err := s.Queries().GetNetwork(ctx, networkID)
	if err != nil {
		t.Fatal(err)
	}
	if n.StateVersion != 3 { // starts at 1, bumped twice
		t.Errorf("state_version = %d, want 3", n.StateVersion)
	}
	_ = orgID
}

func TestInTxRollsBackOnError(t *testing.T) {
	s := freshStore(t)
	ctx := testContext(t)
	_, networkID := insertOrgAndNetwork(t, s)

	sentinel := errors.New("deliberate")
	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		if _, err := q.BumpNetworkStateVersion(ctx, networkID); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("InTx error = %v, want the sentinel back unwrapped", err)
	}

	n, err := s.Queries().GetNetwork(ctx, networkID)
	if err != nil {
		t.Fatal(err)
	}
	// A version bump that escaped a rolled-back transaction would tell agents to
	// fetch state that was never written.
	if n.StateVersion != 1 {
		t.Errorf("state_version = %d after rollback, want 1", n.StateVersion)
	}
}

func TestInTxRollsBackOnPanic(t *testing.T) {
	s := freshStore(t)
	ctx := testContext(t)
	_, networkID := insertOrgAndNetwork(t, s)

	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic did not propagate out of InTx")
			}
		}()
		_ = s.InTx(ctx, func(q *dbgen.Queries) error {
			if _, err := q.BumpNetworkStateVersion(ctx, networkID); err != nil {
				return err
			}
			panic("something went badly wrong mid-transaction")
		})
	}()

	n, err := s.Queries().GetNetwork(ctx, networkID)
	if err != nil {
		t.Fatal(err)
	}
	if n.StateVersion != 1 {
		t.Errorf("state_version = %d after a panic, want 1", n.StateVersion)
	}
}

func TestGeneratedQueries(t *testing.T) {
	s := freshStore(t)
	ctx := testContext(t)
	orgID, networkID := insertOrgAndNetwork(t, s)
	q := s.Queries()

	t.Run("GetNetwork", func(t *testing.T) {
		n, err := q.GetNetwork(ctx, networkID)
		if err != nil {
			t.Fatal(err)
		}
		if n.Slug != "hq" || n.OrganizationID != orgID {
			t.Errorf("got %+v", n)
		}
		if n.CreatedAt.IsZero() {
			t.Error("CreatedAt is zero; the timestamptz override is not doing its job")
		}
		if n.DeletedAt != nil {
			t.Errorf("DeletedAt = %v, want nil for a live network", n.DeletedAt)
		}
	})

	t.Run("missing row is distinguishable from a failure", func(t *testing.T) {
		_, err := q.GetNetwork(ctx, uuid.New())
		if !IsNotFound(err) {
			t.Fatalf("error = %v, want a not-found", err)
		}
	})

	t.Run("ListNetworksForOrganization is scoped", func(t *testing.T) {
		mine, err := q.ListNetworksForOrganization(ctx, orgID)
		if err != nil {
			t.Fatal(err)
		}
		if len(mine) != 1 {
			t.Fatalf("got %d networks, want 1", len(mine))
		}
		// Tenant isolation is the point: another organisation's id must return
		// nothing, not everything.
		others, err := q.ListNetworksForOrganization(ctx, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		if len(others) != 0 {
			t.Errorf("a foreign organisation id returned %d networks", len(others))
		}
	})

	t.Run("BumpNetworkStateVersion returns the new version", func(t *testing.T) {
		v, err := q.BumpNetworkStateVersion(ctx, networkID)
		if err != nil {
			t.Fatal(err)
		}
		if v != 2 {
			t.Errorf("version = %d, want 2", v)
		}
	})

	t.Run("ListActiveMemberships", func(t *testing.T) {
		got, err := q.ListActiveMemberships(ctx, networkID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("got %d memberships in a network with no devices", len(got))
		}
	})

	t.Run("GetConvergenceLag", func(t *testing.T) {
		// The single best health signal in a reconciliation system, so it needs to
		// work before anything depends on it.
		got, err := q.GetConvergenceLag(ctx, networkID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("got %d rows for a network with no devices", len(got))
		}
	})
}

func TestHealthReportsPoolPressure(t *testing.T) {
	s := freshStore(t)
	h := s.Health(testContext(t))

	if !h.Reachable || !h.UpToDate || !h.Ready() {
		t.Fatalf("Health on a migrated database: %+v", h)
	}
	if h.MaxConns == 0 {
		t.Error("MaxConns is 0; an exhausted pool and a slow database would look identical from a probe")
	}
	if h.Error != "" {
		t.Errorf("Error = %q on a healthy database", h.Error)
	}
}

func TestHealthOnAnUnreachableDatabase(t *testing.T) {
	s := openStore(t)
	s.Close() // simulate the database going away underneath us

	h := s.Health(testContext(t))
	if h.Ready() {
		t.Error("Health reports ready against a closed pool")
	}
	if h.Error == "" {
		t.Error("Health gives no reason; a probe response with no reason is useless at 3am")
	}
	if !strings.Contains(strings.ToLower(h.Error), "closed") && !strings.Contains(h.Error, "ping") {
		t.Logf("error text was %q", h.Error) // informational, not a failure
	}
}

// insertOrgAndNetwork seeds the minimum rows the read queries need. Inserts are
// written as raw SQL rather than added to queries/ because the production insert
// paths belong with the features that need them, not with the store layer.
func insertOrgAndNetwork(t *testing.T, s *Store) (orgID, networkID uuid.UUID) {
	t.Helper()
	ctx := testContext(t)

	err := s.pool.QueryRow(ctx,
		`INSERT INTO organizations (slug, name) VALUES ('acme', 'Acme') RETURNING id`).Scan(&orgID)
	if err != nil {
		t.Fatalf("inserting organization: %v", err)
	}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO networks (organization_id, slug, name) VALUES ($1, 'hq', 'HQ') RETURNING id`,
		orgID).Scan(&networkID)
	if err != nil {
		t.Fatalf("inserting network: %v", err)
	}
	return orgID, networkID
}
