# ADR-0014: A hand-written migration runner that checksums what it applied

- **Status:** accepted
- **Date:** 2026-08-11

## Context

Applying the schema needs a runner. goose was the obvious choice — the migration
files already carry its `-- +goose Up` / `-- +goose Down` markers, and hand-written
migration runners are a well-known source of production incidents.

Two things pushed the other way once it was actually added.

It dictated the language version. goose required Go 1.25.7, forcing the whole
project onto a patch release nothing else needed, and it pulled in a chain of
transitive dependencies for a project that otherwise has three.

More importantly, it does not checksum. The append-only migration policy is
enforced in CI, which catches a pull request that edits a merged migration. CI
cannot see the case that actually hurts: a database that already ran the old
version of a file, or a binary deployed from a branch carrying different SQL under
the same version number. In both, the schema and the code disagree and nothing
says so — queries fail later, somewhere else, for reasons that look unrelated.

The format being parsed is a handful of plain statements with one marker in the
middle. There are no functions, no dollar-quoted bodies, none of the parsing
subtleties that make this hard in general.

## Decision

`internal/store` applies migrations itself:

- Files must match `NNNN_lower_snake_case.sql` and are applied in filename order.
  A name that would sort unpredictably is rejected rather than applied out of turn.
- The whole run holds a PostgreSQL advisory lock, so several control-plane replicas
  starting during a deploy cannot apply the same DDL concurrently.
- Each migration runs in its own transaction together with its bookkeeping row.
  PostgreSQL has transactional DDL, so a failure leaves neither the schema change
  nor the record of it.
- Every applied migration's SHA-256 is stored. On every start, an applied migration
  whose file no longer matches fails with `ErrSchemaModified` and names the file.
- A migration that is unapplied while a later one is applied fails with
  `ErrMigrationOutOfOrder`, which is what two branches merging in the wrong order
  looks like from the database's side.
- Migrations run with `statement_timeout` cleared and `lock_timeout` set. The
  request-serving timeout would kill a large DDL statement partway through a
  deploy; a lock timeout is wanted, because an `ALTER` queued behind a long query
  blocks everything arriving after it.

The checksum covers the Up section only. Rewording the Down half does not change
the schema a live database has, and a check that refuses to start over a comment
is a check somebody switches off.

## Consequences

The append-only policy now holds at runtime as well as at review time, which is
the half that protects real databases. Failures name the file and say what to do.
The dependency list stays at three direct entries and the language version is ours
to choose.

Against that: this is our code, and a migration runner is unforgiving. It is
covered by tests that apply from empty, apply twice, detect an edited migration,
reject an out-of-order one, run six replicas concurrently, and assert that a
failing migration leaves nothing behind — and it will need more as the schema grows
features goose already handles. Down migrations are parsed and validated but not
yet executed by the runner; `scripts/migrate-check.sh` exercises them with psql, so
the rollback path is tested even though nothing in Go runs it.

## Alternatives considered

**goose.** Battle-tested, and the honest default recommendation for most projects.
Rejected on the language-version constraint and the absence of checksums, both of
which mattered more here than the edge cases it handles for us.

**golang-migrate or atlas.** Same trade in a different wrapper; atlas in particular
offers far more than needed and would become the thing defining our schema
workflow.

**Keep goose and add a separate checksum check.** Two mechanisms tracking the same
thing, disagreeing eventually.
