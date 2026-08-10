#!/usr/bin/env bash
#
# Apply every migration, roll it all back, then apply it again.
#
# Applying once only proves the Up half parses. The round trip proves the Down
# half is complete: if it leaves a type, index or constraint behind, the second
# Up fails. That matters because a Down nobody exercises is a Down that does not
# work, and the moment it is needed is the worst moment to find out.
set -euo pipefail

DB_URL="${1:?usage: migrate-check.sh <postgres-url>}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-migrations}"

psql_q() { psql "$DB_URL" -v ON_ERROR_STOP=1 -q "$@"; }

table_count() {
  psql "$DB_URL" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"
}

# Migration files are applied in filename order, so the names have to sort
# correctly. A file that does not match NNNN_name.sql would sort unpredictably
# against the others.
for f in "$MIGRATIONS_DIR"/*.sql; do
  base=$(basename "$f")
  if [[ ! "$base" =~ ^[0-9]{4}_[a-z0-9_]+\.sql$ ]]; then
    echo "FAIL: $base does not match NNNN_lower_snake_case.sql" >&2
    exit 1
  fi
done

apply_up() {
  for f in "$MIGRATIONS_DIR"/*.sql; do
    echo "  up   $(basename "$f")"
    sed '/^-- +goose Down/,$d' "$f" | psql_q
  done
}

apply_down() {
  # Reverse order: later migrations may depend on earlier ones.
  for f in $(ls -r "$MIGRATIONS_DIR"/*.sql); do
    if ! grep -q '^-- +goose Down' "$f"; then
      echo "FAIL: $(basename "$f") has no Down section" >&2
      exit 1
    fi
    echo "  down $(basename "$f")"
    sed -n '/^-- +goose Down/,$p' "$f" | psql_q
  done
}

echo "first apply"
apply_up
after_first=$(table_count)
echo "  $after_first tables"
if [ "$after_first" -lt 1 ]; then
  echo "FAIL: migrations created no tables" >&2
  exit 1
fi

echo "roll back"
apply_down
remaining=$(table_count)
echo "  $remaining tables remain"
if [ "$remaining" -ne 0 ]; then
  echo "FAIL: rollback left $remaining tables behind" >&2
  psql "$DB_URL" -tAc \
    "SELECT '  leftover: '||table_name FROM information_schema.tables WHERE table_schema='public'" >&2
  exit 1
fi

echo "re-apply"
apply_up
after_second=$(table_count)
echo "  $after_second tables"
if [ "$after_second" -ne "$after_first" ]; then
  echo "FAIL: re-apply produced $after_second tables, first apply produced $after_first" >&2
  exit 1
fi

echo "migrations apply, roll back and re-apply cleanly"
