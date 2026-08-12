#!/usr/bin/env bash
#
# The A2 gate, end to end, with the real binaries:
#
#   a token is minted over the administrative API
#   `meshp join` enrols and is given an address
#   the keys land with restrictive permissions
#   `meshp status` reports the membership
#   the same token is refused a second time
#   the enrolment is in the audit trail
#   no private key appears in the server's output
#
# Usage: e2e-enrol.sh <postgres-url>
#
# The unit tests cover each of these against a library. This covers the thing a
# person actually runs, which is where the wiring mistakes are — the flag parsing,
# the file modes, the exit codes.
set -euo pipefail

DB_URL="${1:?usage: e2e-enrol.sh <postgres-url>}"
PORT="${MESHP_E2E_PORT:-8099}"
BASE="http://127.0.0.1:${PORT}"
ADMIN_TOKEN="e2e-administrative-token-not-a-secret"
SECRET_KEY="e2e-deployment-secret-not-a-secret"

WORK="$(mktemp -d)"
LOG="$WORK/control.log"
STATE_A="$WORK/device-a"
STATE_B="$WORK/device-b"
CONTROL_PID=""

cleanup() {
  [ -n "$CONTROL_PID" ] && kill "$CONTROL_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; echo "--- control plane log ---" >&2; cat "$LOG" >&2 || true; exit 1; }

for binary in ./bin/meshp ./bin/meshp-control; do
  [ -x "$binary" ] || fail "$binary is missing; run make build"
done

echo "starting meshp-control on ${BASE}"
MESHP_DATABASE_URL="$DB_URL" \
MESHP_LISTEN_ADDR="127.0.0.1:${PORT}" \
MESHP_SECRET_KEY="$SECRET_KEY" \
MESHP_ADMIN_TOKEN="$ADMIN_TOKEN" \
  ./bin/meshp-control >"$LOG" 2>&1 &
CONTROL_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "${BASE}/readyz" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "${BASE}/readyz" >/dev/null 2>&1 || fail "control plane never became ready"

echo "seeding a network with address pools"
# Explicit casts: inside a UNION the literals have no inferable type, and cidr will
# not accept text.
NETWORK_ID="$(psql "$DB_URL" -tAqc "
  WITH o AS (INSERT INTO organizations (slug, name) VALUES ('e2e', 'End To End') RETURNING id),
       n AS (INSERT INTO networks (organization_id, slug, name) SELECT id, 'e2e', 'End To End' FROM o RETURNING id),
       p AS (INSERT INTO address_pools (network_id, prefix, family, purpose)
             SELECT id, '100.90.0.0/24'::cidr, 4, 'device' FROM n
             UNION ALL
             SELECT id, 'fd7c:6d65:7368::/120'::cidr, 6, 'device' FROM n
             RETURNING network_id)
  SELECT DISTINCT network_id FROM p")"
[ -n "$NETWORK_ID" ] || fail "could not seed a network"
echo "  network ${NETWORK_ID}"

echo "minting an enrolment token"
MINT="$(curl -fsS -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"max_uses":1,"expires_in_seconds":600,"tags":["e2e"]}' \
  "${BASE}/api/v1/networks/${NETWORK_ID}/enrollment-tokens")"
TOKEN="$(printf '%s' "$MINT" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[ -n "$TOKEN" ] || fail "no token in the mint response: $MINT"
case "$TOKEN" in
  meshp_tok_*) ;;
  *) fail "token does not carry the expected prefix: $TOKEN" ;;
esac
echo "  minted ${TOKEN:0:18}…"

echo "the administrative API refuses an unauthenticated caller"
status="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' \
  "${BASE}/api/v1/networks/${NETWORK_ID}/enrollment-tokens")"
[ "$status" = "401" ] || fail "minting without a token returned ${status}, want 401"

echo "meshp join"
./bin/meshp join "$TOKEN" --control-url "$BASE" --state-dir "$STATE_A" --name e2e-device \
  >"$WORK/join.out" 2>&1 || fail "join failed: $(cat "$WORK/join.out")"
sed 's/^/  /' "$WORK/join.out"

grep -q 'enrolled in network' "$WORK/join.out" || fail "join did not report success"
grep -qE 'address     100\.90\.0\.' "$WORK/join.out" || fail "join reported no IPv4 address"

echo "the keys are not readable by anyone else"
file_mode="$(stat -c '%a' "$STATE_A/state.json" 2>/dev/null || stat -f '%Lp' "$STATE_A/state.json")"
dir_mode="$(stat -c '%a' "$STATE_A" 2>/dev/null || stat -f '%Lp' "$STATE_A")"
[ "$file_mode" = "600" ] || fail "state file is ${file_mode}, want 600"
[ "$dir_mode" = "700" ] || fail "state directory is ${dir_mode}, want 700"
echo "  file 0${file_mode}, directory 0${dir_mode}"

echo "meshp status"
./bin/meshp status --state-dir "$STATE_A" >"$WORK/status.out" 2>&1 || fail "status failed"
sed 's/^/  /' "$WORK/status.out"
grep -q "$NETWORK_ID" "$WORK/status.out" || fail "status does not mention the network"

echo "the same token a second time"
if ./bin/meshp join "$TOKEN" --control-url "$BASE" --state-dir "$STATE_B" >"$WORK/replay.out" 2>&1; then
  fail "a replayed token was accepted"
fi
sed 's/^/  /' "$WORK/replay.out"
grep -q 'already been used' "$WORK/replay.out" || fail "the replay was refused for the wrong reason"
[ -e "$STATE_B/state.json" ] && fail "a refused join still wrote state"

echo "the enrolment is in the audit trail"
events="$(psql "$DB_URL" -tAqc "SELECT count(*) FROM audit_events WHERE action = 'device.enrolled'")"
[ "$events" = "1" ] || fail "${events} device.enrolled events, want 1"

echo "meshpd opens a control channel and acknowledges a version"
# The gate for the control channel: the agent authenticates with its identity key,
# receives a snapshot and reports the version it applied, and the control plane records
# it. Convergence lag reaching zero is the single best signal that this works.
./bin/meshpd --state-dir "$STATE_A" --log-level debug >"$WORK/meshpd.log" 2>&1 &
MESHPD_PID=$!

converged=0
for _ in $(seq 1 30); do
  lag="$(psql "$DB_URL" -tAqc "
    SELECT coalesce(min(n.state_version - ms.applied_version), -1)
    FROM membership_state ms JOIN networks n ON n.id = ms.network_id")"
  if [ "$lag" = "0" ]; then converged=1; break; fi
  sleep 1
done
kill "$MESHPD_PID" 2>/dev/null || true
wait "$MESHPD_PID" 2>/dev/null || true

if [ "$converged" != "1" ]; then
  echo "--- meshpd log ---" >&2
  cat "$WORK/meshpd.log" >&2
  fail "meshpd never converged: applied version never caught up with the network's"
fi
grep -q 'control channel established' "$WORK/meshpd.log" || fail "meshpd never established a session"
grep -q 'recorded desired state' "$WORK/meshpd.log" || fail "meshpd never recorded desired state"
sed -n 's/.*msg="recorded desired state" \(.*\)/  \1/p' "$WORK/meshpd.log" | tail -1

# A session that was established must also be cleared when the agent goes away, or the
# dashboard shows devices as connected forever.
session_rows="$(psql "$DB_URL" -tAqc "SELECT count(*) FROM membership_state WHERE control_session_id IS NOT NULL")"
[ "$session_rows" = "0" ] || fail "${session_rows} membership(s) still marked as connected after meshpd exited"

echo "no private key material reached the server"
# Invariant 1, checked against the thing that would betray it: the server's own output.
if grep -qiE 'private[_ ]?key' "$LOG"; then
  fail "the control plane log mentions a private key"
fi
# And the plaintext token must not be logged either, only its identifier.
if grep -q "$TOKEN" "$LOG"; then
  fail "the control plane logged the plaintext token"
fi

echo
echo "enrolment works end to end and a replayed token is refused"
