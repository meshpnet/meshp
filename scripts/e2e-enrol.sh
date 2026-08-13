#!/usr/bin/env bash
#
# Enrolment and the control channel, end to end, with the real binaries:
#
#   meshpd comes up with no state at all and is still usable
#   a token is minted over the administrative API
#   `meshp join` asks the daemon, which is what generates the keys
#   the keys land with restrictive permissions, written by the daemon
#   `meshp status` reports a live session, and says the tunnel is not up
#   the same token is refused a second time
#   the agent converges: applied version catches up with the network's
#   the session is cleared when the agent exits
#   no private key material appears where it should not
#
# Usage: e2e-enrol.sh <postgres-url>
#
# The unit tests cover each of these against a library. This covers what a person
# actually runs, which is where the wiring mistakes are — flag parsing, file modes,
# socket permissions, exit codes.
set -euo pipefail

DB_URL="${1:?usage: e2e-enrol.sh <postgres-url>}"
PORT="${MESHP_E2E_PORT:-8099}"
BASE="http://127.0.0.1:${PORT}"
ADMIN_TOKEN="e2e-administrative-token-not-a-secret"
SECRET_KEY="e2e-deployment-secret-not-a-secret"

# Short paths on purpose: a unix socket path has a hard limit near 100 bytes, and mktemp
# under a long temporary root can exceed it — which fails with "invalid argument" and no
# hint about why.
WORK="$(mktemp -d /tmp/mpe2e.XXXXXX)"
CONTROL_LOG="$WORK/control.log"
AGENT_LOG="$WORK/meshpd.log"
STATE_DIR="$WORK/state"
SOCKET="$WORK/d.sock"
CONTROL_PID=""
AGENT_PID=""

cleanup() {
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  [ -n "$CONTROL_PID" ] && kill "$CONTROL_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- control plane log ---" >&2; cat "$CONTROL_LOG" >&2 2>/dev/null || true
  echo "--- agent log ---" >&2; cat "$AGENT_LOG" >&2 2>/dev/null || true
  exit 1
}

mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

for binary in ./bin/meshp ./bin/meshpd ./bin/meshp-control; do
  [ -x "$binary" ] || fail "$binary is missing; run make build"
done

echo "starting meshp-control on ${BASE}"
MESHP_DATABASE_URL="$DB_URL" \
MESHP_LISTEN_ADDR="127.0.0.1:${PORT}" \
MESHP_SECRET_KEY="$SECRET_KEY" \
MESHP_ADMIN_TOKEN="$ADMIN_TOKEN" \
  ./bin/meshp-control >"$CONTROL_LOG" 2>&1 &
CONTROL_PID=$!

for _ in $(seq 1 30); do
  curl -fsS "${BASE}/readyz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "${BASE}/readyz" >/dev/null 2>&1 || fail "control plane never became ready"

echo "starting meshpd with no state at all"
# Deliberately before enrolment. An agent that gives up when it has nothing to do cannot
# be joined without restarting a service, which is a paper cut people script around.
./bin/meshpd --reconcile-interval 2s --state-dir "$STATE_DIR" --socket "$SOCKET" --log-level debug >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 30); do
  [ -S "$SOCKET" ] && ./bin/meshp status --socket "$SOCKET" >/dev/null 2>&1 && break
  sleep 1
done
./bin/meshp status --socket "$SOCKET" >"$WORK/status-before.out" 2>&1 \
  || fail "the daemon never answered on its socket"
grep -q 'not enrolled' "$WORK/status-before.out" \
  || fail "an unenrolled daemon did not say so: $(cat "$WORK/status-before.out")"
echo "  socket answers: $(head -1 "$WORK/status-before.out")"

echo "the socket is owner-only"
# A privilege boundary: anything that can reach this socket can enrol the device and,
# once tunnels exist, decide where its traffic goes.
socket_mode="$(mode_of "$SOCKET")"
[ "$socket_mode" = "600" ] || fail "the socket is ${socket_mode}, want 600"
echo "  0${socket_mode}"

echo "seeding a network with address pools"
# A distinct slug and address pool per run. Seeding fixed names made this script pass exactly
# once against any given database and fail on every rerun, which CI never noticed because it
# gets a fresh Postgres each time. A test that only works on a virgin database is one nobody
# can reproduce locally.
RUN_ID="$$"
SLUG="e2e-${RUN_ID}"
# The third octet keeps concurrent and repeated runs out of each other's pools.
OCTET="$(( RUN_ID % 250 + 1 ))"
# Explicit casts: inside a UNION the literals have no inferable type, and cidr will not
# accept text.
NETWORK_ID="$(psql "$DB_URL" -tAqc "
  WITH o AS (INSERT INTO organizations (slug, name) VALUES ('${SLUG}', 'End To End ${RUN_ID}') RETURNING id),
       n AS (INSERT INTO networks (organization_id, slug, name) SELECT id, '${SLUG}', 'End To End ${RUN_ID}' FROM o RETURNING id),
       p AS (INSERT INTO address_pools (network_id, prefix, family, purpose)
             SELECT id, '100.90.${OCTET}.0/24'::cidr, 4, 'device' FROM n
             UNION ALL
             SELECT id, ('fd7c:6d65:7368:' || to_hex(${OCTET}) || '::/120')::cidr, 6, 'device' FROM n
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
./bin/meshp join "$TOKEN" --control-url "$BASE" --socket "$SOCKET" --name e2e-device \
  >"$WORK/join.out" 2>&1 || fail "join failed: $(cat "$WORK/join.out")"
sed 's/^/  /' "$WORK/join.out"
grep -q 'enrolled in network' "$WORK/join.out" || fail "join did not report success"
grep -qE "address     100\.90\.${OCTET}\." "$WORK/join.out" || fail "join reported no IPv4 address"

echo "the keys were written by the daemon, and only it can read them"
[ -f "$STATE_DIR/state.json" ] || fail "no state file was written"
file_mode="$(mode_of "$STATE_DIR/state.json")"
dir_mode="$(mode_of "$STATE_DIR")"
[ "$file_mode" = "600" ] || fail "state file is ${file_mode}, want 600"
[ "$dir_mode" = "700" ] || fail "state directory is ${dir_mode}, want 700"
echo "  file 0${file_mode}, directory 0${dir_mode}"

echo "no private key crossed the socket or reached a log"
# Invariant 1. The CLI asked the daemon to enrol; it must not have been handed anything
# secret in return, and the control plane must never have seen one.
if grep -qiE 'private' "$WORK/join.out"; then fail "the CLI's output mentions a private key"; fi
priv="$(sed -n 's/.*"wireguard_private_key": *"\([^"]*\)".*/\1/p' "$STATE_DIR/state.json" | head -1)"
[ -n "$priv" ] || fail "could not read the stored private key to check for leaks"
if grep -qF "$priv" "$WORK/join.out"; then fail "the CLI printed the WireGuard private key"; fi
if grep -qF "$priv" "$CONTROL_LOG"; then fail "the control plane logged the WireGuard private key"; fi

echo "meshp status reports a live session"
connected=0
for _ in $(seq 1 30); do
  ./bin/meshp status --socket "$SOCKET" >"$WORK/status.out" 2>&1 || true
  if grep -q 'session     connected' "$WORK/status.out"; then connected=1; break; fi
  sleep 1
done
[ "$connected" = "1" ] || fail "status never reported a connected session: $(cat "$WORK/status.out")"
sed 's/^/  /' "$WORK/status.out"
grep -q "$NETWORK_ID" "$WORK/status.out" || fail "status does not mention the network"
# Status must say what is actually true, in either direction: a membership with an address
# is not a working tunnel, and a working tunnel must not be reported as absent. Which one to
# expect is decided by the platform rather than assumed, because this assertion once said
# "always down" and outlived the build it was written for.
if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" = "0" ] && ip link add dev wgprobe0 type wireguard 2>/dev/null; then
  ip link del dev wgprobe0
  grep -qE 'interface   meshp0 \(up' "$WORK/status.out" \
    || fail "a tunnel is possible here but status says it is not up"
else
  grep -q 'interface   meshp0 (not up)' "$WORK/status.out" \
    || fail "no tunnel is possible here, but status claims one"
fi

echo "the agent converges"
lag_zero=0
for _ in $(seq 1 30); do
  lag="$(psql "$DB_URL" -tAqc "
    SELECT coalesce(max(n.state_version - ms.applied_version), -1)
    FROM membership_state ms JOIN networks n ON n.id = ms.network_id
    WHERE ms.network_id = '${NETWORK_ID}'")"
  if [ "$lag" = "0" ]; then lag_zero=1; break; fi
  sleep 1
done
[ "$lag_zero" = "1" ] || fail "applied version never caught up with the network's"
grep -q 'control channel established' "$AGENT_LOG" || fail "the agent never established a session"
sed -n 's/.*msg="recorded desired state" \(.*\)/  \1/p' "$AGENT_LOG" | tail -1

echo "a second device produces a delta, not another snapshot"
# The point of A4: a device joining must not cause every other agent to be handed the whole
# network again. The agent logs whether what it applied was a snapshot.
TOKEN2="$(curl -fsS -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"max_uses":1,"expires_in_seconds":600}' \
  "${BASE}/api/v1/networks/${NETWORK_ID}/enrollment-tokens" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[ -n "$TOKEN2" ] || fail "could not mint a second token"

# A second daemon, so the first has a peer to be told about.
STATE_DIR2="$WORK/state2"
SOCKET2="$WORK/d2.sock"
./bin/meshpd --reconcile-interval 2s --state-dir "$STATE_DIR2" --socket "$SOCKET2" --log-level debug >"$WORK/meshpd2.log" 2>&1 &
AGENT2_PID=$!
for _ in $(seq 1 30); do
  [ -S "$SOCKET2" ] && ./bin/meshp status --socket "$SOCKET2" >/dev/null 2>&1 && break
  sleep 1
done
./bin/meshp join "$TOKEN2" --control-url "$BASE" --socket "$SOCKET2" --name e2e-second \
  >"$WORK/join2.out" 2>&1 || fail "the second join failed: $(cat "$WORK/join2.out")"

# Eight seconds, not thirty: the heartbeat interval is 25s and would deliver this on its
# own, so a generous window here cannot tell a working push from a missing one.
got_delta=0
for _ in $(seq 1 8); do
  if grep -q 'msg="applied desired state".*snapshot=false' "$AGENT_LOG"; then got_delta=1; break; fi
  sleep 1
done
kill "$AGENT2_PID" 2>/dev/null || true
wait "$AGENT2_PID" 2>/dev/null || true

if [ "$got_delta" != "1" ]; then
  echo "--- first agent log ---" >&2; cat "$AGENT_LOG" >&2
  fail "the first agent was sent a snapshot rather than a delta when a peer joined"
fi
sed -n 's/.*msg="applied desired state" \(.*snapshot=false.*\)/  \1/p' "$AGENT_LOG" | tail -1

# Only where a tunnel is possible: Linux, with the privilege to create interfaces and a
# kernel that can. Skipped rather than failed elsewhere, because "enrolled with no tunnel"
# is a real supported state and this script has to pass on a laptop too.
if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" = "0" ] && ip link add dev wgprobe type wireguard 2>/dev/null; then
  ip link del dev wgprobe
  echo "the interface really comes up"

  up=0
  for _ in $(seq 1 20); do
    if ./bin/meshp status --socket "$SOCKET" 2>/dev/null | grep -qE "interface   meshp0 \((up|up, )"; then
      up=1; break
    fi
    sleep 1
  done
  if [ "$up" != "1" ]; then
    echo "--- status ---" >&2; ./bin/meshp status --socket "$SOCKET" >&2 || true
    echo "--- agent log ---" >&2; tail -30 "$AGENT_LOG" >&2
    fail "the interface never came up"
  fi
  ./bin/meshp status --socket "$SOCKET" | sed -n 's/^\(    interface .*\)/  \1/p'

  # And it is the kernel implementation, not a silent userspace fallback (ADR-0015).
  ./bin/meshp status --socket "$SOCKET" | grep -q "up, kernel" \
    || fail "the tunnel is up but not reported as the kernel implementation"

  # The second daemon in this script shares this host, and the control plane gives both
  # devices the interface name meshp0 — so while it was running the two fought over the same
  # interface and the last one to reconcile won. That is an artefact of running two devices
  # on one host, not something a real deployment does, and it is why the assertions below
  # come after that daemon has been stopped.
  #
  # It does make this a stronger test than it was meant to be: the first daemon has to
  # notice that its interface was taken from it and put it back, with nothing from the
  # control plane to prompt it. That only works because reconciling happens on a timer as
  # well as on arrival.
  echo "  the interface is restored after another process took it over"
  healed=0
  for _ in $(seq 1 20); do
    if ip addr show dev meshp0 2>/dev/null | grep -q "100.90.${OCTET}.1/32"; then healed=1; break; fi
    sleep 1
  done
  if [ "$healed" != "1" ]; then
    echo "--- interface ---" >&2; ip addr show dev meshp0 >&2 || true
    echo "--- wg ---" >&2; wg show meshp0 >&2 || true
    echo "--- agent log ---" >&2; tail -20 "$AGENT_LOG" >&2
    fail "the interface never got this device's address back"
  fi

  # The peer that joined second is configured, with a host route only. A wider prefix would
  # mean one peer absorbing traffic for every other device in the network.
  if command -v wg >/dev/null 2>&1; then
    wg show meshp0 allowed-ips | grep -qE "100\.90\.${OCTET}\.2/32" \
      || { wg show meshp0 >&2; fail "the peer is not configured on the interface"; }
    if wg show meshp0 allowed-ips | grep -qE "/(2[0-9]|1[0-9]|[0-9])\b"; then
      wg show meshp0 allowed-ips >&2
      fail "a peer holds a prefix wider than a single host"
    fi
    echo "  peer configured with host routes only"
  fi

  # And the routes the agent installed are its own, not the kernel's.
  ip route show dev meshp0 | grep -q "100.90.${OCTET}.2" \
    || { ip route show dev meshp0 >&2; fail "no route to the peer via the interface"; }
  echo "  route to the peer installed"
fi

echo "the same token a second time"
if ./bin/meshp join "$TOKEN" --control-url "$BASE" --socket "$SOCKET" >"$WORK/replay.out" 2>&1; then
  fail "a replayed token was accepted"
fi
sed 's/^/  /' "$WORK/replay.out"
grep -q 'already been used' "$WORK/replay.out" || fail "the replay was refused for the wrong reason"

echo "the enrolment is in the audit trail"
events="$(psql "$DB_URL" -tAqc "SELECT count(*) FROM audit_events
  WHERE action = 'device.enrolled' AND network_id = '${NETWORK_ID}'")"
# Two: the device under test and the second one that produced the delta.
[ "$events" = "2" ] || fail "${events} device.enrolled events, want 2"

echo "the session is cleared when the agent goes away"
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
cleared=0
for _ in $(seq 1 20); do
  rows="$(psql "$DB_URL" -tAqc "SELECT count(*) FROM membership_state
    WHERE control_session_id IS NOT NULL AND network_id = '${NETWORK_ID}'")"
  if [ "$rows" = "0" ]; then cleared=1; break; fi
  sleep 1
done
[ "$cleared" = "1" ] || fail "a membership is still marked connected after the agent exited"

# Left behind, the next start would warn about a stale socket for no reason.
if [ -S "$SOCKET" ]; then fail "the daemon left its socket behind on exit"; fi

echo "no private key material reached the control plane"
if grep -qiE 'private[_ ]?key' "$CONTROL_LOG"; then fail "the control plane log mentions a private key"; fi
if grep -qF "$TOKEN" "$CONTROL_LOG"; then fail "the control plane logged the plaintext token"; fi

echo
echo "enrolment and the control channel work end to end; a replayed token is refused"
