#!/usr/bin/env bash
#
# Two live agents, each with its own interface, in their own network namespaces.
#
# This is the topology e2e-enrol.sh cannot build. The control plane hands every device the
# interface name meshp0, so two daemons on one host fight over it and the second has to be
# stopped — which means everything that needs two devices *simultaneously alive* has never
# run outside a unit test:
#
#   a client and an advertiser completing a real WireGuard handshake
#   the client deciding the advertiser is reachable from that handshake
#   a ReachabilityReport crossing the control channel and reaching the database
#
# The last one is the point. Local failover shipped across two releases wired into nothing
# at all — cmd/meshpd never called WithChooser — and no test noticed, because a device with
# no chooser still routes through the server's first candidate and every assertion about
# routing still passes. A report is different: it exists only if the chooser is running.
#
# Namespaces rather than containers because a WireGuard interface is a kernel object in a
# namespace, and that is exactly the thing being isolated. Both agents get to be meshp0.
#
#   root ns          mpbr0 10.99.0.1/24 ── meshp-control, meshp-relay
#                      │
#      ┌───────────────┴───────────────┐
#   netns mpc 10.99.0.2            netns mpa 10.99.0.3
#   the client                     the advertiser
#
# The two agents never address each other directly: every peer is relayed until discovery
# exists (ADR-0002), so their traffic goes out to the relay on the bridge and back. That is
# also what makes this topology honest — it is the path a real deployment behind two NATs
# takes.
#
# Usage: e2e-failover.sh <postgres-url>
set -euo pipefail

DB_URL="${1:?usage: e2e-failover.sh <postgres-url>}"
PORT="${MESHP_E2E_PORT:-8199}"
RELAY_PORT="${MESHP_E2E_RELAY_PORT:-3579}"
RELAY_ID="e2e"
ADMIN_TOKEN="e2e-administrative-token-not-a-secret"
SECRET_KEY="e2e-deployment-secret-not-a-secret"

# The bridge address every namespace reaches the control plane and the relay on. Deliberately
# not 127.0.0.1: a namespace has its own loopback, so the addresses that work for a
# single-host script are exactly the ones that do not work here.
HOST_IP="10.99.0.1"
BRIDGE="mpbr0"
CLIENT_NS="mpc"
ADV_NS="mpa"
CLIENT_IP="10.99.0.2"
ADV_IP="10.99.0.3"

# Short paths: a unix socket path has a hard limit near 100 bytes.
WORK="$(mktemp -d /tmp/mpfo.XXXXXX)"
CONTROL_LOG="$WORK/control.log"
RELAY_LOG="$WORK/relay.log"
CONTROL_PID=""
RELAY_PID=""

cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  [ -n "$CONTROL_PID" ] && kill "$CONTROL_PID" 2>/dev/null || true
  # Deleting a namespace takes its processes and its interfaces with it, which is the tidiest
  # part of this whole approach: no daemon survives, and no meshp0 is left behind.
  for ns in "$CLIENT_NS" "$ADV_NS"; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
  done
  ip link del "$BRIDGE" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- control plane log ---" >&2; tail -40 "$CONTROL_LOG" >&2 2>/dev/null || true
  echo "--- relay log ---" >&2; tail -20 "$RELAY_LOG" >&2 2>/dev/null || true
  for ns in "$CLIENT_NS" "$ADV_NS"; do
    echo "--- ${ns} agent log ---" >&2; tail -30 "$WORK/${ns}.log" >&2 2>/dev/null || true
  done
  exit 1
}

# Skipped rather than failed where the topology is impossible, exactly as the tunnel
# assertions in e2e-enrol.sh are: this has to be runnable from a laptop without pretending
# it proved something.
if [ "$(uname -s)" != "Linux" ] || [ "$(id -u)" != "0" ]; then
  echo "skipped: needs Linux, root"
  exit 0
fi
for tool in ip wg openssl psql; do
  command -v "$tool" >/dev/null 2>&1 || { echo "skipped: needs ${tool}"; exit 0; }
done
if ! ip link add dev wgprobe1 type wireguard 2>/dev/null; then
  echo "skipped: this kernel cannot create a WireGuard interface"
  exit 0
fi
ip link del dev wgprobe1

for binary in ./bin/meshp ./bin/meshpd ./bin/meshp-control ./bin/meshp-relay; do
  [ -x "$binary" ] || fail "$binary is missing; run make build"
done

# ---------------------------------------------------------------------------
# The namespaces

echo "building two network namespaces"
ip link add "$BRIDGE" type bridge
ip addr add "${HOST_IP}/24" dev "$BRIDGE"
ip link set "$BRIDGE" up

# make_ns builds one namespace attached to the bridge, with a route back to the host.
#
# The default route is the bridge rather than nothing: the agent inside has to reach the
# control plane and the relay, and both live in the root namespace on the bridge address.
make_ns() {
  local ns="$1" addr="$2"
  ip netns add "$ns"
  ip link add "veth-${ns}" type veth peer name "in-${ns}"
  ip link set "veth-${ns}" master "$BRIDGE"
  ip link set "veth-${ns}" up
  ip link set "in-${ns}" netns "$ns"
  ip -n "$ns" addr add "${addr}/24" dev "in-${ns}"
  ip -n "$ns" link set "in-${ns}" up
  ip -n "$ns" link set lo up
  ip -n "$ns" route add default via "$HOST_IP"
}
make_ns "$CLIENT_NS" "$CLIENT_IP"
make_ns "$ADV_NS" "$ADV_IP"

ip netns exec "$CLIENT_NS" ping -c 1 -W 2 "$HOST_IP" >/dev/null 2>&1 \
  || fail "the client namespace cannot reach the host"
ip netns exec "$ADV_NS" ping -c 1 -W 2 "$HOST_IP" >/dev/null 2>&1 \
  || fail "the advertiser namespace cannot reach the host"
echo "  ${CLIENT_NS} ${CLIENT_IP} and ${ADV_NS} ${ADV_IP} both reach ${HOST_IP}"

# ---------------------------------------------------------------------------
# The deployment

./bin/meshp-control --generate-relay-key >"$WORK/relay.env" \
  || fail "could not generate a relay keypair"
RELAY_SIGNING_KEY="$(sed -n 's/^MESHP_RELAY_SIGNING_KEY=//p' "$WORK/relay.env")"
RELAY_ISSUER_KEY="$(sed -n 's/^MESHP_RELAY_ISSUER_KEY=//p' "$WORK/relay.env")"
[ -n "$RELAY_SIGNING_KEY" ] && [ -n "$RELAY_ISSUER_KEY" ] \
  || fail "the relay keygen output did not contain both keys"

echo "starting meshp-relay on ${HOST_IP}:${RELAY_PORT}"
MESHP_RELAY_LISTEN="${HOST_IP}:${RELAY_PORT}" \
MESHP_RELAY_ISSUER_KEY="$RELAY_ISSUER_KEY" \
MESHP_RELAY_ADMIN_ADDR="127.0.0.1:9199" \
  ./bin/meshp-relay >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!

# The certificate names the bridge address, because that is what the agents dial. A
# certificate for localhost would be correct for e2e-enrol.sh and useless here.
TLS_DIR="$WORK/tls"
mkdir -p "$TLS_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
  -subj "/CN=${HOST_IP}" \
  -addext "subjectAltName=IP:${HOST_IP}" >/dev/null 2>&1 \
  || fail "could not generate a test certificate"
export SSL_CERT_FILE="$TLS_DIR/cert.pem"
BASE="https://${HOST_IP}:${PORT}"

echo "starting meshp-control on ${BASE}"
# MESHP_RELAYS carries the address the agents must dial, not the one the relay binds. Getting
# this wrong fails silently: the agents are handed a relay they cannot reach and every peer
# stays configured and unreachable.
MESHP_DATABASE_URL="$DB_URL" \
MESHP_LISTEN_ADDR="${HOST_IP}:${PORT}" \
MESHP_SECRET_KEY="$SECRET_KEY" \
MESHP_ADMIN_TOKEN="$ADMIN_TOKEN" \
MESHP_RELAY_SIGNING_KEY="$RELAY_SIGNING_KEY" \
MESHP_RELAYS="${RELAY_ID}=${HOST_IP}:${RELAY_PORT}" \
MESHP_TLS_CERT="${TLS_DIR}/cert.pem" \
MESHP_TLS_KEY="${TLS_DIR}/key.pem" \
  ./bin/meshp-control >"$CONTROL_LOG" 2>&1 &
CONTROL_PID=$!

for _ in $(seq 1 30); do
  curl -fsS --cacert "$TLS_DIR/cert.pem" "${BASE}/readyz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS --cacert "$TLS_DIR/cert.pem" "${BASE}/readyz" >/dev/null 2>&1 \
  || fail "control plane never became ready"

api() {
  curl -fsS --cacert "$TLS_DIR/cert.pem" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H 'Content-Type: application/json' "$@"
}

# A distinct slug and pool per run, so this can be run twice against one database.
RUN_ID="$$"
OCTET="$(( RUN_ID % 250 + 1 ))"
NETWORK_ID="$(psql "$DB_URL" -tAqc "
  WITH o AS (INSERT INTO organizations (slug, name) VALUES ('fo-${RUN_ID}', 'Failover ${RUN_ID}') RETURNING id),
       n AS (INSERT INTO networks (organization_id, slug, name) SELECT id, 'fo-${RUN_ID}', 'Failover ${RUN_ID}' FROM o RETURNING id),
       p AS (INSERT INTO address_pools (network_id, prefix, family, purpose)
             SELECT id, '100.91.${OCTET}.0/24'::cidr, 4, 'device' FROM n RETURNING network_id)
  SELECT DISTINCT network_id FROM p")"
[ -n "$NETWORK_ID" ] || fail "could not seed a network"
echo "  network ${NETWORK_ID}"

# ---------------------------------------------------------------------------
# The agents

# join_ns starts a daemon inside a namespace and enrols it.
join_ns() {
  local ns="$1" name="$2"
  local state="$WORK/${ns}-state" sock="$WORK/${ns}.sock"

  ip netns exec "$ns" ./bin/meshpd --reconcile-interval 2s \
    --state-dir "$state" --socket "$sock" --log-level debug >"$WORK/${ns}.log" 2>&1 &

  for _ in $(seq 1 30); do
    [ -S "$sock" ] && ./bin/meshp status --socket "$sock" >/dev/null 2>&1 && break
    sleep 1
  done
  [ -S "$sock" ] || fail "the daemon in ${ns} never opened its socket"

  local token
  token="$(api -X POST -d '{"max_uses":1,"expires_in_seconds":600}' \
    "${BASE}/api/v1/networks/${NETWORK_ID}/enrollment-tokens" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [ -n "$token" ] || fail "could not mint a token for ${ns}"

  # Inside the namespace, because enrolling is the daemon's job and the daemon is what has
  # to reach the control plane.
  ip netns exec "$ns" ./bin/meshp join "$token" --control-url "$BASE" --socket "$sock" \
    --name "$name" >"$WORK/${ns}-join.out" 2>&1 \
    || { cat "$WORK/${ns}-join.out" >&2; fail "${ns} could not join"; }
}

# ready_ns waits for a session and a live interface.
ready_ns() {
  # Two statements, not one: bash expands every word of a `local` before assigning any of
  # them, so a second name referring to the first reads as unset under `set -u`.
  local ns="$1"
  local sock="$WORK/${ns}.sock"
  for _ in $(seq 1 40); do
    if ./bin/meshp status --socket "$sock" 2>/dev/null \
        | grep -qE 'session     connected' \
       && ./bin/meshp status --socket "$sock" 2>/dev/null \
        | grep -qE 'interface   meshp0 \(up'; then
      return 0
    fi
    sleep 1
  done
  ./bin/meshp status --socket "$sock" >&2 2>/dev/null || true
  fail "${ns} never reached a live session and interface"
}

echo "enrolling a client and an advertiser"
join_ns "$CLIENT_NS" "failover-client"
join_ns "$ADV_NS" "failover-advertiser"
ready_ns "$CLIENT_NS"
ready_ns "$ADV_NS"

# Both agents hold meshp0, which is the whole reason for the namespaces.
ip netns exec "$CLIENT_NS" wg show meshp0 >/dev/null 2>&1 \
  || fail "the client has no meshp0"
ip netns exec "$ADV_NS" wg show meshp0 >/dev/null 2>&1 \
  || fail "the advertiser has no meshp0"
echo "  two devices, both holding meshp0, in their own namespaces"

CLIENT_MEMBERSHIP="$(sed -n 's/.*"membership_id": *"\([^"]*\)".*/\1/p' \
  "$WORK/${CLIENT_NS}-state/state.json" | head -1)"
ADV_MEMBERSHIP="$(sed -n 's/.*"membership_id": *"\([^"]*\)".*/\1/p' \
  "$WORK/${ADV_NS}-state/state.json" | head -1)"
[ -n "$CLIENT_MEMBERSHIP" ] && [ -n "$ADV_MEMBERSHIP" ] \
  || fail "could not read both membership ids"

ADV_ADDR="$(sed -n 's/.*"address_v4": *"\([^"]*\)".*/\1/p' \
  "$WORK/${ADV_NS}-state/state.json" | head -1 | cut -d/ -f1)"
[ -n "$ADV_ADDR" ] || fail "could not read the advertiser's mesh address"

# ---------------------------------------------------------------------------
# A real handshake
#
# Everything above is satisfied by two interfaces that hold the right keys and never speak.
# The probe the agent reports on is derived from handshake age, so without traffic there is
# no handshake, no verdict and nothing to report — and the assertion below would pass or
# fail on timing rather than on behaviour.
echo "forcing a handshake between them"
handshaken=0
for _ in $(seq 1 30); do
  ip netns exec "$CLIENT_NS" ping -c 1 -W 1 "$ADV_ADDR" >/dev/null 2>&1 || true
  if ip netns exec "$CLIENT_NS" wg show meshp0 latest-handshakes 2>/dev/null \
      | awk '{ if ($2 > 0) found = 1 } END { exit !found }'; then
    handshaken=1; break
  fi
  sleep 1
done
if [ "$handshaken" != "1" ]; then
  echo "--- client wg ---" >&2; ip netns exec "$CLIENT_NS" wg show meshp0 >&2
  echo "--- advertiser wg ---" >&2; ip netns exec "$ADV_NS" wg show meshp0 >&2
  echo "--- relay ---" >&2; tail -20 "$RELAY_LOG" >&2
  fail "the two agents never completed a handshake through the relay"
fi
echo "  handshake completed through the relay"

# ---------------------------------------------------------------------------
# Carrying a prefix

echo "advertising a customer prefix"
CARRIED="192.168.${OCTET}.0/24"
api -X POST -d "{\"slug\":\"branch-lan\",\"name\":\"Branch LAN\",\"kind\":\"subnet\",\"prefixes\":[\"${CARRIED}\"]}" \
  "${BASE}/api/v1/networks/${NETWORK_ID}/route-groups" >"$WORK/rg.out" \
  || { cat "$WORK/rg.out" >&2; fail "creating the route group failed"; }
api -X POST -d "{\"membership_id\":\"${ADV_MEMBERSHIP}\",\"priority\":1}" \
  "${BASE}/api/v1/networks/${NETWORK_ID}/route-groups/branch-lan/advertisers" >"$WORK/adv.out" \
  || { cat "$WORK/adv.out" >&2; fail "recording the advertiser failed"; }

carried=0
for _ in $(seq 1 30); do
  if ip netns exec "$CLIENT_NS" wg show meshp0 allowed-ips 2>/dev/null | grep -qF "$CARRIED"; then
    carried=1; break
  fi
  sleep 1
done
[ "$carried" = "1" ] || fail "the client never carried ${CARRIED}"
echo "  the client routes ${CARRIED} through the advertiser"

# ---------------------------------------------------------------------------
# The report
#
# The assertion this whole script exists for. consecutive_ok is incremented only when the
# control plane folds in a client's reachability report, so a non-zero value proves the
# entire chain end to end: the reconciler read the kernel, the chooser turned that into a
# verdict, the session carried it, and the server recorded it against this advertiser.
#
# A device with no chooser routes through the server's first candidate exactly as this one
# does, and every assertion above still passes. This is the one that does not.
echo "waiting for the client to report on its advertiser"
ADVERTISER_ROW="$(psql "$DB_URL" -tAqc \
  "SELECT id FROM route_advertisers WHERE membership_id = '${ADV_MEMBERSHIP}'")"
[ -n "$ADVERTISER_ROW" ] || fail "the advertiser row was not created"

reported=0
for _ in $(seq 1 60); do
  observed="$(psql "$DB_URL" -tAqc \
    "SELECT consecutive_ok FROM advertiser_health WHERE advertiser_id = '${ADVERTISER_ROW}'")"
  if [ -n "$observed" ] && [ "$observed" -gt 0 ]; then reported=1; break; fi
  sleep 1
done
if [ "$reported" != "1" ]; then
  echo "--- advertiser health ---" >&2
  psql "$DB_URL" -c "SELECT * FROM advertiser_health WHERE advertiser_id = '${ADVERTISER_ROW}'" >&2 || true
  echo "--- client agent log ---" >&2
  grep -iE "advertis|route|report" "$WORK/${CLIENT_NS}.log" | tail -20 >&2 || true
  fail "no reachability report from the client ever reached the control plane"
fi
echo "  the control plane recorded the client's verdict (consecutive_ok=${observed})"

# One report from one device is enough, because it arrives already filtered: the agent
# counted its own failures and successes and held a minimum time before sending it, so the
# control plane does not count samples again. This assertion could not be made until it
# did — an advertiser used to sit at 'unknown' until ten different clients happened to
# report, which was arithmetic rather than design.
state="$(psql "$DB_URL" -tAqc \
  "SELECT state FROM advertiser_health WHERE advertiser_id = '${ADVERTISER_ROW}'")"
[ "$state" = "healthy" ] \
  || fail "one client reported it reachable and it is '${state}', want healthy"
echo "  and moved it to healthy on that one report"

echo
echo "two agents, two namespaces, one real handshake, and a verdict that reached the control plane"
