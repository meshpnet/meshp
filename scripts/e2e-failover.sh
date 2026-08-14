#!/usr/bin/env bash
#
# Three live agents, each with its own interface, in their own network namespaces.
#
# This is the topology e2e-enrol.sh cannot build. The control plane hands every device the
# interface name meshp0, so two daemons on one host fight over it and the second has to be
# stopped — which means everything that needs several devices *simultaneously alive* has
# never run outside a unit test:
#
#   a client and an advertiser completing a real WireGuard handshake
#   the client deciding the advertiser is reachable from that handshake
#   a ReachabilityReport crossing the control channel and reaching the database
#   a client failing over to a standby when the primary stops answering, on its own
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
#      ┌───────────────┼───────────────┬───────────────┐
#   netns mpc      netns mpa       netns mpb
#   10.99.0.2      10.99.0.3       10.99.0.4
#   the client     primary         standby
#
# The agents never address each other directly: every peer is relayed until discovery
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
ADV2_NS="mpb"
CLIENT_IP="10.99.0.2"
ADV_IP="10.99.0.3"
ADV2_IP="10.99.0.4"
ALL_NS="$CLIENT_NS $ADV_NS $ADV2_NS"

# Short paths: a unix socket path has a hard limit near 100 bytes.
WORK="$(mktemp -d /tmp/mpfo.XXXXXX)"
CONTROL_LOG="$WORK/control.log"
RELAY_LOG="$WORK/relay.log"
CONTROL_PID=""
RELAY_PID=""

# retire_ns takes a namespace away completely: its processes first, then the namespace
# itself, which destroys the interfaces inside it.
#
# Killing the daemon alone is not enough and it matters. A kernel WireGuard interface
# answers handshakes on its own — meshpd created it and does not carry its packets — so a
# gateway whose daemon is dead keeps handshaking, and a test that only killed the daemon
# would wait out the liveness window and never see a failure.
retire_ns() {
  local ns="$1"
  ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$ns" 2>/dev/null || true
  ip link del "veth-${ns}" 2>/dev/null || true
}

cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  [ -n "$CONTROL_PID" ] && kill "$CONTROL_PID" 2>/dev/null || true
  # Deleting a namespace takes its processes and its interfaces with it, which is the tidiest
  # part of this whole approach: no daemon survives, and no meshp0 is left behind.
  for ns in $ALL_NS; do
    retire_ns "$ns"
  done
  ip link del "$BRIDGE" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- control plane log ---" >&2; tail -40 "$CONTROL_LOG" >&2 2>/dev/null || true
  echo "--- relay log ---" >&2; tail -20 "$RELAY_LOG" >&2 2>/dev/null || true
  for ns in $ALL_NS; do
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

echo "building three network namespaces"
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
make_ns "$ADV2_NS" "$ADV2_IP"

for ns in $ALL_NS; do
  ip netns exec "$ns" ping -c 1 -W 2 "$HOST_IP" >/dev/null 2>&1 \
    || fail "namespace ${ns} cannot reach the host"
done
echo "  ${ALL_NS} all reach ${HOST_IP}"

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

echo "enrolling a client and two advertisers"
join_ns "$CLIENT_NS" "failover-client"
join_ns "$ADV_NS" "failover-primary"
join_ns "$ADV2_NS" "failover-standby"
for ns in $ALL_NS; do
  ready_ns "$ns"
done

# All three hold meshp0, which is the whole reason for the namespaces.
for ns in $ALL_NS; do
  ip netns exec "$ns" wg show meshp0 >/dev/null 2>&1 || fail "${ns} has no meshp0"
done
echo "  three devices, all holding meshp0, in their own namespaces"

# membership_of and addr_of read what a device was given, from the state its own daemon
# wrote. Reading it from there rather than from the API is a check in itself: the two have
# to agree about who this device is.
membership_of() {
  sed -n 's/.*"membership_id": *"\([^"]*\)".*/\1/p' "$WORK/${1}-state/state.json" | head -1
}
addr_of() {
  sed -n 's/.*"address_v4": *"\([^"]*\)".*/\1/p' "$WORK/${1}-state/state.json" \
    | head -1 | cut -d/ -f1
}

CLIENT_MEMBERSHIP="$(membership_of "$CLIENT_NS")"
ADV_MEMBERSHIP="$(membership_of "$ADV_NS")"
ADV2_MEMBERSHIP="$(membership_of "$ADV2_NS")"
ADV_ADDR="$(addr_of "$ADV_NS")"
ADV2_ADDR="$(addr_of "$ADV2_NS")"
for v in "$CLIENT_MEMBERSHIP" "$ADV_MEMBERSHIP" "$ADV2_MEMBERSHIP" "$ADV_ADDR" "$ADV2_ADDR"; do
  [ -n "$v" ] || fail "could not read every device's membership id and address"
done

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

# A standby behind it. The server orders the candidates and the agent picks among them
# (ADR-0003), so this is the list the client gets to choose from — priority 2 means the
# client should be using the other one until it stops answering.
api -X POST -d "{\"membership_id\":\"${ADV2_MEMBERSHIP}\",\"priority\":2}" \
  "${BASE}/api/v1/networks/${NETWORK_ID}/route-groups/branch-lan/advertisers" >"$WORK/adv2.out" \
  || { cat "$WORK/adv2.out" >&2; fail "recording the standby advertiser failed"; }

# carrier_of names the mesh address of whichever peer holds the carried prefix.
#
# By address rather than by key because both are on the same line of `wg show allowed-ips`:
# a peer's own /32 sits beside whatever prefixes it carries. Identifying the carrier matters
# — "the prefix is on the interface" is satisfied by the wrong peer holding it, which is a
# device sending the customer's traffic somewhere that cannot deliver it.
carrier_of() {
  local line
  line="$(ip netns exec "$CLIENT_NS" wg show meshp0 allowed-ips 2>/dev/null | grep -F "$CARRIED" || true)"
  case "$line" in
    *"${ADV_ADDR}/32"*)  echo "$ADV_ADDR" ;;
    *"${ADV2_ADDR}/32"*) echo "$ADV2_ADDR" ;;
    *) echo "" ;;
  esac
}

carried=0
for _ in $(seq 1 30); do
  if [ "$(carrier_of)" = "$ADV_ADDR" ]; then carried=1; break; fi
  sleep 1
done
if [ "$carried" != "1" ]; then
  ip netns exec "$CLIENT_NS" wg show meshp0 allowed-ips >&2
  fail "the client never carried ${CARRIED} through the first-preference advertiser"
fi
echo "  the client routes ${CARRIED} through the primary (${ADV_ADDR})"

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

# ---------------------------------------------------------------------------
# Failing over
#
# The primary goes away entirely — processes and namespace, which takes its interface with
# it. Killing the daemon would not do: a kernel WireGuard interface answers handshakes on
# its own, so the gateway would keep looking alive to the one signal the agent reads.
#
# Then nothing is done to the client at all. No command, no state delta, no control-plane
# involvement of any kind. It has to work this out from the kernel it already reads every
# reconcile pass, which is the entire claim of ADR-0003: a device that had to ask could not
# fail over during a control-plane outage, and an outage is when it matters most.
echo "retiring the primary advertiser"
retire_ns "$ADV_NS"

# The wait is real and cannot be tuned away. internal/tunnel treats a handshake as live for
# livenessGrace (3 minutes) — deliberately longer than WireGuard's own rekey interval, so a
# working advertiser is never declared dead over a late rekey — and internal/routeprobe then
# wants FailThreshold consecutive failing passes before it moves. So the earliest possible
# failover is a little over three minutes after the last successful handshake, and this
# polls rather than sleeping so it reports the moment it happens.
echo "  waiting for the client to notice (livenessGrace is 3m, so this takes a while)"
started="$(date +%s)"
moved=0
for _ in $(seq 1 100); do
  if [ "$(carrier_of)" = "$ADV2_ADDR" ]; then moved=1; break; fi
  sleep 5
done
elapsed="$(( $(date +%s) - started ))"

if [ "$moved" != "1" ]; then
  echo "--- client allowed-ips ---" >&2
  ip netns exec "$CLIENT_NS" wg show meshp0 allowed-ips >&2
  echo "--- client handshakes ---" >&2
  ip netns exec "$CLIENT_NS" wg show meshp0 latest-handshakes >&2
  echo "--- client agent log ---" >&2
  grep -iE "advertis|moving|route" "$WORK/${CLIENT_NS}.log" | tail -30 >&2 || true
  fail "the client never moved to the standby after ${elapsed}s"
fi
echo "  moved to the standby (${ADV2_ADDR}) after ${elapsed}s, with nothing asked of the server"

# The route follows the cryptokey routing, or the client accepts the customer's LAN and has
# no way to send anything to it.
ip netns exec "$CLIENT_NS" ip route show dev meshp0 | grep -qF "$CARRIED" \
  || { ip netns exec "$CLIENT_NS" ip route show dev meshp0 >&2
       fail "the carried prefix has no route after the move"; }
echo "  and the route moved with it"

# The move is reported, which is what lets every other device be reordered away from a
# gateway this one found dead. Without it each device would have to rediscover the same
# failure alone, three minutes at a time.
told=0
for _ in $(seq 1 30); do
  if grep -q "a device moved between advertisers" "$CONTROL_LOG"; then told=1; break; fi
  sleep 2
done
if [ "$told" != "1" ]; then
  echo "--- control plane log ---" >&2; grep -iE "advertiser|reachab" "$CONTROL_LOG" | tail -20 >&2 || true
  fail "the client moved and never told the control plane"
fi
sed -n 's/.*\(msg="a device moved between advertisers".*\)/  \1/p' "$CONTROL_LOG" | tail -1

echo
echo "three agents, three namespaces, a real handshake, a verdict that reached the control"
echo "plane, and a failover the client worked out for itself"
