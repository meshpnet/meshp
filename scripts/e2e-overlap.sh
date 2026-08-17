#!/usr/bin/env bash
# Two customers on 192.168.1.0/24, one technician, both reachable.
#
# The claim ADR-0004 has made since the beginning and that has never been true. ADR-0020
# settles how, and four merged slices built it: the rules that translate, the numbers to
# translate between, the wire field that carries them, and the agent that applies them. Every
# one of those is tested. The join between them is not.
#
# That gap has produced a defect every time it has been closed in this project. This is the
# test that closes it here: a real daemon holding two real memberships, two real advertisers
# each answering at 192.168.1.5, and an assertion that reaching one does not reach the other.
#
#   [mpca] 192.168.1.5  <--wg--  [mptech]  --wg-->  192.168.1.5 [mpcb]
#            port 9001            two memberships          port 9002
#
# Each advertiser answers at the same address on a different port. That is what makes the
# crossover assertions mean something: if the two prefixes were not really disambiguated a
# misrouted packet would still find a machine at 192.168.1.5, just the wrong one, on a port
# it does not serve.
#
# The advertiser is also the customer host, which is deliberate. Putting 192.168.1.5 on a
# separate LAN behind it would test forwarding as well, and forwarding is currently defeated
# by any host with a foreign FORWARD drop policy (#89) -- which would make this test fail for
# a reason that has nothing to do with what it is asserting.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

DB_URL="${1:?usage: e2e-overlap.sh <postgres-url>}"
PORT="${MESHP_E2E_PORT:-8299}"
RELAY_PORT="${MESHP_E2E_RELAY_PORT:-3679}"
RELAY_ID="e2e"
ADMIN_TOKEN="e2e-administrative-token-not-a-secret"
SECRET_KEY="e2e-deployment-secret-not-a-secret"

HOST_IP="10.98.0.1"
BRIDGE="mpbr1"
TECH_NS="mptech"
CA_NS="mpca"
CB_NS="mpcb"
TECH_IP="10.98.0.2"
CA_IP="10.98.0.3"
CB_IP="10.98.0.4"
ALL_NS="$TECH_NS $CA_NS $CB_NS"

# The address both customers use. The whole point.
CUST_ADDR="192.168.1.5"
CUST_PREFIX="192.168.1.0/24"
PORT_A=9001
PORT_B=9002

WORK="$(mktemp -d /tmp/mpov.XXXXXX)"
CONTROL_LOG="$WORK/control.log"
RELAY_LOG="$WORK/relay.log"
CONTROL_PID=""
RELAY_PID=""

cleanup() {
  for ns in $ALL_NS; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
  done
  ip link del "$BRIDGE" 2>/dev/null || true
  [ -n "$CONTROL_PID" ] && kill "$CONTROL_PID" 2>/dev/null || true
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

if [ "$(uname -s)" != "Linux" ] || [ "$(id -u)" != "0" ]; then
  echo "skipped: needs Linux and root"
  exit 0
fi
if ! ip link add mpprobe type wireguard 2>/dev/null; then
  echo "skipped: this kernel cannot make a WireGuard interface"
  exit 0
fi
ip link del mpprobe
command -v nft >/dev/null 2>&1 || { echo "skipped: needs nft to translate"; exit 0; }
command -v nc >/dev/null 2>&1 || { echo "skipped: needs nc to tell the two customers apart"; exit 0; }

# ---------------------------------------------------------------------------
# The namespaces

echo "building three network namespaces"
ip link add "$BRIDGE" type bridge
ip addr add "${HOST_IP}/24" dev "$BRIDGE"
ip link set "$BRIDGE" up

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
make_ns "$TECH_NS" "$TECH_IP"
make_ns "$CA_NS" "$CA_IP"
make_ns "$CB_NS" "$CB_IP"
for ns in $ALL_NS; do
  ip netns exec "$ns" ping -c 1 -W 2 "$HOST_IP" >/dev/null 2>&1 \
    || fail "namespace ${ns} cannot reach the host"
done
echo "  ${ALL_NS} all reach ${HOST_IP}"

# Both customers answer at the same address, on their own machine. A dummy interface rather
# than a LAN behind them, for the reason in the header.
for ns in "$CA_NS" "$CB_NS"; do
  ip -n "$ns" link add cust type dummy
  ip -n "$ns" addr add "${CUST_ADDR}/24" dev cust
  ip -n "$ns" link set cust up
done
echo "  ${CA_NS} and ${CB_NS} both answer at ${CUST_ADDR}"

# ---------------------------------------------------------------------------
# The control plane

./bin/meshp-control --generate-relay-key >"$WORK/relay.env" \
  || fail "could not mint relay keys"
RELAY_SIGNING_KEY="$(sed -n 's/^MESHP_RELAY_SIGNING_KEY=//p' "$WORK/relay.env")"
RELAY_ISSUER_KEY="$(sed -n 's/^MESHP_RELAY_ISSUER_KEY=//p' "$WORK/relay.env")"

echo "starting meshp-relay on ${HOST_IP}:${RELAY_PORT}"
MESHP_RELAY_LISTEN="${HOST_IP}:${RELAY_PORT}" \
MESHP_RELAY_ISSUER_KEY="$RELAY_ISSUER_KEY" \
MESHP_RELAY_ADMIN_ADDR="127.0.0.1:9299" \
  ./bin/meshp-relay >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!

TLS_DIR="$WORK/tls"
mkdir -p "$TLS_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS_DIR/key.pem" \
  -out "$TLS_DIR/cert.pem" -days 1 -subj "/CN=${HOST_IP}" \
  -addext "subjectAltName=IP:${HOST_IP}" >/dev/null 2>&1 \
  || fail "could not make a certificate"

# Every agent below trusts this certificate and nothing else. Exported rather than passed,
# because the agents run under ip netns exec and inherit the environment.
export SSL_CERT_FILE="$TLS_DIR/cert.pem"

BASE="https://${HOST_IP}:${PORT}"
echo "starting meshp-control on ${BASE}"
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
  || { tail -20 "$CONTROL_LOG" >&2; fail "control plane never became ready"; }

api() {
  curl -fsS --cacert "$TLS_DIR/cert.pem" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H 'Content-Type: application/json' "$@"
}

# ---------------------------------------------------------------------------
# Two customers of one MSP, on the same addresses

RUN_ID="$$"
OCTET="$(( RUN_ID % 200 + 1 ))"
SECOND_OCTET="$(( OCTET + 1 ))"

ORG_ID="$(psql "$DB_URL" -tAqc "
  INSERT INTO organizations (slug, name) VALUES ('ov-${RUN_ID}', 'Overlap ${RUN_ID}') RETURNING id")"
[ -n "$ORG_ID" ] || fail "could not seed an organisation"

seed_network() {
  local slug="$1" octet="$2"
  psql "$DB_URL" -tAqc "
    WITH n AS (INSERT INTO networks (organization_id, slug, name)
               VALUES ('${ORG_ID}', '${slug}', '${slug}') RETURNING id),
         p AS (INSERT INTO address_pools (network_id, prefix, family, purpose)
               SELECT id, '100.92.${octet}.0/24'::cidr, 4, 'device' FROM n RETURNING network_id)
    SELECT DISTINCT network_id FROM p"
}
NET_A="$(seed_network "cust-a-${RUN_ID}" "$OCTET")"
NET_B="$(seed_network "cust-b-${RUN_ID}" "$SECOND_OCTET")"
[ -n "$NET_A" ] && [ -n "$NET_B" ] || fail "could not seed two networks"
echo "  two customers: ${NET_A} and ${NET_B}"

# ---------------------------------------------------------------------------
# The agents

start_daemon() {
  local ns="$1"
  local sock="$WORK/${ns}.sock"
  ip netns exec "$ns" ./bin/meshpd --reconcile-interval 2s \
    --state-dir "$WORK/${ns}-state" --socket "$sock" --log-level debug >"$WORK/${ns}.log" 2>&1 &
  for _ in $(seq 1 30); do
    [ -S "$sock" ] && ./bin/meshp status --socket "$sock" >/dev/null 2>&1 && break
    sleep 1
  done
  [ -S "$sock" ] || fail "the daemon in ${ns} never opened its socket"
}

join_network() {
  local ns="$1" network="$2" name="$3"
  local sock="$WORK/${ns}.sock" token
  token="$(api -X POST -d '{"max_uses":1,"expires_in_seconds":600}' \
    "${BASE}/api/v1/networks/${network}/enrollment-tokens" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [ -n "$token" ] || fail "could not mint a token for ${ns} in ${network}"
  ip netns exec "$ns" ./bin/meshp join "$token" --control-url "$BASE" --socket "$sock" \
    --name "$name" >"$WORK/${ns}-join-${name}.out" 2>&1 \
    || { cat "$WORK/${ns}-join-${name}.out" >&2; fail "${ns} could not join ${network}"; }
}

echo "enrolling one technician into both customers, and an advertiser into each"
start_daemon "$TECH_NS"
start_daemon "$CA_NS"
start_daemon "$CB_NS"

join_network "$CA_NS" "$NET_A" "customer-a-router"
join_network "$CB_NS" "$NET_B" "customer-b-router"

# The condition the whole feature exists for: one device, two memberships (ADR-0004).
join_network "$TECH_NS" "$NET_A" "technician"
join_network "$TECH_NS" "$NET_B" "technician"

# Two interfaces, or nothing below can work. Asserted rather than assumed because enrolment
# is what numbers them, and a second membership handed meshp0 again would have the two fight
# over one interface rather than collide in the routing table.
for iface in meshp0 meshp1; do
  ok=0
  for _ in $(seq 1 40); do
    if ./bin/meshp status --socket "$WORK/${TECH_NS}.sock" 2>/dev/null | grep -qE "interface   ${iface} \(up"; then
      ok=1; break
    fi
    sleep 1
  done
  [ "$ok" = "1" ] || {
    ./bin/meshp status --socket "$WORK/${TECH_NS}.sock" >&2 || true
    fail "the technician never brought up ${iface}"
  }
done
echo "  the technician holds two memberships, on meshp0 and meshp1"

# ---------------------------------------------------------------------------
# Both customers carry the same prefix

echo "both customers carry ${CUST_PREFIX}"
carry() {
  local network="$1" ns="$2"
  api -X POST -d "{\"slug\":\"lan\",\"name\":\"LAN\",\"kind\":\"subnet\",\"prefixes\":[\"${CUST_PREFIX}\"]}" \
    "${BASE}/api/v1/networks/${network}/route-groups" >"$WORK/rg-${ns}.out" \
    || { cat "$WORK/rg-${ns}.out" >&2; fail "could not create the route group in ${network}"; }

  local membership
  membership="$(sed -n 's/.*"membership_id": *"\([^"]*\)".*/\1/p' "$WORK/${ns}-state/state.json" | head -1)"
  [ -n "$membership" ] || fail "could not read ${ns}'s membership"
  api -X POST -d "{\"membership_id\":\"${membership}\",\"priority\":1}" \
    "${BASE}/api/v1/networks/${network}/route-groups/lan/advertisers" >"$WORK/adv-${ns}.out" \
    || { cat "$WORK/adv-${ns}.out" >&2; fail "could not advertise in ${network}"; }
}
carry "$NET_A" "$CA_NS"
carry "$NET_B" "$CB_NS"

# ---------------------------------------------------------------------------
# What the control plane allocated

echo "waiting for the control plane to allocate a range for each"
MAPPED_A=""
MAPPED_B=""
for _ in $(seq 1 40); do
  MAPPED_A="$(psql "$DB_URL" -tAqc "
    SELECT mapped_prefix FROM prefix_mappings WHERE network_id = '${NET_A}'")"
  MAPPED_B="$(psql "$DB_URL" -tAqc "
    SELECT mapped_prefix FROM prefix_mappings WHERE network_id = '${NET_B}'")"
  [ -n "$MAPPED_A" ] && [ -n "$MAPPED_B" ] && break
  sleep 1
done
[ -n "$MAPPED_A" ] && [ -n "$MAPPED_B" ] \
  || fail "no mapped ranges were allocated: A=${MAPPED_A:-none} B=${MAPPED_B:-none}"
[ "$MAPPED_A" != "$MAPPED_B" ] \
  || fail "both customers were given ${MAPPED_A}, which is the collision again"
echo "  customer A at ${MAPPED_A}, customer B at ${MAPPED_B}"

# The host part is carried across unchanged, so the address to reach is the customer's own
# host number inside the allocated range.
host_in() { echo "${1%.*/*}.${CUST_ADDR##*.}"; }
REACH_A="$(host_in "$MAPPED_A")"
REACH_B="$(host_in "$MAPPED_B")"
echo "  so ${CUST_ADDR} is ${REACH_A} in A and ${REACH_B} in B"

# ---------------------------------------------------------------------------
# The assertions

echo "waiting for the technician to install both translations"
installed=0
for _ in $(seq 1 40); do
  if ip netns exec "$TECH_NS" nft list table inet meshp_map >/dev/null 2>&1 \
     && ip netns exec "$TECH_NS" ip route show | grep -q "${MAPPED_A%%/*}" \
     && ip netns exec "$TECH_NS" ip route show | grep -q "${MAPPED_B%%/*}"; then
    installed=1; break
  fi
  sleep 1
done
if [ "$installed" != "1" ]; then
  echo "--- routes ---" >&2; ip netns exec "$TECH_NS" ip route show >&2 || true
  echo "--- nft ---" >&2; ip netns exec "$TECH_NS" nft list ruleset >&2 || true
  echo "--- agent log ---" >&2; grep -iE "map|collid|contest" "$WORK/${TECH_NS}.log" | tail -20 >&2
  fail "the technician did not install routes and rules for both ranges"
fi
echo "  both ranges routed, and the translation is installed"

# A listener on each customer, on its own port. Different ports are what make the crossover
# assertions below mean something: both machines answer at the same address.
ip netns exec "$CA_NS" nc -l -k -s "$CUST_ADDR" -p "$PORT_A" >/dev/null 2>&1 &
ip netns exec "$CB_NS" nc -l -k -s "$CUST_ADDR" -p "$PORT_B" >/dev/null 2>&1 &
sleep 2

opens() {
  ip netns exec "$TECH_NS" timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

# Given the tunnels take a moment to hand shake, the first reach is retried.
reached_a=0
for _ in $(seq 1 30); do
  if opens "$REACH_A" "$PORT_A"; then reached_a=1; break; fi
  sleep 1
done
if [ "$reached_a" != "1" ]; then
  echo "--- tech status ---" >&2; ./bin/meshp status --socket "$WORK/${TECH_NS}.sock" >&2 || true
  echo "--- tech nft ---" >&2; ip netns exec "$TECH_NS" nft list table inet meshp_map >&2 || true
  echo "--- tech routes ---" >&2; ip netns exec "$TECH_NS" ip route show >&2 || true
  echo "--- customer A log ---" >&2; tail -20 "$WORK/${CA_NS}.log" >&2
  fail "customer A is not reachable at ${REACH_A}:${PORT_A}"
fi
echo "  ${REACH_A}:${PORT_A} reaches customer A"

reached_b=0
for _ in $(seq 1 30); do
  if opens "$REACH_B" "$PORT_B"; then reached_b=1; break; fi
  sleep 1
done
[ "$reached_b" = "1" ] || fail "customer B is not reachable at ${REACH_B}:${PORT_B}"
echo "  ${REACH_B}:${PORT_B} reaches customer B"

# The assertion the whole feature exists for. Both customers answer at 192.168.1.5, so a
# packet that went to the wrong membership would still find a machine there -- just the wrong
# one, on a port it does not serve. These two failing is what proves the prefixes really are
# distinguishable, rather than one of them quietly winning.
if opens "$REACH_A" "$PORT_B"; then
  fail "customer B's port answered at customer A's address: the technician reached the wrong customer"
fi
if opens "$REACH_B" "$PORT_A"; then
  fail "customer A's port answered at customer B's address: the technician reached the wrong customer"
fi
echo "  neither address reaches the other customer"

# And the customer sees the technician's real mesh address, which is what ADR-0007's
# destination-side enforcement runs on. A translation that rewrote the source would hand every
# server in every customer's network one address for the whole MSP.
seen="$(ip netns exec "$CA_NS" ss -Htn state established "sport = :${PORT_A}" 2>/dev/null | awk '{print $NF}' | sed 's/:[0-9]*$//' | head -1)"
if [ -n "$seen" ]; then
  case "$seen" in
    100.92.*) echo "  customer A sees the technician as ${seen}, its real mesh address" ;;
    *) fail "customer A saw the connection from ${seen}, which is not the technician's mesh address" ;;
  esac
fi

echo
echo "two customers on ${CUST_PREFIX} are both reachable from one device, and neither is the other"
