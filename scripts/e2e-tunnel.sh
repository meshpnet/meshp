#!/usr/bin/env bash
#
# Run an end-to-end script inside a privileged Linux container, so the assertions that need
# real interfaces actually execute.
#
# `make e2e` on macOS skips them: there is no way to create a WireGuard interface there in
# this build. Skipping is right for a laptop and wrong for a gate, so this exists to make
# the same scripts run where the interfaces are real. CI runs them directly on a Linux
# runner and gets the same coverage without Docker.
#
# Usage: e2e-tunnel.sh [script]   (default: ./scripts/e2e-enrol.sh)
set -euo pipefail

E2E_SCRIPT="${1:-./scripts/e2e-enrol.sh}"
[ -x "$E2E_SCRIPT" ] || { echo "no such executable script: $E2E_SCRIPT" >&2; exit 2; }

NETWORK="meshp-e2e-$$"
PG="meshp-e2e-pg-$$"
GO_IMAGE="${GO_IMAGE:-golang:1.25}"

cleanup() {
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create "$NETWORK" >/dev/null
docker run -d --name "$PG" --network "$NETWORK" \
  -e POSTGRES_USER=meshp -e POSTGRES_PASSWORD=meshp -e POSTGRES_DB=meshp \
  postgres:16-alpine >/dev/null

echo "waiting for postgres"
for _ in $(seq 1 40); do
  if docker exec "$PG" pg_isready -U meshp -d meshp >/dev/null 2>&1; then break; fi
  sleep 1
done

# Debian rather than Alpine: the daemon is built here and run here, and a glibc image
# avoids a cgo/musl mismatch being mistaken for a networking problem.
#
# An anonymous volume over /src/bin so the container builds its own binaries. Without it the
# host's are visible, make considers them current, and Linux tries to run a darwin binary —
# which it reports as "Exec format error" from inside a readiness timeout. It also keeps the
# host's bin/ as it was, so `make e2e` on the host afterwards does not silently run Linux
# binaries that make believes are up to date.
docker run --rm --privileged \
  --network "$NETWORK" \
  -v "$PWD":/src -w /src \
  -v /src/bin \
  -v "$(go env GOMODCACHE)":/go/pkg/mod \
  -e MESHP_TEST_DATABASE_URL="postgres://meshp:meshp@${PG}:5432/meshp?sslmode=disable" \
  -e E2E_SCRIPT="$E2E_SCRIPT" \
  "$GO_IMAGE" bash -c '
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends iproute2 iputils-ping wireguard-tools nftables postgresql-client openssl ca-certificates >/dev/null
make build
"$E2E_SCRIPT" "$MESHP_TEST_DATABASE_URL"
'
