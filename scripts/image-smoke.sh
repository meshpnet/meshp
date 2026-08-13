#!/usr/bin/env bash
#
# Start the container image against a real PostgreSQL and wait for it to report ready.
#
# Building an image proves the compiler was happy. This proves the thing we would actually
# ship starts, finds its database, applies its own schema and says so — which is the part
# that breaks when an entrypoint, a base image or an embedded migration changes.
#
# Readiness is the assertion rather than liveness on purpose: /healthz answers as soon as
# the process is listening, so a container that can never reach its database still passes a
# liveness check. Readiness is what a load balancer would believe.
#
# Usage: image-smoke.sh
#   MESHP_IMAGE           image to run (default meshp:ci)
#   MESHP_DATABASE_URL    where the container should connect
#   MESHP_IMAGE_NETWORK   docker network (default host)
set -euo pipefail

IMAGE="${MESHP_IMAGE:-meshp:ci}"
DB_URL="${MESHP_DATABASE_URL:?set MESHP_DATABASE_URL}"
PORT="${MESHP_IMAGE_PORT:-8099}"
NAME="meshp-smoke-$$"

# Host networking is what a Linux CI runner wants: the PostgreSQL service publishes its port
# on the runner, and the container reaches it at 127.0.0.1. It is not what a laptop can do —
# Docker Desktop does not share the host namespace — so the network is a parameter, and the
# script is runnable in both places. Two of these scripts have already been fixed today for
# working in exactly one environment.
NETWORK="${MESHP_IMAGE_NETWORK:-host}"

fail() {
  echo "FAIL: $*" >&2
  echo "--- container log ---" >&2
  docker logs "$NAME" 2>&1 | tail -40 >&2 || true
  exit 1
}

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# On host networking the container shares the runner's interfaces, so it binds loopback and
# nothing is published — binding 0.0.0.0 there would expose the control plane on the runner.
# On any other network it has a namespace of its own, so it binds 0.0.0.0 within it and the
# port is published to reach it from here.
if [ "$NETWORK" = "host" ]; then
  net_args=(--network host)
  bind="127.0.0.1:${PORT}"
else
  net_args=(--network "$NETWORK" -p "127.0.0.1:${PORT}:${PORT}")
  bind="0.0.0.0:${PORT}"
fi

echo "starting ${IMAGE} on network ${NETWORK}"
docker run -d --name "$NAME" "${net_args[@]}" \
  -e MESHP_DATABASE_URL="$DB_URL" \
  -e MESHP_LISTEN_ADDR="$bind" \
  -e MESHP_SECRET_KEY="image-smoke-secret-not-a-secret" \
  -e MESHP_LOG_LEVEL="debug" \
  "$IMAGE" >/dev/null

# Liveness first, so a container that never listens at all is reported as that rather than
# as a readiness timeout thirty seconds later.
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    echo "  healthz answers"
    break
  fi
  docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -q true \
    || fail "the container exited before it listened"
  sleep 1
done
curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 \
  || fail "the container never answered /healthz"

# Then readiness, which requires the schema to be current — so this covers the migrations
# embedded in the binary rather than the ones in the repository.
ready=0
for _ in $(seq 1 40); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/readyz" || true)"
  if [ "$code" = "200" ]; then ready=1; break; fi
  docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -q true \
    || fail "the container exited while coming up"
  sleep 1
done
[ "$ready" = "1" ] || fail "the container never became ready (last /readyz was ${code:-no response})"
echo "  readyz answers 200"

# Migrations are embedded, so the copy in the image is documentation. Check it is there all
# the same: an operator reading a container to find out what it applied should find it.
docker run --rm --entrypoint ls "$IMAGE" /usr/share/meshp/migrations >/dev/null \
  || fail "the image carries no copy of the migrations"

# And the other binary in the image runs, since nothing else covers it.
docker run --rm --entrypoint /usr/local/bin/meshp-relay "$IMAGE" --version >/dev/null \
  || fail "meshp-relay does not run in the image"

echo
echo "the image starts, migrates and reports ready"
