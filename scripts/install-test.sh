#!/usr/bin/env bash
#
# Run install.sh end to end against a release built here.
#
# An install path nobody has executed is the one that fails on the first person who tries
# it, so this builds the same archive the release workflow builds, serves it, installs from
# it, and checks that a tampered archive is refused. It runs in a container because it
# writes to /usr/local/bin and /etc/systemd/system.
set -euo pipefail

VERSION="v0.0.0-test"
# This machine's architecture, not a fixed one: the script under test picks the archive by
# what it finds, so a test that built something else would only ever prove it says no.
ARCH="$(go env GOARCH)"
# Laid out the way a real release is — artifacts under the tag — so the URL the script
# builds is the shape it will build in production.
REL="/tmp/rel/${VERSION}"
STAGE="${REL}/meshp_${VERSION}_linux_${ARCH}"

fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$STAGE"
for cmd in meshp meshpd meshp-control meshp-relay; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "${STAGE}/${cmd}" "./cmd/${cmd}"
done
cp LICENSE NOTICE README.md "$STAGE/"
cp -r deploy/systemd "$STAGE/"
tar -C "$REL" -czf "${STAGE}.tar.gz" "$(basename "$STAGE")"
rm -rf "$STAGE"
(cd "$REL" && sha256sum ./* > SHA256SUMS)

(cd /tmp/rel && python3 -m http.server 871 >/dev/null 2>&1) &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do curl -fsS "http://127.0.0.1:871/${VERSION}/SHA256SUMS" >/dev/null 2>&1 && break; sleep 0.5; done

echo "installing from a locally built release"
MESHP_DOWNLOAD_BASE="http://127.0.0.1:871" MESHP_VERSION="$VERSION" \
  sh scripts/install.sh || fail "the install script failed"

for cmd in meshp meshpd meshp-control meshp-relay; do
  [ -x "/usr/local/bin/${cmd}" ] || fail "${cmd} was not installed"
done
[ -f /etc/systemd/system/meshpd.service ] || fail "the agent's unit was not installed"
/usr/local/bin/meshp --version >/dev/null || fail "the installed binary does not run"
echo "  binaries and unit installed, and the binary runs"

# The security-critical half. An archive that has been tampered with must not be installed,
# and this is the only assertion here that anyone would miss if it silently stopped working.
rm -f /usr/local/bin/meshp
printf 'tampered' >> "${REL}/meshp_${VERSION}_linux_${ARCH}.tar.gz"
if MESHP_DOWNLOAD_BASE="http://127.0.0.1:871" MESHP_VERSION="${VERSION}" sh scripts/install.sh >/dev/null 2>&1; then
  fail "a tampered archive was installed"
fi
[ -x /usr/local/bin/meshp ] && fail "a tampered archive was installed despite the checksum"
echo "  a tampered archive is refused"

echo
echo "the install path works, and refuses what it should"
