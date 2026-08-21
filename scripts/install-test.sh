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

# --- version resolution ------------------------------------------------------------------
#
# The branch that runs when nobody sets MESHP_VERSION: the documented one-liner, and the
# only path most people will ever take. It had no coverage at all, because every case in
# this file passes a version explicitly and so never makes `[ "$VERSION" = "latest" ]` true
# (#112). Publishing v0.1.0 walked straight into it.
#
# Both cases are served from files on disk. SimpleHTTPRequestHandler strips the query string
# before mapping a path, so one file named `releases` answers both requests the script makes
# — the list at `releases?per_page=1`, and a 404 at `releases/latest`, because `releases` is
# a file and not a directory. That is exactly the pair GitHub returns for a repository whose
# only releases are pre-releases.

PRE_TAG="v0.9.0-rc.1"
mkdir -p /tmp/rel/api-pre
printf '[{"tag_name": "%s", "prerelease": true}]' "$PRE_TAG" > /tmp/rel/api-pre/releases

echo "a repository with only a pre-release is not installed from"
# The assignment fails when the script does, which is what is wanted here, so the two are
# joined with && rather than tested afterwards: set -e would otherwise end the run at the
# refusal this is asserting.
out="$(MESHP_DOWNLOAD_BASE="http://127.0.0.1:871" MESHP_API_BASE="http://127.0.0.1:871/api-pre" \
  sh scripts/install.sh 2>&1)" && fail "a pre-release was installed without being asked for"
[ -x /usr/local/bin/meshpd ] || fail "the refusal removed an already-installed binary"
case "$out" in
  *"$PRE_TAG"*) ;;
  # A refusal that will not say what it found leaves the reader with two facts that look
  # contradictory — no latest version, and a release on the releases page — and no way to
  # see that both are true. That was the whole of #111.
  *) fail "the refusal does not name the pre-release: ${out}" ;;
esac
case "$out" in
  *MESHP_VERSION*) ;;
  *) fail "the refusal does not say how to install it deliberately: ${out}" ;;
esac
echo "  refused, and the message names ${PRE_TAG} and MESHP_VERSION"

# And the other half: a repository that does have a stable release. Here `releases/latest`
# is a directory holding an index, which is what turns the 404 above into a served body.
mkdir -p "/tmp/rel/api-stable/releases/latest"
printf '{"tag_name": "%s"}' "$VERSION" > "/tmp/rel/api-stable/releases/latest/index.html"

rm -f /usr/local/bin/meshp
echo "a stable release is resolved and installed with no version given"
MESHP_DOWNLOAD_BASE="http://127.0.0.1:871" MESHP_API_BASE="http://127.0.0.1:871/api-stable" \
  sh scripts/install.sh >/dev/null || fail "the latest version could not be resolved"
# Installing at all is the assertion. The tag has to have been read out of that JSON, since
# it is the only thing naming the directory the archive is downloaded from — a resolution
# that produced anything else would have 404ed rather than arriving here.
[ -x /usr/local/bin/meshp ] || fail "nothing was installed after resolving the latest version"
echo "  resolved ${VERSION} and installed it"

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
echo "the install path works, resolves a version, and refuses what it should"
