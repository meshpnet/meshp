#!/usr/bin/env bash
#
# Run install.sh end to end against a release built here.
#
# An install path nobody has executed is the one that fails on the first person who tries
# it, so this builds the same archive the release workflow builds, signs it with a key made up
# for the purpose, serves it, installs from it, and then damages it every way that matters and
# requires each to be refused: the archive, the checksums, the signature, and a machine with
# no openssl. It runs in a container on Linux (make install-check) and on a macOS runner in CI,
# because it writes to /usr/local/bin and /etc/systemd/system.
#
# It also downloads one real release from GitHub — v0.2.2, the newest one published before
# releases were signed — and installs it with install.sh exactly as it is in this tree. That is
# the one network dependency here, and it is deliberate: "this does not break installing the
# release people are installing today" is a claim about a file on GitHub, so it is checked
# against that file and not against a copy of it.
set -euo pipefail

VERSION="v0.0.0-test"
# This machine's platform, not a fixed one: the script under test picks the archive by what
# it finds, so a test that built something else would only ever prove it says no.
OS="$(go env GOOS)"
ARCH="$(go env GOARCH)"
# Laid out the way a real release is — artifacts under the tag — so the URL the script
# builds is the shape it will build in production.
ROOT="/tmp/rel"
REL="${ROOT}/${VERSION}"
NAME="meshp_${VERSION}_${OS}_${ARCH}"
ARCHIVE="${REL}/${NAME}.tar.gz"
SERVER="http://127.0.0.1:871"
BIN="/usr/local/bin"

fail() { echo "FAIL: $*" >&2; exit 1; }

# The release workflow runs on Linux and writes its checksums with sha256sum; a Mac has shasum,
# which writes the same format. sums takes its files as arguments so the glob is expanded by the
# caller, before the redirection creates SHA256SUMS: inside the function it would be expanded
# after, and list the half-written checksum file as one of the things it checksums.
if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$1" | awk '{print $1}'; }
  sums() { sha256sum "$@"; }
else
  digest() { shasum -a 256 "$1" | awk '{print $1}'; }
  sums() { shasum -a 256 "$@"; }
fi

echo "openssl here is: $(openssl version)"

KEYS="$(mktemp -d)"
server=""
trap '[ -z "$server" ] || kill "$server" 2>/dev/null || true; rm -rf "$KEYS"' EXIT

# --- a release, built and signed here ----------------------------------------------------

binaries="meshp meshpd"
if [ "$OS" = "linux" ]; then binaries="meshp meshpd meshp-control meshp-relay"; fi

rm -rf "$ROOT"
mkdir -p "${REL}/${NAME}"
for cmd in $binaries; do
  CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -o "${REL}/${NAME}/${cmd}" "./cmd/${cmd}"
done
cp LICENSE NOTICE README.md "${REL}/${NAME}/"
if [ "$OS" = "linux" ]; then cp -r deploy/systemd "${REL}/${NAME}/"; fi
tar -C "$REL" -czf "$ARCHIVE" "$NAME"
rm -rf "${REL:?}/${NAME}"
(cd "$REL" && sums ./* > SHA256SUMS)

# Made here and thrown away with the job. The release key is never anywhere near a test, and a
# test that needed it would be a reason for it to be somewhere it should not.
openssl ecparam -name prime256v1 -genkey -noout -out "${KEYS}/release.key"
openssl ec -in "${KEYS}/release.key" -pubout -out "${KEYS}/release.pub" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "${KEYS}/other.key"

echo "nothing is signed without a key"
if MESHP_RELEASE_SIGNING_KEY="" scripts/release-signature.sh sign "$REL" 2>/dev/null; then
  fail "release-signature.sh signed with no key"
fi
if [ -e "${REL}/SHA256SUMS.sig" ]; then fail "a signature was written without a key"; fi
echo "  refused, and no signature written"

MESHP_RELEASE_SIGNING_KEY="$(cat "${KEYS}/release.key")" \
  scripts/release-signature.sh sign "$REL" >/dev/null

# --- the script under test -----------------------------------------------------------------
#
# install.sh trusts one key, written into it, and there is deliberately no way to hand it
# another. So what is tested with the made-up key is a copy with that one assignment changed —
# and a test of a copy is worth only as much as the copy's resemblance, so that is asserted
# rather than assumed: with the key taken out of both, the two are byte for byte the same.

# rekey <pem file, or nothing> rewrites install.sh's RELEASE_KEY to hold that key, or none.
rekey() {
  awk -v keyfile="$1" '
    BEGIN {
      q = sprintf("%c", 39)
      if (keyfile != "") while ((getline line < keyfile) > 0) key = key line "\n"
    }
    skipping { if ($0 == q) skipping = 0; next }
    index($0, "RELEASE_KEY=" q) == 1 {
      if ($0 != "RELEASE_KEY=" q q) skipping = 1
      if (key == "") print "RELEASE_KEY=" q q
      else { print "RELEASE_KEY=" q; printf "%s", key; print q }
      next
    }
    { print }
  '
}

UNDER_TEST="${KEYS}/install.sh"
KEYLESS="${KEYS}/install-keyless.sh"
rekey "${KEYS}/release.pub" < scripts/install.sh > "$UNDER_TEST"
rekey "" < scripts/install.sh > "$KEYLESS"

rekey "" < "$UNDER_TEST" | cmp -s - "$KEYLESS" \
  || fail "the copy under test differs from install.sh in more than its key"
[ "$(scripts/release-signature.sh key "$UNDER_TEST")" = "$(cat "${KEYS}/release.pub")" ] \
  || fail "the copy under test does not carry the test key"
# And the substitution is not a no-op, which would make every case below test the real key.
if cmp -s "$UNDER_TEST" scripts/install.sh; then fail "rekey changed nothing"; fi

# The key in install.sh is the one SECURITY.md tells people to check by hand. Two places
# publishing different keys would leave somebody verifying a release with one and installing
# with the other — and a change to the key that touches only one of them is the change a
# reviewer most needs to see.
echo "install.sh and SECURITY.md publish the same release key"
embedded="$(scripts/release-signature.sh key)"
published="$(sed -n '/^-----BEGIN PUBLIC KEY-----$/,/^-----END PUBLIC KEY-----$/p' SECURITY.md)"
[ "$embedded" = "$published" ] || fail "install.sh and SECURITY.md carry different release keys"
if [ -n "$embedded" ]; then
  printf '%s\n' "$embedded" > "${KEYS}/published.pem"
  openssl pkey -pubin -in "${KEYS}/published.pem" -noout -text | grep -q prime256v1 \
    || fail "the release key is not an EC P-256 key, which is what install.sh's openssl call assumes"
  openssl pkey -pubin -in "${KEYS}/published.pem" -outform DER -out "${KEYS}/published.der"
  fingerprint="$(digest "${KEYS}/published.der")"
  grep -q "$fingerprint" SECURITY.md \
    || fail "SECURITY.md does not give the release key's fingerprint, ${fingerprint}"
  echo "  the same P-256 key, fingerprint ${fingerprint}"
else
  echo "  neither carries one yet, so only the releases that predate signing can be installed"
fi

echo "the release verifies the way the release workflow checks it before publishing"
scripts/release-signature.sh verify "$REL" "$UNDER_TEST" >/dev/null \
  || fail "release-signature.sh does not accept a release it signed"
if scripts/release-signature.sh verify "$REL" "$KEYLESS" 2>/dev/null; then
  fail "release-signature.sh would publish a release install.sh carries no key for"
fi
echo "not from meshp" > "${REL}/unlisted"
if scripts/release-signature.sh verify "$REL" "$UNDER_TEST" 2>/dev/null; then
  fail "release-signature.sh would publish a file the signature does not cover"
fi
rm -f "${REL}/unlisted"
echo "  accepted; and refused with no key, and with a file the checksums do not list"

# Kept so each case below can damage the release and the next one start from what was built.
cp -R "$REL" "${KEYS}/pristine"
pristine() { rm -rf "$REL"; cp -R "${KEYS}/pristine" "$REL"; }

(cd "$ROOT" && exec python3 -m http.server 871 >/dev/null 2>&1) &
server=$!
# Stopped by the trap on the way out, which bash on a Mac would otherwise report as though it
# were something going wrong.
disown "$server"
for _ in $(seq 1 20); do curl -fsS "${SERVER}/${VERSION}/SHA256SUMS" >/dev/null 2>&1 && break; sleep 0.5; done

# attempt <script> [VAR=value...] runs an install, keeping what it said in $out.
attempt() {
  local script="$1"
  shift
  out="$(env MESHP_DOWNLOAD_BASE="$SERVER" "$@" sh "$script" 2>&1)"
}

# refused <what> <script> [VAR=value...] requires the install to fail and to install nothing.
refused() {
  local what="$1"
  shift
  rm -f "${BIN}/meshp"
  if attempt "$@"; then fail "${what} was installed: ${out}"; fi
  if [ -e "${BIN}/meshp" ]; then fail "${what} was refused, but only after installing"; fi
}

# says <text> requires the last install to have said it, because a refusal for the wrong
# reason passes every check above and proves nothing about the one it was meant to test.
says() {
  case "$out" in
    *"$1"*) ;;
    *) fail "expected to be told '$1', and was told: ${out}" ;;
  esac
}

echo "installing from a locally built, signed release"
attempt "$UNDER_TEST" MESHP_VERSION="$VERSION" || fail "the install script failed: ${out}"
says "verifying the signature"
for cmd in $binaries; do
  [ -x "${BIN}/${cmd}" ] || fail "${cmd} was not installed"
done
if [ "$OS" = "linux" ]; then
  [ -f /etc/systemd/system/meshpd.service ] || fail "the agent's unit was not installed"
fi
"${BIN}/meshp" --version >/dev/null || fail "the installed binary does not run"
echo "  signature checked, binaries installed, and the binary runs"

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
mkdir -p "${ROOT}/api-pre"
printf '[{"tag_name": "%s", "prerelease": true}]' "$PRE_TAG" > "${ROOT}/api-pre/releases"

echo "a repository with only a pre-release is not installed from"
# The script as it is in this tree: this path is decided before any key is consulted.
if attempt scripts/install.sh MESHP_API_BASE="${SERVER}/api-pre"; then
  fail "a pre-release was installed without being asked for"
fi
[ -x "${BIN}/meshpd" ] || fail "the refusal removed an already-installed binary"
# A refusal that will not say what it found leaves the reader with two facts that look
# contradictory — no latest version, and a release on the releases page — and no way to
# see that both are true. That was the whole of #111.
says "$PRE_TAG"
says "MESHP_VERSION"
echo "  refused, and the message names ${PRE_TAG} and MESHP_VERSION"

# And the other half: a repository that does have a stable release. Here `releases/latest`
# is a directory holding an index, which is what turns the 404 above into a served body.
mkdir -p "${ROOT}/api-stable/releases/latest"
printf '{"tag_name": "%s"}' "$VERSION" > "${ROOT}/api-stable/releases/latest/index.html"

rm -f "${BIN}/meshp"
echo "a stable release is resolved and installed with no version given"
attempt "$UNDER_TEST" MESHP_API_BASE="${SERVER}/api-stable" \
  || fail "the latest version could not be resolved: ${out}"
# Installing at all is the assertion. The tag has to have been read out of that JSON, since
# it is the only thing naming the directory the archive is downloaded from — a resolution
# that produced anything else would have 404ed rather than arriving here.
[ -x "${BIN}/meshp" ] || fail "nothing was installed after resolving the latest version"
echo "  resolved ${VERSION} and installed it"

# --- what must be refused ------------------------------------------------------------------
#
# The security-critical half, and the only assertions here that anyone would miss if they
# silently stopped working. Every case damages the release in one way, requires a refusal for
# the reason that damage should cause, and puts the release back.

echo "a tampered archive is refused"
printf 'tampered' >> "$ARCHIVE"
refused "a tampered archive" "$UNDER_TEST" MESHP_VERSION="$VERSION"
says "checksum does not match"
echo "  refused on its checksum"

echo "skipping the signature still checks the checksum"
refused "a tampered archive, with the signature skipped" "$UNDER_TEST" \
  MESHP_VERSION="$VERSION" MESHP_INSECURE_SKIP_SIGNATURE=1
says "checksum does not match"
echo "  refused on its checksum"
pristine

# The attack the checksums alone cannot see, and the reason any of this exists: whoever can
# replace the archive can replace the checksum file beside it. Both are consistent with each
# other and only the signature says otherwise.
replace_archive() {
  local tmp
  tmp="$(mktemp -d)"
  tar -C "$tmp" -xzf "$ARCHIVE"
  echo "not from meshp" > "${tmp}/${NAME}/planted"
  tar -C "$tmp" -czf "$ARCHIVE" "$NAME"
  rm -rf "$tmp"
  printf '%s  ./%s\n' "$(digest "$ARCHIVE")" "${NAME}.tar.gz" > "${REL}/SHA256SUMS"
}

echo "a replaced archive, with checksums rewritten to match, is refused"
replace_archive
refused "a replaced archive with matching checksums" "$UNDER_TEST" MESHP_VERSION="$VERSION"
says "not signed by the meshp release key"
# And by the check the release workflow makes before publishing, which is the same openssl
# call and would otherwise only ever be shown to accept things.
if scripts/release-signature.sh verify "$REL" "$UNDER_TEST" 2>/dev/null; then
  fail "release-signature.sh would publish a replaced archive"
fi
echo "  refused on its signature, by install.sh and by the release workflow's check"

# The same release, and the flag that says not to check. It installs — which is the point
# being made, not a weakness of the test: with the signature skipped this is exactly as
# protected as every release was before signing, and the warning has to say so.
echo "it installs only when the signature is deliberately not checked, and says so"
rm -f "${BIN}/meshp"
attempt "$UNDER_TEST" MESHP_VERSION="$VERSION" MESHP_INSECURE_SKIP_SIGNATURE=1 \
  || fail "MESHP_INSECURE_SKIP_SIGNATURE=1 did not skip the signature: ${out}"
[ -x "${BIN}/meshp" ] || fail "MESHP_INSECURE_SKIP_SIGNATURE=1 installed nothing"
says "WARNING: MESHP_INSECURE_SKIP_SIGNATURE=1"
says "WITHOUT checking its signature"
echo "  installed, with the warning before and after"

echo "checksums signed by some other key are refused"
openssl dgst -sha256 -sign "${KEYS}/other.key" -out "${REL}/SHA256SUMS.sig" "${REL}/SHA256SUMS"
refused "checksums signed by another key" "$UNDER_TEST" MESHP_VERSION="$VERSION"
says "not signed by the meshp release key"
echo "  refused on its signature"
pristine

echo "a tampered signature is refused"
sig="${REL}/SHA256SUMS.sig"
{ head -c 20 "${KEYS}/pristine/SHA256SUMS.sig"; printf 'X'; tail -c +22 "${KEYS}/pristine/SHA256SUMS.sig"; } > "$sig"
if cmp -s "$sig" "${KEYS}/pristine/SHA256SUMS.sig"; then
  { head -c 20 "${KEYS}/pristine/SHA256SUMS.sig"; printf 'Y'; tail -c +22 "${KEYS}/pristine/SHA256SUMS.sig"; } > "$sig"
fi
refused "a tampered signature" "$UNDER_TEST" MESHP_VERSION="$VERSION"
says "not signed by the meshp release key"
echo "  refused"
pristine

echo "a release with no signature is refused"
rm -f "${REL}/SHA256SUMS.sig"
refused "a release with no signature" "$UNDER_TEST" MESHP_VERSION="$VERSION"
says "SHA256SUMS.sig"
echo "  refused, rather than installed on its checksum alone"
pristine

# A bare server without openssl. The requirement is that a missing tool is a refusal that
# names the way out, never a quiet downgrade to checking less. PATH is built from everything
# this machine has except openssl, rather than from a list of what install.sh uses today,
# so a tool it starts needing tomorrow does not make this case fail for the wrong reason.
echo "a machine with no openssl refuses, and does not skip the check"
bare="${KEYS}/bin-without-openssl"
mkdir -p "$bare"
for d in /usr/bin /bin /usr/sbin /sbin; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    n="${f##*/}"
    case "$n" in openssl*) continue ;; esac
    [ -e "${bare}/${n}" ] || ln -s "$f" "${bare}/${n}"
  done
done
refused "a release, on a machine with no openssl," "$UNDER_TEST" PATH="$bare" MESHP_VERSION="$VERSION"
says "needs openssl"
says "MESHP_INSECURE_SKIP_SIGNATURE=1"
echo "  refused, naming openssl and the flag"

echo "the flag that skips the check takes 1 and nothing else"
refused "a release with MESHP_INSECURE_SKIP_SIGNATURE=yes" "$UNDER_TEST" \
  MESHP_VERSION="$VERSION" MESHP_INSECURE_SKIP_SIGNATURE=yes
says "either 1 or unset"
echo "  refused"

# The state install.sh is in from the day this is merged until the maintainer adds the key.
echo "a copy of install.sh with no key refuses a release that is not pinned"
refused "a release, by a script with no key," "$KEYLESS" MESHP_VERSION="$VERSION"
says "carries no release key"
echo "  refused"

# --- the releases from before signing -------------------------------------------------------
#
# v0.1.0 to v0.2.2 are not signed and never will be. install.sh pins each by the digest of its
# checksum file, so they install as they always have and cannot be replaced. Run with the script
# exactly as it is in this tree, against the files exactly as GitHub serves them.

LEGACY="v0.2.2"
mkdir -p "${ROOT}/${LEGACY}"
for f in SHA256SUMS "meshp_${LEGACY}_${OS}_${ARCH}.tar.gz"; do
  curl -fsSL "https://github.com/meshpnet/meshp/releases/download/${LEGACY}/${f}" -o "${ROOT}/${LEGACY}/${f}" \
    || fail "could not download ${f} from the ${LEGACY} release"
done
cp "${ROOT}/${LEGACY}/SHA256SUMS" "${KEYS}/legacy-sums"

echo "the release people install today still installs, with install.sh as it is"
rm -f "${BIN}/meshp"
attempt scripts/install.sh MESHP_VERSION="$LEGACY" || fail "${LEGACY} no longer installs: ${out}"
says "pinned for ${LEGACY}"
[ -x "${BIN}/meshp" ] || fail "${LEGACY} installed nothing"
echo "  ${LEGACY} installed against its pinned checksums"

echo "its checksums, changed, are refused"
printf '0000000000000000000000000000000000000000000000000000000000000000  ./planted\n' \
  >> "${ROOT}/${LEGACY}/SHA256SUMS"
refused "${LEGACY} with changed checksums" scripts/install.sh MESHP_VERSION="$LEGACY"
says "not the ones that were published"
cp "${KEYS}/legacy-sums" "${ROOT}/${LEGACY}/SHA256SUMS"
echo "  refused"

# Nothing legitimate makes an unsigned release the latest one: they are all pre-releases, which
# GitHub leaves out of that answer. So the default path does not take one even when told to.
mkdir -p "${ROOT}/api-legacy/releases/latest"
printf '{"tag_name": "%s"}' "$LEGACY" > "${ROOT}/api-legacy/releases/latest/index.html"
echo "an unsigned release offered as the latest is not installed unless named"
refused "${LEGACY}, offered as latest," scripts/install.sh MESHP_API_BASE="${SERVER}/api-legacy"
says "predates signed releases"
says "MESHP_VERSION=${LEGACY}"
echo "  refused, and the message says how to ask for it"

echo
echo "the install path works, resolves a version, and refuses what it should"
