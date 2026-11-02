#!/usr/bin/env bash
#
# Install meshp from a published release.
#
#   curl -fsSL https://raw.githubusercontent.com/meshpnet/meshp/main/scripts/install.sh | sudo sh
#
# Or, having read it first, which is the better habit and the reason this stays short enough
# to read:
#
#   curl -fsSLO https://raw.githubusercontent.com/meshpnet/meshp/main/scripts/install.sh
#   less install.sh && sudo sh install.sh
#
# What it does: works out this machine's platform, downloads that archive, the checksum file
# and the checksum file's signature, refuses to continue unless the signature is the meshp
# release key's and the archive matches the checksum, installs the binaries, and installs the
# agent's systemd unit without starting it. Joining a network is a separate decision and needs
# a token, so this stops before making it.
#
# What it deliberately does not do: install the control plane or the relay. Those need a
# database, a certificate and an administrator's decisions about who may reach them, and a
# script that guessed at any of it would be configuring a security boundary on somebody's
# behalf. The server-side units ship in the archive, under systemd/.
#
# What the signature proves, and what it cannot while this script and the key it trusts come
# from the same place, is ADR-0035. SECURITY.md says how to check a release by hand.
set -eu

REPO="${MESHP_REPO:-meshpnet/meshp}"
# Overridable so this script can be run end to end against a locally built release rather
# than only in production. An install path nobody has executed is the one that fails on the
# first person who tries it.
DOWNLOAD_BASE="${MESHP_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"
API_BASE="${MESHP_API_BASE:-https://api.github.com/repos/${REPO}}"
VERSION="${MESHP_VERSION:-latest}"
PREFIX="${MESHP_PREFIX:-/usr/local/bin}"

# The meshp release key. The release workflow signs every release's SHA256SUMS with its private
# half, and will not publish a release this key does not verify.
#
# A constant and not a setting, unlike everything above. A trusted key that could be replaced
# from the environment would be a way to skip verification that does not say it is one, and
# the way to skip it, further down, is required to say so. SECURITY.md publishes its
# fingerprint and so does meshp.net, which is not served from GitHub: comparing the two is the
# one check that does not depend on trusting wherever this copy came from.
#
# Empty until the maintainer creates the key (ADR-0035). While it is empty this script installs
# only the releases listed below, which are every release there is.
RELEASE_KEY=''

# The releases published before releases were signed, each pinned by the SHA-256 of its
# SHA256SUMS exactly as GitHub serves it. Every digest here was read from the release and
# matches the one GitHub recorded when the release workflow uploaded the file.
#
# A closed list rather than a version below which a signature is optional. A floor accepts any
# unsigned release beneath it, including one published tomorrow by whoever had taken over the
# account, and an old copy of a release replaced in place. These four are all there will ever
# be, so the list can only shrink.
UNSIGNED_RELEASES="
v0.1.0 ff429bcbb41e801d1db3be1652e931d856e3d39b3853756c403fc7b669ff8fbe
v0.2.0 5a0013ebf192a8505f239180c4433067255974b58c9c350010c228f87bf3808b
v0.2.1 638c91de1aaa4ebfdce36aea1be576e44cda16f54833eaf935f41ceea455cf34
v0.2.2 c6ff31ef9fa3b30520e4f5f58656416430953a207add663c9d6d7234c8e288f4
"

die() { echo "meshp install: $*" >&2; exit 1; }
warn() { echo "meshp install: $*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || die "this needs $1, which is not installed"; }
need curl
need tar
need install

# Not checking the signature is possible, and it has to be asked for in words that say what it
# gives up. It is never what happens because a tool is missing: that is a refusal, which names
# this variable, and so does nothing else.
case "${MESHP_INSECURE_SKIP_SIGNATURE:-}" in
  ""|0) skip_signature="" ;;
  1) skip_signature=1 ;;
  *) die "MESHP_INSECURE_SKIP_SIGNATURE is either 1 or unset, not '${MESHP_INSECURE_SKIP_SIGNATURE}'" ;;
esac

# Whichever of the two this system has. One function rather than two code paths, so the check
# that matters is written once.
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "this needs sha256sum or shasum to verify the download"
fi

[ "$(id -u)" = "0" ] || die "run this with sudo: it writes to ${PREFIX} and /etc/systemd/system"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin) ;;
  *) die "no published build for ${os}; Windows and mobile ship as signed packages" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) die "no published build for $(uname -m)" ;;
esac

# Whether somebody asked for this version by name, which an unsigned release requires.
named=""
[ "$VERSION" = "latest" ] || named=1

# The tag, resolved before anything is downloaded, so the archive and the checksums are
# certain to come from the same release. Asking twice for "latest" could straddle a
# publication and produce a mismatch that looks like tampering.
if [ "$VERSION" = "latest" ]; then
  # GitHub excludes pre-releases from this endpoint, so a repository whose only releases
  # are pre-releases answers 404 here. That is the honest answer to "what is the latest
  # stable version" and it must not be turned into an install: somebody piping this to sh
  # is asking for the version offered as ready, and there is not one yet.
  #
  # -f makes the 404 a failure rather than a body, which is what separates it from a
  # release whose JSON could not be parsed.
  if latest="$(curl -fsSL "${API_BASE}/releases/latest" 2>/dev/null)"; then
    VERSION="$(printf '%s' "$latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$VERSION" ] || die "could not read a version out of the latest release; set MESHP_VERSION"
  else
    # Naming the pre-release rather than only refusing. "Could not work out the latest
    # version" while a release sits on the releases page is a dead end, and the reader has
    # no way to know the two facts are compatible.
    pre="$(curl -fsSL "${API_BASE}/releases?per_page=1" 2>/dev/null \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$pre" ] || die "could not work out the latest version; set MESHP_VERSION"
    die "there is no stable release yet: the newest is the pre-release ${pre}.
  Install it deliberately, having read what it is not ready for:
    MESHP_VERSION=${pre} sh install.sh"
  fi
fi

# How this release will be shown to be meshp's, decided before anything is downloaded, so a
# machine that cannot check it says so before fetching fifteen megabytes it would refuse.
pinned="$(printf '%s\n' "$UNSIGNED_RELEASES" | awk -v v="$VERSION" '$1 == v {print $2}')"
if [ -n "$pinned" ]; then
  # Only by name. None of these is a stable release, so nothing legitimate resolves "latest"
  # to one; if something does, the releases page has been changed to offer an old version as
  # the current one, and the default path is not where that should be quietly accepted.
  [ -n "$named" ] || die "the latest release is said to be ${VERSION}, which predates signed releases and was never offered as stable.
  If that is really the version wanted, name it:
    MESHP_VERSION=${VERSION} sh install.sh"
  provenance="pinned"
elif [ -n "$skip_signature" ]; then
  provenance="skipped"
else
  provenance="signed"
  case "$RELEASE_KEY" in
    *"BEGIN PUBLIC KEY"*) ;;
    *) die "this copy of install.sh carries no release key, so it cannot check ${VERSION} and will not
  install it. It predates the first signed release; fetch install.sh again." ;;
  esac
  # `openssl version` rather than `command -v openssl`, so an openssl that is present and does
  # not run is found here and not reported later as a bad signature.
  openssl version >/dev/null 2>&1 || die "checking who published ${VERSION} needs openssl, which is not installed.
  Install it (apt-get install openssl, dnf install openssl, apk add openssl) and run this again.
  To install without checking, knowing that the checksums then prove only that the download
  arrived intact and not who made it:
    MESHP_INSECURE_SKIP_SIGNATURE=1 sh install.sh"
fi

archive="meshp_${VERSION}_${os}_${arch}.tar.gz"
base="${DOWNLOAD_BASE}/${VERSION}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "downloading ${archive} (${VERSION})"
curl -fsSL "${base}/${archive}" -o "${work}/${archive}" \
  || die "could not download ${archive}; check that ${VERSION} has a build for ${os}/${arch}"
curl -fsSL "${base}/SHA256SUMS" -o "${work}/SHA256SUMS" \
  || die "could not download the checksums"
if [ "$provenance" = "signed" ]; then
  # A release without a signature is refused rather than installed on its checksum alone.
  # Accepting one would let anybody able to publish a release strip the signature and be
  # believed, which is the whole of what the signature is for.
  curl -fsSL "${base}/SHA256SUMS.sig" -o "${work}/SHA256SUMS.sig" \
    || die "could not download SHA256SUMS.sig. Every release after v0.2.2 is signed, so ${VERSION}
  without a signature is not one to install"
fi

# The checksum file first, because everything after this trusts it. Then the archive against
# it. Both before anything is unpacked, which is the point: an archive that has been tampered
# with must not get as far as being extracted, let alone executed.
case "$provenance" in
  signed)
    echo "verifying the signature"
    printf '%s\n' "$RELEASE_KEY" > "${work}/release-key.pem"
    openssl dgst -sha256 -verify "${work}/release-key.pem" \
      -signature "${work}/SHA256SUMS.sig" "${work}/SHA256SUMS" >/dev/null 2>&1 \
      || die "the checksums are not signed by the meshp release key; do not install this"
    ;;
  pinned)
    echo "verifying the checksums against the copy pinned for ${VERSION}, which predates signing"
    [ "$(sha256 "${work}/SHA256SUMS")" = "$pinned" ] \
      || die "the checksums for ${VERSION} are not the ones that were published; do not install this"
    ;;
  skipped)
    warn "WARNING: MESHP_INSECURE_SKIP_SIGNATURE=1, so nothing checks who published ${VERSION}."
    warn "  The archive is still checked against SHA256SUMS. That proves it arrived intact, and"
    warn "  nothing more: both files come from the same place, and whoever can replace one can"
    warn "  replace the other."
    ;;
esac

echo "verifying the checksum"
# Matched on the whole name rather than by a pattern, so one line cannot stand in for another.
want="$(awk -v f="$archive" '$2 == f || $2 == "./" f {print $1}' "${work}/SHA256SUMS")"
case "$want" in
  ""|*[!0-9a-f]*) die "the checksums do not list ${archive} exactly once; do not install this" ;;
esac
[ "$(sha256 "${work}/${archive}")" = "$want" ] || die "the checksum does not match; do not install this"

tar -C "$work" -xzf "${work}/${archive}"
dir="${work}/meshp_${VERSION}_${os}_${arch}"
[ -d "$dir" ] || die "the archive did not contain what was expected"

echo "installing to ${PREFIX}"
for cmd in meshp meshpd meshp-control meshp-relay; do
  [ -f "${dir}/${cmd}" ] || continue
  install -m 0755 "${dir}/${cmd}" "${PREFIX}/${cmd}"
done

if [ "$os" = "linux" ] && [ -d /etc/systemd/system ] && [ -f "${dir}/systemd/meshpd.service" ]; then
  install -m 0644 "${dir}/systemd/meshpd.service" /etc/systemd/system/meshpd.service
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
  echo
  echo "installed. The agent is not running yet:"
  echo
  echo "    sudo systemctl enable --now meshpd"
  echo "    sudo meshp join <token>"
  echo
  echo "Nothing joins a network without a token, so this stops here rather than"
  echo "starting a daemon with nothing to do."
else
  echo
  echo "installed ${PREFIX}/meshp and ${PREFIX}/meshpd."
  echo "Start meshpd however this system starts services, then run 'meshp join <token>'."
fi

if [ "$provenance" = "skipped" ]; then
  echo
  warn "installed ${VERSION} WITHOUT checking its signature (MESHP_INSECURE_SKIP_SIGNATURE=1)."
fi
