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
# What it does: works out this machine's platform, downloads that archive and the checksum
# file, refuses to continue if they disagree, installs the binaries, and installs the agent's
# systemd unit without starting it. Joining a network is a separate decision and needs a
# token, so this stops before making it.
#
# What it deliberately does not do: install the control plane or the relay. Those need a
# database, a certificate and an administrator's decisions about who may reach them, and a
# script that guessed at any of it would be configuring a security boundary on somebody's
# behalf. The server-side units ship in the archive, under systemd/.
set -eu

REPO="${MESHP_REPO:-meshpnet/meshp}"
# Overridable so this script can be run end to end against a locally built release rather
# than only in production. An install path nobody has executed is the one that fails on the
# first person who tries it.
DOWNLOAD_BASE="${MESHP_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"
API_BASE="${MESHP_API_BASE:-https://api.github.com/repos/${REPO}}"
VERSION="${MESHP_VERSION:-latest}"
PREFIX="${MESHP_PREFIX:-/usr/local/bin}"

die() { echo "meshp install: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "this needs $1, which is not installed"; }
need curl
need tar
need install

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

# The tag, resolved before anything is downloaded, so the archive and the checksums are
# certain to come from the same release. Asking twice for "latest" could straddle a
# publication and produce a mismatch that looks like tampering.
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "${API_BASE}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || die "could not work out the latest version; set MESHP_VERSION"
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

# Verified before anything is unpacked, which is the point: an archive that has been
# tampered with must not get as far as being extracted, let alone executed.
echo "verifying the checksum"
if command -v sha256sum >/dev/null 2>&1; then
  ( cd "$work" && grep " ./${archive}\$\|  ${archive}\$" SHA256SUMS | sed 's| \./| |' | sha256sum -c - ) \
    || die "the checksum does not match; do not install this"
elif command -v shasum >/dev/null 2>&1; then
  want="$(grep "${archive}\$" "${work}/SHA256SUMS" | awk '{print $1}')"
  got="$(shasum -a 256 "${work}/${archive}" | awk '{print $1}')"
  [ -n "$want" ] && [ "$want" = "$got" ] || die "the checksum does not match; do not install this"
else
  die "this needs sha256sum or shasum to verify the download"
fi

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
