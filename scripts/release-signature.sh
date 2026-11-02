#!/usr/bin/env bash
#
# The release signature: made by the release workflow, checked by install.sh (ADR-0035).
#
#   release-signature.sh sign <dir>                  sign <dir>/SHA256SUMS with the private key
#                                                    in $MESHP_RELEASE_SIGNING_KEY
#   release-signature.sh verify <dir> [install.sh]   check <dir> the way install.sh will
#   release-signature.sh key [install.sh]            print the public key install.sh carries
#
# The release workflow runs `sign` in the one job that holds the key, and `verify` twice: there,
# and again in the job that publishes, immediately before anything is published. That job can
# publish and cannot sign, and the signing job can sign and cannot publish, so neither a
# compromised step in one nor a stolen token from the other is enough on its own.
#
# install-test.sh runs all three on every pull request that touches the install path, against
# a key it makes up, so none of this is first executed on the day of a release (ADR-0018).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

die() { echo "release-signature: $*" >&2; exit 1; }

# key prints the PEM block install.sh assigns to RELEASE_KEY, or nothing when it has none yet.
key() {
  local script="${1:-$here/install.sh}"
  [ -f "$script" ] || die "$script does not exist"
  sed -n '/^-----BEGIN PUBLIC KEY-----$/,/^-----END PUBLIC KEY-----$/p' "$script"
}

# check runs a checksum file against the files it names, with whichever tool this system has.
check() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c --quiet SHA256SUMS
  else shasum -a 256 -c --quiet SHA256SUMS
  fi
}

sign() {
  local dir="$1"
  # Refused rather than skipped. A release install.sh cannot verify is one it will not install,
  # and publishing it anyway would be the unsigned release this exists to stop.
  [ -n "${MESHP_RELEASE_SIGNING_KEY:-}" ] \
    || die "MESHP_RELEASE_SIGNING_KEY is empty, so nothing is signed and nothing will be published. ADR-0035 says how the key is set up."
  [ -f "$dir/SHA256SUMS" ] || die "$dir/SHA256SUMS does not exist"

  local tmp
  tmp="$(mktemp -d)"
  # On disk only for as long as openssl needs it, and readable by nobody else meanwhile.
  (umask 077 && printf '%s\n' "$MESHP_RELEASE_SIGNING_KEY" > "$tmp/key")
  if ! openssl dgst -sha256 -sign "$tmp/key" -out "$dir/SHA256SUMS.sig" "$dir/SHA256SUMS"; then
    rm -rf "$tmp"
    die "openssl could not sign with MESHP_RELEASE_SIGNING_KEY; it should be a PEM EC P-256 private key"
  fi
  rm -rf "$tmp"
  echo "signed $dir/SHA256SUMS"
}

verify() {
  local dir="$1" script="${2:-$here/install.sh}"
  local pem
  pem="$(key "$script")"
  [ -n "$pem" ] \
    || die "$script carries no release key, so it would refuse this release; publishing it would put up something nobody can install. ADR-0035 says how the key is set up."
  [ -s "$dir/SHA256SUMS.sig" ] || die "$dir/SHA256SUMS.sig is missing"

  local tmp
  tmp="$(mktemp)"
  printf '%s\n' "$pem" > "$tmp"
  # The same openssl invocation install.sh makes, so a signature that passes here is one it
  # accepts.
  if ! openssl dgst -sha256 -verify "$tmp" -signature "$dir/SHA256SUMS.sig" "$dir/SHA256SUMS" >/dev/null; then
    rm -f "$tmp"
    die "SHA256SUMS is not signed by the key $script carries"
  fi
  rm -f "$tmp"

  # Everything published beside the signature is covered by it. A file the checksums do not
  # list would sit on the release page looking as vouched for as the archives, and not be.
  local f name
  for f in "$dir"/*; do
    name="${f##*/}"
    case "$name" in SHA256SUMS|SHA256SUMS.sig) continue ;; esac
    awk -v f="./$name" '$2 == f { found = 1 } END { exit !found }' "$dir/SHA256SUMS" \
      || die "$name is not listed in SHA256SUMS, so the signature does not cover it"
  done
  (cd "$dir" && check) || die "a file in $dir does not match SHA256SUMS"
  echo "verified $dir against the key $script carries"
}

usage="usage: $0 sign <dir> | verify <dir> [install.sh] | key [install.sh]"
case "${1:-}:$#" in
  sign:2) sign "$2" ;;
  verify:2|verify:3) verify "$2" "${3:-}" ;;
  key:1|key:2) key "${2:-}" ;;
  *) die "$usage" ;;
esac
