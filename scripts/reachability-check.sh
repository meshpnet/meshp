#!/usr/bin/env bash
#
# Fail on a mechanism nothing reaches.
#
# ADR-0018 says a mechanism is not done until something running reaches it, and it is the
# decision this project cites most often. Until now it was enforced by somebody happening to
# look: dns_zones went unread from the first migration until the DNS work, unapplied_components
# was written on every acknowledgement and selected by nothing until the overview endpoint, and
# PathReport sat in the protocol with both ends independently correct and nothing joining them
# (#121). Each was found by a person reading nearby code for another reason.
#
# Two things are cheap to check mechanically, and this checks those two: a schema table no query
# touches, and a protocol message nothing references.
#
# What it does not catch is worth stating, because one of its own motivating examples escapes it.
# This works at table granularity, and unapplied_components was a *column* on a table that is
# queried constantly — it appeared only in a RETURNING clause on an insert, where it is always
# empty. Telling that from a read needs real SQL parsing rather than grep. Nor can this see a
# message that is sent and handled but whose ends disagree. Both of those are what the
# end-to-end scripts and image-smoke.sh are for; this is the cheap half, and cheap is the point:
# it runs on every pull request rather than when somebody happens to look.
#
# Exceptions live in scripts/reachability-allow, one per line, each with a reason. That file is
# the deliverable: it turns "nobody has looked" into something a reviewer has to read.
set -euo pipefail

ALLOW="${MESHP_REACHABILITY_ALLOW:-scripts/reachability-allow}"
PROTO="${MESHP_PROTO:-proto/meshp/v1/control.proto}"

found=0

# allowed reports whether <kind>:<name> is excused, matching the name exactly rather than as a
# prefix — otherwise an entry for `users` would silently excuse `user_sessions` too.
allowed() {
  grep -qE "^$1[[:space:]]+—" "$ALLOW"
}

echo "tables no query touches"
for table in $(grep -h '^CREATE TABLE' migrations/*.sql \
  | sed 's/CREATE TABLE IF NOT EXISTS //; s/CREATE TABLE //; s/[ (].*//'); do
  # The SQL keywords that actually name a table. Matching the bare word anywhere would count
  # a mention in a comment, which is how three of these looked reachable on first inspection.
  if grep -qEi "(FROM|JOIN|INTO|UPDATE|TABLE)[[:space:]]+\"?${table}\"?([[:space:]]|,|;|\(|$)" queries/*.sql; then
    continue
  fi
  if allowed "table:${table}"; then
    continue
  fi
  echo "  ${table} — in the schema, and no query in queries/ reads or writes it"
  found=1
done

echo "protocol messages nothing references"
# The payload types of the two oneofs, which is what an agent and a server can actually send.
# A message reachable only as a nested field of one of these is covered by its parent.
oneof_types="$(awk '
  /^message (ClientMessage|ServerMessage) \{/ { inmsg = 1 }
  inmsg && /^  oneof payload \{/ { inoneof = 1; next }
  inoneof && /^  \}/ { inoneof = 0; inmsg = 0 }
  inoneof && NF { print $1 }
' "$PROTO" | sort -u)"

for message in $oneof_types; do
  # Outside the generated code, and outside tests. A message only a test constructs is not one
  # anything running reaches, which is the whole distinction being drawn — and every real case
  # found so far had neither.
  hits="$(grep -rl "\b${message}\b" internal/ cmd/ --include='*.go' 2>/dev/null \
    | grep -v '/gen/' | grep -vc '_test\.go$' || true)"
  if [ "${hits:-0}" -gt 0 ]; then
    continue
  fi
  if allowed "message:${message}"; then
    continue
  fi
  echo "  ${message} — named in a oneof, and no Go outside proto/gen references it"
  found=1
done

if [ "$found" -ne 0 ]; then
  cat >&2 <<'MSG'

Something is defined and nothing reaches it (ADR-0018).

Either wire it up, or add it to scripts/reachability-allow with a reason somebody
reading this in six months can act on. "Not yet" is a fine reason; it is not a fine
absence.
MSG
  exit 1
fi

echo
echo "everything defined is reached, or excused in ${ALLOW}"
