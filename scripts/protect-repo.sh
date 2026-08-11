#!/usr/bin/env bash
#
# Apply branch and tag protection to a meshpnet repository, idempotently.
#
#   ./scripts/protect-repo.sh meshp
#   ./scripts/protect-repo.sh meshp-cloud disabled     # create but do not enforce
#
# Requires gh authenticated with admin on the repository.
#
# PRECONDITION, and it is the whole reason this is a script rather than a few
# clicks: branch protection and rulesets are not available on private
# repositories under a GitHub Free organisation. Both APIs answer
#
#   403  Upgrade to GitHub Pro or make this repository public to enable this feature.
#
# So a repository must either be public, or the organisation must be on a paid
# plan. This script detects that and says so rather than half-applying.
#
# WHY THERE ARE NO BYPASS ACTORS
#
# A standing admin bypass would make every rule advisory for the person most able
# to cause damage, including the force-push and deletion rules that exist to
# survive a bad afternoon. The escape hatch is instead to set the ruleset's
# enforcement to "disabled" for as long as it takes:
#
#   ./scripts/protect-repo.sh meshp disabled     # then re-run with no argument
#
# That is one deliberate, logged act rather than a permanent hole.
#
# WHY ZERO REQUIRED APPROVALS
#
# GitHub will not let anyone approve their own pull request. On a single-maintainer
# project, requiring one approval does not raise the bar — it makes main
# unmergeable. Pull requests are still required, so CI runs on the merge result
# and the pull-request-only checks (sign-off, append-only migrations) finally
# execute. Raise this to 1 the day a second maintainer joins.
set -euo pipefail

REPO="${1:?usage: protect-repo.sh <repo-name> [active|disabled]}"
ENFORCEMENT="${2:-active}"
OWNER="${OWNER:-meshpnet}"

# GitHub Actions, so a required check can only be satisfied by the workflow that
# claims to produce it and not by anything else that learns the name.
ACTIONS_APP_ID=15368

# Only the aggregate check is required. Requiring the individual jobs means
# protection silently stops covering a job the day someone renames it, and the
# nightly fuzz jobs also publish check runs — requiring those would block every
# pull request forever, because they only run on a schedule.
REQUIRED_CHECK="ci"

die() { echo "error: $*" >&2; exit 1; }

check_precondition() {
  local body status
  body=$(gh api "repos/$OWNER/$REPO/rulesets" 2>&1) && return 0
  status=$body
  if grep -q 'Upgrade to GitHub' <<<"$status"; then
    cat >&2 <<EOF
error: $OWNER/$REPO cannot be protected as it stands.

  Branch protection and rulesets are unavailable on private repositories under a
  GitHub Free organisation. Either:

    make it public      gh repo edit $OWNER/$REPO --visibility public \\
                          --accept-visibility-change-consequences
    or pay for Team     https://github.com/organizations/$OWNER/settings/billing

  Then run this script again.
EOF
    exit 3
  fi
  die "could not read rulesets for $OWNER/$REPO: $status"
}

# ruleset_id prints the id of a ruleset with the given name, or nothing.
ruleset_id() {
  gh api "repos/$OWNER/$REPO/rulesets" --jq ".[] | select(.name == \"$1\") | .id" 2>/dev/null | head -1
}

# upsert creates or replaces a ruleset from a JSON body on stdin.
upsert() {
  local name="$1" body id
  body=$(cat)
  id=$(ruleset_id "$name")
  if [ -n "$id" ]; then
    printf '  updating ruleset %-14s (id %s) ... ' "$name" "$id"
    gh api -X PUT "repos/$OWNER/$REPO/rulesets/$id" --input - >/dev/null <<<"$body"
  else
    printf '  creating ruleset %-14s ... ' "$name"
    gh api -X POST "repos/$OWNER/$REPO/rulesets" --input - >/dev/null <<<"$body"
  fi
  echo "ok"
}

check_precondition

echo "protecting $OWNER/$REPO (enforcement: $ENFORCEMENT)"

# --- the default branch ----------------------------------------------------
upsert main <<EOF
{
  "name": "main",
  "target": "branch",
  "enforcement": "$ENFORCEMENT",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash", "rebase"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "$REQUIRED_CHECK", "integration_id": $ACTIONS_APP_ID }
        ]
      }
    }
  ]
}
EOF

# --- release tags ----------------------------------------------------------
#
# Tags are load-bearing here, not decorative: the append-only migration policy
# becomes absolute from the first tagged release, so "which migrations shipped in
# v0.1.0" has to remain answerable. A tag that can be moved or deleted cannot
# answer it.
upsert release-tags <<EOF
{
  "name": "release-tags",
  "target": "tag",
  "enforcement": "$ENFORCEMENT",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
EOF

echo
echo "in force on $OWNER/$REPO:"
gh api "repos/$OWNER/$REPO/rulesets" --jq '.[] | "  \(.name) [\(.target)] \(.enforcement)"'
for id in $(gh api "repos/$OWNER/$REPO/rulesets" --jq '.[].id'); do
  gh api "repos/$OWNER/$REPO/rulesets/$id" \
    --jq '"  \(.name): " + ([.rules[].type] | join(", "))'
done
