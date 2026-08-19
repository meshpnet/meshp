# Contributing

Thank you for contributing to meshp. This document covers everything you need
to get a change accepted. The short version: read the ADRs, sign off your
commits, make `make ci` pass, and expect to rebase.

## Before you start

1. **Read [`docs/adr/`](docs/adr/) first.** Design decisions live in
   Architecture Decision Records, and they are enforced by review. If you
   disagree with a decision there, open an issue explaining your reasoning —
   that disagreement is more valuable to us than a patch that works around it.
2. **Check for an existing issue.** Search open issues before filing or
   implementing. Ask in an issue before starting substantial work, so effort
   is not duplicated.
3. **Small, focused changes get merged faster.** One pull request should do
   one thing. A change that fixes two things is two pull requests.

## Local requirements

- Go as pinned in [`.go-version`](.go-version). The build downloads the required
  toolchain automatically; nothing else needs installing for the lint, test,
  and build targets. (`go.mod` names the *language* version, which is older on
  purpose — following it gets you the wrong compiler.)
- GNU Make. `make help` lists every target, and the `##` comments are the
  source of truth.
- PostgreSQL is only needed for the control-plane database targets
  (`make dev`, integration tests); `make ci` deliberately runs without it.

## Pull request checklist

1. **Branch from a current `main`.**
   ```bash
   git checkout main && git pull --rebase
   git checkout -b your-change
   ```
2. **Sign off every commit.** This is checked by CI and merges are blocked
   without it:
   ```bash
   git commit -s  # adds a Signed-off-by: line automatically
   ```
   The sign-off certifies your agreement to the Developer Certificate of
   Origin (https://developercertificate.org) — that you wrote the change or
   have the right to submit it under this project's licence. Automated
   dependency-update pull requests are exempt; humans are not.
3. **Make the CI target pass locally before opening the pull request:**
   ```bash
   make ci
   ```
   This runs the lint, lint-cross, tidy-check, standalone-check, build,
   cross, test, cover-check, cover-check-io, and fuzz-seeds jobs —
   everything CI runs except the jobs needing Postgres. If
   you touched control-plane state or migrations, also run the integration
   target with Postgres running (`make dev` brings it up).
4. **Keep `main` green at merge time.** Branches must be current with `main`
   before merging, so expect to rebase rather than merge. Squash and rebase
   merges only — history stays linear.

## Code expectations

- **Tests are properties, not anecdotes.** The README's "How this is tested"
  section shows the standard: invariants are machine-checked with randomised
  inputs, model-based tests, and fuzzing rather than a handful of golden
  examples. A new invariant needs a test that fails when the invariant breaks.
- **Fail closed.** When something unexpected cannot be decided, the safe
  answer wins over the convenient one (see `docs/adr/` — fail-closed is a
  recurring theme).
- **Do not hand-migrate state.** The control plane's migration runner is
  deliberately minimal; migrations are immutable once merged.
- **Generated code is committed** so the tree builds without codegen
  toolchains; regenerate rather than hand-edit it and include the output in
  your change.

## Reporting security issues

Do not open public issues or pull requests for vulnerabilities. Report them
privately through this repository's GitHub security advisories, as described
in `SECURITY.md`.

## Licence

Contributions are made under the project's licence, Apache 2.0 (see
[`LICENSE`](LICENSE)).
