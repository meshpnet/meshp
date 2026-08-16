# Contributing to meshp

Thank you for contributing to meshp.

The core of meshp is licensed under the Apache 2.0 license (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Commercial use is permitted, including running the core as a service or reselling it. See [ADR-0009](docs/adr/0009-licensing-and-commercial-boundary.md) for details on licensing and the commercial boundary.

## Architecture Decisions First

Read [`docs/adr/`](docs/adr/) before proposing substantial changes.

If you disagree with a decision recorded in an Architectural Decision Record (ADR), that disagreement is more valuable to us than a patch. Open an issue or start a discussion first so we can align on design before code is written.

## Local Validation

Before submitting a pull request, run the local continuous integration suite:

```bash
make ci
```

`make ci` executes everything checked by GitHub Actions on a pull request, minus the jobs that require PostgreSQL or Docker. This includes:

- Code formatting checks (`gofmt`)
- Go vetting and linter runs (`golangci-lint`)
- Cross-compilation across supported target platforms
- Dependency hygiene checks
- Unit tests with race detection
- Package coverage floor enforcement
- Seed corpus fuzz testing
- Proprietary import boundary validation (Invariant 12)

Run `make help` to inspect all available make targets.

## Developer Certificate of Origin (DCO)

Every commit must include a sign-off:

```bash
git commit -s
```

Continuous integration enforces the DCO check on every pull request commit.

A sign-off certifies that you have the legal right to submit the work under the project's open source license. It is a certification of provenance, not a copyright assignment. You retain copyright to your contributions.

## Branch Protection and Pull Requests

The `main` branch is protected and subject to the following rules:

- All changes must arrive through pull requests. Direct pushes, force-pushes, and branch deletions on `main` are refused.
- The aggregate `ci` check must pass before merging.
- All review comments and discussion threads must be resolved.
- Git history remains strictly linear. Branches must be rebased on top of `main` before merging.
- Pull requests are merged using rebase or squash merges only.

## Testing and Mutation Testing

Tests are expected to fail when the behaviour they describe is broken.

- Write tests that verify properties and invariants rather than only trivial happy paths.
- Practice mutation testing: intentionally break the implementation logic to confirm that relevant tests fail and turn red.
- Tests that depend on elapsed time must use injected mockable clocks (`clock.Fake`), not real-time sleeps (`time.Sleep`).
- Any new database migration must be added as a new migration file. Merged migrations are immutable and must not be edited.
- Protocol changes in `proto/` may only add fields; never remove or renumber existing fields.
