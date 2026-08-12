# ADR-0013: Generated code is committed

- **Status:** accepted
- **Date:** 2026-08-10

## Context

Protobuf bindings and database access code are generated, from
`proto/meshp/v1/*.proto` and from `migrations/` plus `queries/`. Either they are
committed or they are produced by a build step.

Leaving them out looked tidier and broke immediately in practice. Generated
protobuf code imports `google.golang.org/protobuf`, so with `proto/gen/`
ignored, the dependency was absent from `go.mod` — everything built on a fresh
clone precisely because nothing referenced the generated package, and the moment
a developer ran `make proto`, `go build ./...` and `govulncheck` both failed on
code the repository could not see.

The deeper problem is that Go's tooling assumes buildable source in the tree.
`go install github.com/meshpnet/meshp/cmd/meshp@latest` runs no Makefile. Neither
does a downstream module importing our protocol package — and `meshp-sdk`, the
mobile clients and eventually third parties are all expected to.

## Decision

Generated code is committed:

- `proto/gen/` — protobuf bindings
- `internal/store/gen/` — sqlc output

The generators remain the source of truth. CI regenerates and fails if the result
differs from what is committed, so the tree cannot drift from the `.proto` and
`.sql` files it came from.

**Every generator must be pinned, including the plugins a generator invokes.** The
check is only meaningful if regeneration is deterministic, and the first version of
this setup was not: `buf` itself was pinned in the Makefile while `buf.gen.yaml`
named `remote: buf.build/protocolbuffers/go` with no version. Bindings were
committed by protoc-gen-go v1.36.11 and CI regenerated them with v1.36.12 hours
later, so a pull request that touched no `.proto` at all failed on a one-line
version comment. A gate that fails for reasons unrelated to the change is a gate
people learn to ignore.

`protoc-gen-go` is therefore invoked locally through `go tool`, so its version is
whatever `go.mod` pins — one number, visible to Dependabot, and necessarily the
same version as the protobuf runtime the generated code is compiled against.

## Consequences

`go build`, `go test`, `go install` and `govulncheck` all work on a fresh clone
with no generate step. Downstream modules can import our protocol package. New
contributors do not hit a build failure before they have read anything.

The costs are real but small. Regeneration produces large diffs that reviewers
must learn to skim rather than read. A pull request touching a `.proto` and
forgetting to regenerate is rejected by CI rather than by a human, which is the
right outcome but an extra round trip for the author. And committed generated
code can be edited by hand, which nothing prevents — the regeneration check
catches it, so the failure is loud, but it is worth saying that the check is the
only thing standing between us and hand-patched bindings.

## Alternatives considered

**Generate at build time, keep it out of the tree.** Tidier history, and the
approach we started with. Rejected because it breaks `go install` and every
downstream importer, and because it silently hid a missing dependency.

**Commit, and skip the regeneration check.** Cheaper CI. Rejected: without the
check, committed output drifts from its source and the first symptom is a field
that exists in the schema and not in the code.

**A separate module for generated code.** Isolates the diffs and lets the
protocol version independently. Worth revisiting if the protocol is ever consumed
widely enough to need its own release cadence; today it would mean a cross-repo
version bump for every protocol change during the period we change it most.
