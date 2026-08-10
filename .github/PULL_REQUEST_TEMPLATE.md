<!--
Keep this short. The parts that matter are the invariants and the migrations,
because those are the two things a reviewer cannot easily check by reading a diff.
-->

## What this changes

<!-- One or two sentences. Why, more than what — the diff already says what. -->

## Invariants

Does this touch anything in [`docs/INVARIANTS.md`](../docs/INVARIANTS.md)?

- [ ] No invariant is affected.
- [ ] An invariant is affected, and it still holds. Which, and how it is tested:

<!-- e.g. "Invariant 8 — added a case to TestPropertyNeverOffersSomethingUnusable" -->

## Decisions

- [ ] This follows the existing ADRs.
- [ ] This changes a decision recorded in [`docs/adr`](../docs/adr), and an ADR is added or superseded in this pull request.

## Checks

- [ ] `make ci` passes locally.
- [ ] Commits are signed off (`git commit -s`).
- [ ] New behaviour has tests. Behaviour that depends on elapsed time uses `clock.Fake`, not `time.Sleep`.
- [ ] Any new migration is a **new file**; no already-merged migration is edited.
- [ ] Protocol changes only add fields — nothing removed, nothing renumbered.
