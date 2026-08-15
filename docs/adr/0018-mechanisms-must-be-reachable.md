# ADR-0018: A mechanism is not done until something running reaches it

- **Status:** accepted
- **Date:** 2026-08-15

## Context

Twice now a complete, well-commented, well-tested mechanism has been merged into
`main` while reachable from no running code. Both times every test passed. Both
times the feature was simply absent from every build, and nothing said so.

**`peerset` dropped `StateDelta.relays`.** The field was added to the proto and
handled everywhere downstream of it — relay credentials, the relay link, endpoint
selection, the status output — but not in the fold that turns a delta into desired
state. So an agent discarded every relay the control plane sent it. Each piece had
tests and each passed, because each was tested against a `Set` built by hand in
the test rather than against one `peerset` had produced from a delta.

**`cmd/meshpd` never called `WithChooser`.** Local failover was built across two
pull requests, with unit tests, property tests and mutation testing on the
decision logic. The daemon never gave the reconciler a chooser, so no released
agent could fail over. The tests all constructed the reconciler themselves.

The common cause is not carelessness about wiring. It is that **a unit test
constructs the object it is testing**, which makes it blind, by design, to whether
production constructs it at all. The better the unit test, the more confidently it
reports success on a feature nothing can reach.

It is also not a problem more unit tests would fix, and it resists the usual
instinct — the code reads correctly, because it *is* correct. What is missing is
one edge in a call graph.

## Decision

Adding a seam is not finished at the seam. Specifically:

- **When a new option, sink or constructor argument is added to a package, grep
  for its call site in `cmd/` before the pull request is opened.** If nothing in a
  binary calls it, the change is incomplete, however good the tests are.

- **At least one test per mechanism must reach it the way production does.** Not
  by constructing the object, but through whatever the daemon or the server
  actually builds. Where that is impractical in Go — `cmd/meshpd` has no test
  files and its reconciler needs a real link — the end-to-end scripts are the
  place, because they run the real binaries.

- **Prefer an observable that only exists when the mechanism runs.** Asserting
  that traffic still flows proves nothing: a device with no chooser routes through
  the server's first candidate and every routing assertion passes. Asserting that
  a `ReachabilityReport` reached the database cannot pass without the chooser
  running. When choosing what to assert, pick the thing that is absent when the
  wiring is absent.

- **When a message type gains a field, handle it in every path that carries
  state.** For `peerset` that is fold, snapshot-clear, `Clone` and `Equal`; the
  package doc lists them. A field added to three of the four is silently wrong.

## Consequences

`scripts/e2e-failover.sh` exists largely because of this, and its central
assertion was chosen against this rule: it stands up two live agents in network
namespaces so a real handshake happens, then asserts a client's verdict reached
the control plane. Reintroducing the `WithChooser` omission makes it fail, while
every routing assertion in the same script still passes — which is the signature
this ADR is about.

The cost is that some mechanisms are awkward to reach from a test that goes
through production construction, and reaching them means building harnesses like
that one. That cost is real and is worth paying: the alternative is a suite that
grows more confident as it becomes less connected to what ships.

This does not ask for end-to-end coverage of everything. It asks for one edge, per
mechanism, that would break if the mechanism were unplugged.

## Alternatives considered

**Trust review to catch it.** Both instances were reviewed. The diff that adds
`WithChooser` to a package and the absence of a call to it in `cmd/` are not in the
same diff, and often not in the same pull request.

**A lint that flags exported functions with no non-test callers.** Appealing, and
it would have caught `WithChooser` exactly. Rejected for now because the false
positive rate on a library with a deliberate public API is high enough to be
ignored, and an ignored gate is worse than none. Worth revisiting if this happens
a third time.
