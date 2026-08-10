# ADR-0008: Desired state is delivered as incremental, lazily scoped deltas

- **Status:** accepted
- **Date:** 2026-08-10

## Context

The simple implementation pushes each agent the full state of its network whenever
anything changes. It is easy to reason about and it is quadratic: a 500-device
network means every join sends 500 agents a 500-peer document. At MSP scale, with
technicians in dozens of networks, this becomes the dominant cost of running the
control plane and the dominant cause of agent CPU spikes.

Full-state pushes also hand every device a complete map of the network, including
hosts its policy forbids it from reaching — a needless disclosure.

The wire protocol is the single hardest thing to change once agents are deployed
in the field, so this cannot be deferred as an optimisation.

## Decision

Two properties, both from the first version of the protocol:

**Incremental.** `StateDelta` carries `from_version` and `to_version` with only
what changed: peers to upsert, peer keys to remove, and components (DNS, filter,
route groups, relays, tunnel) present only when they differ. `from_version: 0`
means a full snapshot, which the server sends when the agent is too far behind or
its history is unavailable. Agents acknowledge with `StateAck.applied_version`,
and the gap between a network's `state_version` and each membership's
`applied_version` is our primary convergence metric.

**Lazily scoped.** An agent receives only the peers its ACLs permit it to reach.
Scope is a function of policy, so a policy change can add or remove peers from an
agent's view, which is a normal delta.

Protocol compatibility rules live in `proto/meshp/v1/control.proto` and are
enforced by `make proto-lint` plus an N-2 agent test in `meshp-testlab`.

## Consequences

Update cost scales with the size of the change rather than the size of the
network, and a device's config stops being a map of everything. Bandwidth and
agent CPU stay flat as networks grow.

The costs: the server must retain enough version history to compute deltas, and
must fall back to snapshots correctly when it cannot — a bug here means agents that
never converge. Scope changes are subtle, because "this peer was removed" and
"you may no longer see this peer" are different events that look identical on the
wire, and only the first should tear down a working tunnel. Debugging is harder
than with full pushes, which is why `meshp doctor` captures the applied version
and the last several deltas.

## Alternatives considered

**Full state pushes, optimise later.** Rejected: this is a protocol change, and
protocol changes after agents are deployed are the expensive kind. Doing it now
costs days; doing it in a year costs a compatibility matrix.

**Full state, sent rarely, with a separate fast path for urgent changes.** Two
mechanisms doing one job, and revocation — the change that most needs to be fast —
ends up on the slow path or duplicated.
