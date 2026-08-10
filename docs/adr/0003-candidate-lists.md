# ADR-0003: Desired state carries candidate lists, not single assignments

- **Status:** accepted
- **Date:** 2026-08-10

## Context

If the control plane tells a device "your exit is DE-01", then every failover
costs a full round trip: the node's egress breaks, health checks notice, the
selector recomputes, the new assignment is pushed, the agent applies it. Realistic
detection-to-convergence is 20–45 seconds, and none of it works at all while the
control plane is unreachable.

Letting the agent pick its own exit instead contradicts the rule that the agent
converges toward server-defined state — and worse, it makes the two disagree
without a defined winner. When a stale server assignment arrives after the agent
has already moved, which one is right?

There is also a WireGuard constraint: switching to another exit requires that exit
to already have this device in *its* peer list. Authorisation is mutual, so a
switch the server has not pre-arranged cannot work anyway.

## Decision

Desired state carries an **ordered list of pre-authorised candidates** per route
group, not a single choice. The server owns the set and the order; the agent
decides only which candidates are alive.

- The server pre-provisions peer configuration on every candidate advertiser, so
  each one already accepts this device.
- The agent probes and uses the highest-priority candidate that passes its local
  liveness check.
- The agent reports what it chose and why (`ReachabilityReport.switch_reason`).
  The server records it and emits an audit event; it does not treat it as drift
  to be corrected.

Authority splits cleanly: **the server decides authorisation and preference, the
agent decides liveness.** Neither can override the other's half.

## Consequences

Failover no longer involves the control plane, so it happens in seconds rather
than tens of seconds, and it keeps working during a control-plane outage. The
contradiction between local failover and server-defined state disappears, because
executing a server-supplied ordered policy *is* convergence.

The cost is that every device is pre-authorised on every candidate in its group,
which widens the set of exits a compromised device can reach from one to all
candidates in groups it was already entitled to use. That is an acceptable widening
— it is bounded by policy either way — but it means draining an advertiser must
also stop pre-authorising new devices, and revocation must remove the device from
every candidate, not just the active one.

The server also needs to hold more state per device and compute candidate sets on
every membership change, which makes the lazily-scoped delta protocol
(ADR-0008) more important, not less.

## Alternatives considered

**Single assignment, faster health checks.** Cuts detection time but not the round
trip, and does nothing during a control-plane outage. Sub-second central probing
of thousands of advertisers is also a lot of traffic to buy a partial fix.

**Agent picks freely from the whole pool.** Removes server preference entirely,
which loses priority, draining, capacity awareness and pinned egress IPs — all of
which are things customers pay for.
