# ADR-0001: Route groups, not exit pools

- **Status:** accepted
- **Date:** 2026-08-10

## Context

The obvious model for redundant internet egress is an "exit pool": a named set
of exit nodes, with health checking, priority, draining and failover attached to
it.

Build that and you will build it a second time within months. The first customer
with two subnet routers behind one office LAN needs exactly the same
thing — ordered candidates, health, draining, failover — for `192.168.1.0/24`
instead of `0.0.0.0/0`. So does anyone who wants a redundant service gateway.
Exit pools are a special case wearing a costume.

There is also a hard constraint that shapes the model. In WireGuard,
`AllowedIPs` *is* the routing table, and a prefix can belong to only one peer per
interface. There is no "two peers both advertising the default route" state to
model, so per-device multipath is not on the table regardless of how we name
things.

## Decision

One primitive: a **route group** is a set of prefixes plus an ordered set of
**advertisers**, where an advertiser is a device membership that has agreed to
carry that traffic.

- An exit is a route group over `0.0.0.0/0` and `::/0`.
- A subnet router is a route group over a LAN prefix.
- A service gateway is a route group over a `/32`.

Health, priority, weight, draining, selection mode, failover and failback are
properties of the route group and its advertisers. "Exit pool" survives only as
a label in the UI for a route group whose kind is `egress`.

## Consequences

Health checking, the failover state machine, the anti-flap rules and the audit
events are written once and are immediately available to LAN gateways. Gateway HA
becomes a UI change rather than a project.

The cost is that the model is more abstract than the product vocabulary.
Customers say "exit node" and the schema says `route_advertisers`, so the UI and
the API have to translate, and error messages need care to avoid leaking the
abstraction. We accept that: one honest primitive with a translation layer beats
three subsystems that drift.

Because per-device multipath is impossible, `LOAD_BALANCED` as a per-device mode
is not implementable and we do not offer it. Spreading *different devices* across
advertisers is possible and is what `failover` mode does when several advertisers
share a priority.

## Alternatives considered

**Exit pools now, generalise later.** Rejected: the generalisation touches the
schema, the protocol and the agent's route installer simultaneously, which is the
definition of a migration you avoid doing.

**Model it as generic policy routing with a rules engine.** Too much surface for
v1, and it makes the common cases hard to express. Route groups are the smallest
abstraction that covers the three real cases.
