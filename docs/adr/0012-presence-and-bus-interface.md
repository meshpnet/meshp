# ADR-0012: Presence and pub/sub sit behind an interface with in-memory and Redis implementations

- **Status:** accepted
- **Date:** 2026-08-10

## Context

Two requirements pull in opposite directions.

Self-hosting should be `docker compose up` with as few moving parts as
possible. Requiring Redis to run a ten-device network is a tax on exactly the
users we most want.

But presence and health are high-frequency writes. Advertiser health checks every
few seconds and device heartbeats every thirty seconds add up to hundreds of
writes per second at modest scale. Putting those in PostgreSQL as row updates
produces table bloat and vacuum pressure on the same database that holds desired
state. And once more than one `meshp-control` replica exists, a configuration
change on one replica has to reach agents connected to another, which needs a bus.

So Redis is genuinely optional at small scale and genuinely required at large
scale, and we cannot know which a given deployment is.

## Decision

Two narrow interfaces defined in the core, with two implementations each:

- **`Presence`** — liveness, last-seen, applied-version, session ownership,
  advertiser health state. Ephemeral by definition; losing it costs a
  re-report, not correctness.
- **`Bus`** — publish/subscribe for "network N's state changed", so any replica
  can wake the agents it holds.

Implementations: an in-memory version used when a single replica is configured,
and a Redis version used otherwise. Selection is configuration, not a build tag.

PostgreSQL remains the sole source of truth for desired state. Nothing that must
survive a restart lives only in `Presence`, and no correctness property may depend
on `Bus` delivery — a missed notification must degrade to the agent's next
heartbeat noticing a version gap, never to a permanently stale agent.

## Consequences

Small self-hosted deployments run two containers. Large ones scale horizontally by
adding Redis and replicas, with no code change and no migration. Heartbeat traffic
never touches the primary database.

The cost is two implementations of each interface to write and test, and a class of
bug that only appears in one of them. The in-memory path will get most of the
development testing while the Redis path carries production, which is backwards —
so CI runs the full integration suite against both, and that is not optional.

Keeping `Bus` non-load-bearing forces heartbeats to carry
`applied_state_version` and the server to compare it on every beat. That is
slightly more work per heartbeat and it is what makes a dropped notification a
latency problem instead of an outage.

## Alternatives considered

**Require Redis always.** One code path, no divergence, and simpler reasoning.
Rejected on the self-hosting experience, which is our main distribution channel.

**PostgreSQL for everything, including presence.** Genuinely fine up to a few
hundred devices, and it is where a naive implementation lands. Rejected because the
write pattern damages the database that matters, and because `LISTEN`/`NOTIFY`
does not fan out well enough to be the bus at scale.

**Presence in PostgreSQL with an unlogged table.** Avoids most of the bloat and
keeps one dependency. A reasonable middle path we may revisit; rejected for now
because it still puts the load on the same instance and does not solve fan-out.
