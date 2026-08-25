# ADR-0025: The bus is PostgreSQL LISTEN/NOTIFY, not Redis

- **Status:** accepted
- **Date:** 2026-08-25
- **Amends:** [ADR-0012](0012-presence-and-bus-interface.md), for `Bus` only

## Context

ADR-0012 defined two interfaces — `Presence` and `Bus` — and named their
implementations: "an in-memory version used when a single replica is configured, and a
Redis version used otherwise."

Two years of that record being unimplemented is not why it is being revisited. It is
being revisited because the first thing to actually need it is `Bus`, on its own, and
the reasoning that made Redis the obvious answer for *both* does not survive being
applied to one.

ADR-0012's own Context states the tension:

> Self-hosting should be `docker compose up` with as few moving parts as possible.
> Requiring Redis to run a ten-device network is a tax on exactly the users we most want.

It accepted that tax on the grounds that a deployment large enough to need replicas is
large enough to run Redis. That trade is real for `Presence`, which is high-frequency by
definition. It is not real for `Bus`: a notification is published when an administrator
changes something, which is a human-rate event, not a per-heartbeat one.

## Decision

`Bus` is PostgreSQL `LISTEN`/`NOTIFY`. Every deployment already has PostgreSQL, so
redundancy costs no additional infrastructure.

`Presence` is not settled here. It stays as ADR-0012 describes — in-memory today, and
whatever it eventually needs is a separate decision, because the argument that moves `Bus`
to PostgreSQL is precisely the argument that keeps `Presence` out of it. ADR-0012 is
otherwise unchanged: the interfaces stay, the selection stays configuration rather than a
build tag, and nothing that must survive a restart lives in either.

### Why this is better than Redis here, not merely cheaper

**A notification is delivered at `COMMIT`.** This is the part that would have been a bug
with Redis rather than a cost. The publisher changes state in a transaction and then tells
the world; with Redis those are two systems and there is a window between them, so a
replica can be woken to read state that has not committed yet — and it reads the old state,
concludes nothing changed, and goes back to sleep. The change then waits for the next
heartbeat, which is exactly the outage `Bus` exists to avoid, appearing only under load.

PostgreSQL has no such window. `NOTIFY` inside a transaction fires when that transaction
commits, and **never fires at all if it rolls back**. Both were verified against a real
server before this was written, not inferred from the manual.

**One fewer thing to secure, back up and watch.** A Redis carrying wake-ups for every
network on a control plane is a component with credentials, a network position and a
failure mode, added to a product whose argument is that self-hosting should be ordinary.

**It cannot silently become load-bearing.** ADR-0012 requires that a missed notification
degrade to the agent's next heartbeat noticing a version gap. A queue that is best-effort
by construction — no persistence, no delivery guarantee, dropped entirely if a listener is
not connected — keeps that honest in a way a durable queue would quietly erode.

### What this costs

**A connection per replica, held open.** `LISTEN` needs a session of its own; it cannot
share the pool, because a pooled connection is handed back between statements. With
`MaxConns` at 16 this is affordable and it is a real charge against the pool.

**`NOTIFY` has a global queue with a ceiling.** PostgreSQL keeps pending notifications in
one server-wide 8 GB queue and raises an error when it fills, which happens when a listener
stops consuming. meshp publishes on administrative change rather than on heartbeat, so the
rate is orders of magnitude below the risk — but "we are far from the limit" is a fact
about today's usage, and anything that starts publishing per-device-event should read this
paragraph first.

**Payloads are capped at 8000 bytes.** Irrelevant here: the payload is one network id, and
deliberately nothing more — the message says *what changed*, never *how*, so a listener
always reads the committed state rather than trusting a wire format.

## Consequences

**Redundancy stops requiring extra infrastructure.** Two `meshp-control` containers against
one PostgreSQL is now a working configuration rather than a broken one. That matters
disproportionately for this product: redundancy that required an operator to stand up and
secure a second data store would be redundancy most self-hosters do not have.

**Redis is not ruled out and is no longer implied.** If `Presence` eventually needs a shared
store, that decision is made on its own terms. Having `Bus` on PostgreSQL does not
prejudice it, and does not oblige a deployment that adds Redis for `Presence` to move `Bus`
there too.

**The in-memory implementation stays.** A single-replica deployment does not need a
listening connection, and the selection is configuration. This also keeps the test path
ADR-0012 asked for, where the same suite runs against both.

**One notification may nudge a replica twice.** The publisher notifies its own hub directly
*and* publishes, so it receives its own message back. Harmless — `Session.Notify` coalesces,
and ten nudges produce one push — and deliberately not optimised away, because suppressing
self-delivery means tracking a replica identity for no benefit, while the local notify must
not depend on the bus round trip: if PostgreSQL is unreachable the agents attached to *this*
replica should still be woken.

## Alternatives considered

**Redis, as ADR-0012 said.** The right answer if `Presence` and `Bus` had to share a
mechanism, and the wrong one for `Bus` alone. Rejected on the infrastructure tax and on the
commit-window bug above; the second is what changed this from a preference into a decision.

**No bus; let the heartbeat find it.** Agents already carry `applied_state_version` and the
server already compares it, so a change reaches every device within one heartbeat interval
with no new machinery at all. Genuinely tempting, and rejected because that interval is the
difference between revoking a device and *having* revoked it — an administrator who removes
a laptop expects it gone, not gone within a minute.

**A polled table.** A `state_changes` table replicas poll. No held connection and no queue
ceiling, at the cost of a query per replica per interval forever, and of reintroducing the
latency the bus exists to remove. It is what to fall back to if the queue ceiling ever
becomes a real constraint rather than a paragraph.
