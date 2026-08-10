# ADR-0002: Relay-first, with opportunistic direct upgrade

- **Status:** accepted
- **Date:** 2026-08-10

## Context

The usual order is to build direct peer-to-peer connectivity first and add a
relay as a fallback. That order puts the hardest, least predictable component —
NAT traversal across symmetric NATs, CGNAT, and hostile corporate firewalls — on
the critical path to a product that works at all.

We are building the data plane from parts (`wireguard-go`, `wgctrl`,
`pion/ice`) rather than inheriting a mature one, so our hole punching will be bad
before it is good. Meanwhile a relay is a few hundred lines that works
everywhere, immediately.

## Decision

Every session starts on a relay. A direct path is attempted in the background and
adopted only once it is proven with a successful handshake and a round trip. If
it later degrades, traffic falls back to the relay.

Relay reachability is therefore a hard requirement and direct connectivity is an
optimisation. `meshpd` never reports a peer as unreachable because hole punching
failed.

## Consequences

The product works on day one, on every network, including the ones where
traversal will never succeed. Debugging is far easier because "is it connected?"
and "is it fast?" become separate questions with separate answers.

We pay for it in bandwidth and latency, and the relay fleet becomes
infrastructure we must operate and pay for from the first user rather than the
hundredth. Relay cost per user is a real number in the unit economics, not a
rounding error, and self-hosters must run at least one relay for their network to
function.

There is also no user-visible "fallback" event, which removes a whole category of
confusing support conversation. The status output shows `direct` or `relay` as a
path quality, not as a success or a failure.

## Alternatives considered

**Direct-first with relay fallback.** The conventional order. Rejected because it
makes early milestones depend on the component most likely to slip, and because
the failure mode — some users simply cannot connect — is the worst possible first
impression.

**Relay-only, permanently.** Simpler, and honestly adequate for many business
customers. Rejected because latency between two machines in the same office
routing through a datacentre is indefensible, and because direct paths are most
of the performance story we will eventually be judged on.
