# ADR-0017: An agent asks for its relay credential; the server does not push it

- **Status:** accepted
- **Date:** 2026-08-13

## Context

A relay verifies a short-lived signed capability naming one WireGuard key and one
network (ADR-0016). Something has to get that capability to the agent.

Two things about it decide the answer. It is **device-specific** — a token for one
key is useless to another. And it is **short-lived** — thirty minutes, chosen so
that the whole cost of a leak is bounded by a number we pick rather than by how
long until someone notices.

Desired state is neither of those things. It is network-scoped and versioned: a
delta describes a network at a version, and every agent in that network converges
on it. Putting a per-device credential inside it would mean bumping a network's
state version for one device's token, every half hour, for every device — turning a
counter that exists to describe the network into a clock. The delta machinery would
work; the meaning would be wrong.

Where relay *endpoints* belong is a different question with a different answer,
already settled by the protocol: `StateDelta` carries `RelayConfig`. Which relays
exist, their addresses and their keys are network-wide facts that change rarely, and
versioning them is exactly right.

## Decision

Relay endpoints arrive in desired state, as the protocol already provides for.

The token arrives by request: the agent sends `RelayTokenRequest` on the control
channel it already holds, and the server answers with `RelayToken`. Two additive
messages.

The agent asks because **it is the only party that knows when it needs one**. It
knows when its token expires, whether it is currently relaying, and whether a relay
has just refused it. A server pushing on a timer would have to model all of that
from a distance and would push to devices that are not relaying at all.

The token is not relay-specific. It names a key and a network and is signed by the
deployment, so any relay holding that public key accepts it. A token per relay would
multiply the requests and buy nothing: the relay is not the thing being
authenticated, the device is.

The request carries no fields. The session already establishes which membership is
asking, and adding a device identifier to a message sent over an authenticated
session would create a second, weaker way to say who you are.

## Consequences

An agent with no control channel cannot obtain a *new* relay credential. Its
existing one keeps working until it expires, so a control-plane outage costs
connectivity only if it outlasts the token — which is why thirty minutes rather than
thirty seconds, and it is the reason Invariant 15 constrains the TTL rather than
security alone. An outage longer than the TTL degrades relayed paths while direct
paths continue, and that is a real weakening of Invariant 15 that ADR-0016 already
introduced by putting the agent in the data path.

The server must hold a signing key, which is new: until now the control plane held a
symmetric secret for enrolment challenges and sessions, and nothing it produced was
verified by a third party. A deployment now has an identity that relays trust, which
means key rotation becomes something we will have to design — a relay configured with
the old public key rejects every token from a rotated control plane, and the failure
looks like every device losing relaying at once.

Requests are cheap but unbounded: a misbehaving agent could ask continuously. The
server should rate-limit and, better, refuse to issue a second token while the first
is still comfortably valid — returning the one it already issued rather than minting
another, so a loop costs nothing and the number of live credentials per device stays
at one.

## Alternatives considered

**An HTTP endpoint on the control plane.** Simpler to reason about in isolation and
trivially testable with curl. Rejected because the agent already holds an
authenticated, live session that exists precisely to carry this kind of exchange, and
a second path means a second authentication story, a second thing to rate-limit, and
a second thing that has to work through whatever proxy an operator puts in front.

**Pushing the token in desired state.** Rejected above: it would make a network's
version counter advance for per-device credential rotation. It also delivers to every
device whether or not it relays.

**A long-lived or permanent token.** Removes the refresh problem entirely. Rejected
because the credential's whole security argument is that it expires: a stolen token
lets someone receive a key's relayed packets — which they still cannot decrypt — and
the only thing bounding that is the clock.
