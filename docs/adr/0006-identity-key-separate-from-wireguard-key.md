# ADR-0006: Device identity key is separate from rotatable WireGuard keys

- **Status:** accepted
- **Date:** 2026-08-10

## Context

The tempting simplification is to let a device's WireGuard public key *be* its
identity. One key, one row, no indirection.

It makes key rotation impossible without re-enrolment. Rotating a WireGuard key
would change the device's identity, so every reference — audit history, ACL tags,
DNS records, route advertiser rows, assignment history — would have to be
rewritten or would silently point at a device that no longer exists. In practice
products that do this simply never rotate, which is a poor answer for a key that
lives on a laptop for three years.

It also interacts badly with multi-network membership (ADR-0004), where a device
deliberately holds a *different* WireGuard key per network.

## Decision

Two kinds of key:

- **Device identity:** a long-lived Ed25519 keypair generated at enrolment.
  `devices.identity_public_key` is unique and is what the device authenticates
  the control channel with, by signing a server-issued challenge. It is the
  device's stable name for its whole life.
- **WireGuard keys:** one per network membership, in `wireguard_keys`, rotatable.
  Rotation creates a new `current` key while the previous one moves to
  `retiring` for an overlap window so peers accept both, then to `retired`.

Enrolment proof is therefore concrete: the device generates its identity keypair
locally, and proves possession by signing the challenge in `ClientHello`. The
enrolment token authorises; the signature authenticates. Neither private key ever
leaves the device.

## Consequences

WireGuard keys become routine to rotate, which we will want for scheduled hygiene
and need for incident response. A device's history stays intact across rotations.
Per-membership keys mean customer networks cannot correlate a shared device.

The cost is a second key to generate, store and protect, and an overlap window
during which two public keys are valid for one membership — which the peer
distribution logic and the `wireguard_keys_one_current` invariant have to handle
carefully. Rotation is a distributed operation: it is not complete until every
peer that needs the new key has applied it, so it is driven by the same
version-and-ack machinery as everything else rather than by a timer.

## Alternatives considered

**WireGuard key as identity.** Simplest. Rejected: it trades away key rotation
permanently, which is not a trade worth making for one saved column.

**Certificate-based device identity (an internal PKI).** More standard, and a
better story for enterprises later. Rejected for v1 as a large amount of
machinery — issuance, renewal, revocation lists, trust distribution — to solve a
problem one Ed25519 key already solves.
