# ADR-0005: IPv6 ULA primary, configurable IPv4, never a hardcoded 100.64/10

- **Status:** accepted
- **Date:** 2026-08-10

## Context

The convention in this category is to assign mesh addresses from
`100.64.0.0/10`. That range is RFC 6598 carrier-grade NAT space, and real ISPs
assign it to real subscribers — extremely common on Indian mobile and broadband
networks, among others. A device whose WAN or LAN address already lives in
`100.64/10` will collide with the mesh, and the failure is confusing: some
destinations work, some do not, and nothing in the UI explains why.

IPv4 mesh space is also just small and awkward to subdivide per tenant, and every
address is a scarce thing to allocate and reclaim.

Separately: addresses cannot be chosen ad hoc by agents. They must be allocated
by the control plane, and a released address must not be reissued immediately —
DNS caches, ACL caches and long-lived connections all still refer to it.

## Decision

- Every membership gets an **IPv6 ULA address** from a per-deployment
  `fd00::/8` prefix. This is the primary, always-present address.
- IPv4 is allocated additionally, from a **configurable** prefix. The shipped
  default is `100.90.0.0/16`, chosen for low collision likelihood, and it is
  explicitly a default rather than an assumption.
- The deployment operator can change both, and per-network pools live in
  `address_pools` rather than in code.
- Allocation goes through IPAM (`address_allocations`). Released addresses enter a
  `quarantined` state with a `quarantine_until` timestamp before returning to the
  free pool.
- The agent detects a collision between a configured mesh prefix and a locally
  present address and refuses to bring the interface up with a specific error,
  rather than producing partial connectivity.

## Consequences

We avoid the single most confusing class of connectivity bug in this product
category, in the market we are starting in. IPv6-primary also gives every device
a globally unique-ish stable identity with no scarcity, which makes per-tenant
allocation trivial.

The cost is that IPv6 must work properly everywhere from the beginning — in the
agent, in DNS (AAAA records as first-class, not an afterthought), in ACL
compilation, in route installation and in the UI. Any platform path that assumes
IPv4 is a bug. Some legacy applications and appliances are IPv4-only, which is why
IPv4 remains allocated rather than optional.

Quarantine means the effective pool is smaller than the prefix suggests, and the
reclaim job is a piece of machinery that must be monitored.

## Alternatives considered

**Use `100.64.0.0/10` like everyone else.** Interoperable expectations, and it is
what users' existing documentation assumes. Rejected on the collision risk, which
is concentrated exactly in our beachhead market.

**IPv4 only, configurable.** Simpler agents and simpler debugging. Rejected because
per-tenant IPv4 allocation at MSP scale runs out of pleasant options quickly.
