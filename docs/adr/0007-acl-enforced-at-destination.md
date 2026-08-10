# ADR-0007: ACLs are enforced at the destination, in the agent

- **Status:** accepted
- **Date:** 2026-08-10

## Context

Policy like "Developers may reach Development on TCP 22 and 443" has to be
enforced somewhere in the data plane. WireGuard's `AllowedIPs` cannot express it:
it is a prefix-to-peer map with no notion of ports or protocols. Restricting which
peer keys a device receives gives coarse host-level reachability at best, and it
leaks the shape of the network to anyone who inspects a config.

If enforcement happens only on the sending side, then a device whose agent has
been tampered with — root on their own laptop is enough — simply ignores the rules.

## Decision

The control plane compiles the ACL document into a per-device `PacketFilter` and
the agent enforces it, **inbound at the destination**, as the authoritative check.
Source-side outbound rules are also installed, but only to fail fast and give a
clear local error; they are never the security boundary.

Platform implementations: nftables on Linux, WFP on Windows, and the packet-filter
path in the macOS network extension. An agent that cannot enforce a filter reports
`packet_filter: false` in its capabilities, and the control plane refuses to place
it in a network whose policy requires port-level enforcement rather than silently
degrading to host-level.

The policy itself is one versioned JSON document per network
(`acl_policies.document`) rather than a table of rules, so it can be diffed,
reviewed, tested against real traffic with `meshp acl test`, and rolled back.

## Consequences

Policy holds even against a compromised or modified client, which is the only
version of this feature worth selling. Because the destination decides, we can
also give honest answers to "why was I refused?" from the side that actually
refused.

The costs are substantial and worth stating plainly. We need three separate
packet-filter implementations, each with its own quirks and its own failure modes,
and getting them wrong means either a security hole or a broken network. Rules
must be reconciled atomically with the rest of desired state — a half-applied
filter is worse than none. And a device is now responsible for enforcing rules
about traffic *to* it, so a stale filter on one machine is a policy gap even when
every other machine is current, which makes convergence lag a security metric and
not just an ops metric.

## Alternatives considered

**Enforce only via peer distribution and `AllowedIPs`.** Nearly free, works
everywhere, no packet filters. Rejected: no port granularity, and it cannot
express deny at all. This is the coarse fallback for agents that report no filter
capability, not the model.

**Enforce at the source only.** Simpler and the error messages are better.
Rejected because it is advisory rather than enforcing.

**Enforce centrally by proxying traffic.** Would give the strongest control, and
violates Invariant 2 — the control plane must never be in the data path.
