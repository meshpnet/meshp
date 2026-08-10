# ADR-0009: Apache 2.0 core; the commercial layer is API-separated, not a fork

- **Status:** accepted
- **Date:** 2026-08-10

## Context

We need a licence split that keeps a business viable without making the open
project a demo. Two candidate shapes:

- Copyleft the control plane (AGPL) to stop a competitor offering it as a service,
  keeping the agent permissive.
- Apache everything in the core and rely on the proprietary layer above it.

The deciding question is what a competitor actually gains by running our open
control plane as a service. The answer is: a single-tenant WireGuard manager. That
product exists, is free, and nobody has built a business on it. Our defensible
asset is multi-tenant management, white-label branding, metering and billing —
which is proprietary regardless of the core's licence.

An AGPL core would also force license boundaries to become repository boundaries,
and would create a permanent question about whether the agent people run on their
laptops is really permissive.

## Decision

- **Apache 2.0** for the entire open core: agent, CLI, protocol, relay, control
  plane, IPAM, ACL engine, DNS, route groups and failover, gateways, web UI,
  deployment tooling.
- **Proprietary**, in a separate private repository, for the commercial layer:
  agency hierarchy, white-label, custom domains, billing, metering, provisioning,
  SSO/SCIM, posture, fleet orchestration.
- The commercial layer **calls the open control plane over its HTTP API**. It is
  never linked into it, does not fork it, and does not enable features that are
  disabled in the open build.
- Contributions carry a DCO sign-off.

Two things follow and are enforced in CI:

1. No package in this repository may import anything from the commercial
   repository (`make standalone-check`).
2. The open core must build, test and run with the commercial layer entirely
   absent.

Redundancy is explicitly in the open core. Route groups, health checking,
automatic failover and failback are not paid features. We do not sell reliability
back to people by withholding it.

## Consequences

We can say, truthfully, that every line of code that touches a packet is open
source, and that the only closed components are billing, tenant hierarchy and our
own infrastructure. That claim is worth more to us than the protection AGPL would
have offered, and it is the thing that has to survive every future decision.

Because the boundary is an API, self-hosters run the same `meshp-control` binary
we run, and the proprietary layer is forced to use a complete public API — we are
its first consumer, so it cannot rot.

The costs: anyone may run our core as a service, and some will. Some will resell
it. We accept that and compete on operating it. Apache also means we cannot later
relicense contributed code without permission, so if dual-licensing ever matters
we would need a CLA from that point forward, not retroactively.

## Alternatives considered

**AGPL control plane, Apache agent.** Real protection against a hosted competitor.
Rejected because it protects a low-value asset, complicates the repository
topology, and muddies the trust story that is our main advantage over the
proprietary incumbent.

**Open core with failover behind a paid tier.** The most direct revenue path, and
the reason a lot of infrastructure software is resented. Rejected on principle and
on strategy: crippled redundancy would remove the one differentiator people would
otherwise talk about for us.
