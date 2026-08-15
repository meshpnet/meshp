# ADR-0009: Apache 2.0 core; the commercial layer is API-separated, not a fork

- **Status:** accepted, amended 2026-08-15 (see "Operated, not distributed")
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

## Operated, not distributed (amendment, 2026-08-15)

The original decision said what the commercial layer *is* and left open how it
reaches anyone. It is now settled: **the commercial layer is operated, never
distributed.** It runs in meshp Cloud and nowhere else. There is no on-premise
build, no licence key, no customer-installable agency tier.

So the only multi-tenancy anyone else can run is the one they build themselves on
the open API, which they are free to do — and a self-hosted meshp is a complete
single-tenant deployment with the real web UI, not a trial of one.

This was decided against a specific temptation. The market has no self-hostable
multi-tenant mesh in it, which reads like an opening, and taking it would mean
shipping the closed layer as installable software. That trade is bad at this
size: it buys one differentiator and costs an entire business function — licence
issuing, an air-gapped activation story, a version support matrix, upgrade
support for deployments nobody here can see, and debugging someone else's
infrastructure by correspondence. One person cannot run that and build this. The
differentiator is not one we could service anyway.

What it costs is worth naming rather than discovering later. It forfeits the
sovereignty deal: an MSP whose own customer is a hospital or a bank that requires
the control plane inside their datacentre cannot be served, and with CERT-In in
the picture that is not a fringe case in India. It also means competing on
execution rather than on a difference in kind, since the comparable hosted
products are cloud-only too.

**The decision is deliberately reversible, in one direction.** An on-premise
offering can be added later; one that has shipped cannot be withdrawn. It stays
cheap to add only while the boundary above holds — the commercial layer calling
the open control plane over its HTTP API, never linked, never forked. Keep that
and on-premise is a packaging problem. Break it, by growing tenancy into the
control plane because that is easier for the hosted product, and this stops being
a decision that can be revisited. `make standalone-check` is what guards it.

One consequence follows and is easy to miss. With no component to sell a
self-hoster, the open build is not the bottom rung of a product ladder — there is
no rung above it short of migrating to the hosted service entirely. It is there
to be genuinely good and to be trusted, and that is the whole of its commercial
job. Deciding how much to invest in it on any other basis will get the answer
wrong.

## Alternatives considered

**AGPL control plane, Apache agent.** Real protection against a hosted competitor.
Rejected because it protects a low-value asset, complicates the repository
topology, and muddies the trust story that is our main advantage over the
proprietary incumbent.

**Open core with failover behind a paid tier.** The most direct revenue path, and
the reason a lot of infrastructure software is resented. Rejected on principle and
on strategy: crippled redundancy would remove the one differentiator people would
otherwise talk about for us.
