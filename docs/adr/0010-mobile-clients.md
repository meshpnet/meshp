# ADR-0010: Mobile clients wrap the official WireGuard tunnel libraries and are relay-only

- **Status:** accepted
- **Date:** 2026-08-10

## Context

Porting our whole data plane to iOS and Android — ICE, hole punching, endpoint
discovery, route and DNS management — is several months per platform. iOS adds a
memory-constrained network extension process, a Network Extension entitlement with
a multi-week approval lead time, and VPN-specific App Store review. Android adds
`VpnService`, userspace WireGuard, and doze-mode behaviour.

Meanwhile phones are usually behind carrier NAT, where hole punching frequently
fails anyway. The expensive part of the port is the part that would least often
pay off.

## Decision

The mobile clients are thin applications over the **official WireGuard tunnel
libraries** (`wireguard-apple`, `wireguard-android`), plus our control-channel
client. They are **relay-only**: no ICE, no hole punching, no direct paths.

They keep everything that makes meshp meshp — live desired-state updates, policy
changes without re-scanning a QR code, DNS configuration, route groups, egress
selection and failover — because all of that rides the control channel rather than
the traversal stack.

The Go core is consumed as a published binary artifact from `meshp` releases (an
`.xcframework` for iOS, a shared library plus JNI for Android), not as a source
submodule, so a Go commit cannot break mobile CI.

Both clients are open source. A closed-source VPN client on someone's phone
contradicts the project's whole proposition, and openness is also what makes
F-Droid distribution possible.

## Consequences

Real mobile clients in roughly six weeks each instead of six months each, with
full policy and failover behaviour. We can honestly say all five platforms join
one network.

The cost is performance: two phones on the same office Wi-Fi relay through a
datacentre, and every mobile byte is relay bandwidth we pay for. Mobile is
therefore disproportionately expensive per user, which has to be in the pricing
model rather than discovered later. Phone-to-phone latency will be visibly worse
than a competitor's, and we should say so rather than let people find out.

Adding direct paths on mobile later is additive — a capability flag and a
traversal implementation — so this is a deferral, not a dead end.

White-label branding is driven at runtime from the login domain, not by
per-agency builds. Apple rejects apps built from a commercialised template unless
submitted by the provider of the content, so per-agency iOS apps would have to be
published under each agency's own developer account.

## Alternatives considered

**Full port of the data plane to both platforms.** The right answer eventually.
Rejected as a v1 cost that would delay everything else by two quarters to improve
a case that carrier NAT often defeats.

**Ship plain WireGuard config profiles and no app.** Nearly free, and mobile users
would appear in the mesh immediately. Rejected because a static profile cannot
receive policy updates, cannot fail over, and needs a new QR code every time an
admin changes anything.
