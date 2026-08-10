# ADR-0011: Full-tunnel devices fail closed

- **Status:** accepted
- **Date:** 2026-08-10

## Context

When a device routes all traffic through an exit, the tunnel going down is not
merely a loss of service — it is a silent loss of the property the user chose the
exit for. Traffic quietly resumes over the local network with the user's real
address, and nothing tells them. The moments this happens are exactly the
dangerous ones: waking from sleep, switching from Wi-Fi to tethering, an exit
failing, the agent crashing, or the agent being killed during an upgrade.

The same applies to DNS. A tunnel that is up while queries leak to the local
resolver discloses everything the user is doing to whoever runs that network.

This is not an edge case to handle later. It is the difference between a product
that provides egress control and one that appears to.

## Decision

While a membership claims a default route, `meshpd` installs firewall rules that
**block non-tunnel egress**, and those rules are:

- installed *before* the route is claimed, not after;
- kept in place if the agent exits, crashes, or is killed, because they are
  system firewall state rather than process state;
- removed only by an explicit teardown — `meshp down`, or the agent starting up
  and finding stale rules it owns.

DNS is covered by the same principle: `DnsConfig.prevent_leaks` blocks plaintext
DNS outside the tunnel while a default route is claimed.

Whether to fail closed is an **administrator policy**, not a user preference, and
it travels in desired state (`TunnelConfig.fail_closed`). The default for
route groups of kind `egress` is closed.

Because rules survive the process, `meshpd` must be able to identify and clean up
its own leftovers on startup — implemented as an owned rule table or tag on every
platform. This is a hard requirement, not a nicety: the failure mode is a machine
with no working network and no obvious cause, which is the worst bug this project
can ship (Invariant 20).

## Consequences

Users get the property they actually bought, including across sleep, network
changes and crashes. Administrators can guarantee it for a fleet.

The cost is that we have deliberately built something that can take a machine
offline, so the cleanup path has to be as well tested as the setup path — more so.
Every platform needs an implementation and an integration test that kills the
agent mid-session and asserts both that traffic is blocked and that a subsequent
start restores connectivity. `meshp doctor` must work, and must explain the
situation in plain language, on a machine with no internet access.

There will also be support tickets from users whose network broke because a laptop
lost its tunnel and correctly refused to leak. That is the intended behaviour, and
the error message is the product.

## Alternatives considered

**Fail open.** No risk of bricking a machine, and no support tickets. Rejected: it
makes the exit feature dishonest, silently, at the worst possible moment.

**Fail closed only while the agent is running.** Easier, since rules can live and
die with the process. Rejected because agent crash and agent kill are two of the
main cases the feature exists to cover.
