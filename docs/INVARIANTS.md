# Invariants

These are the properties that must hold at all times. They are referenced by
number from code comments, and a change request that breaks one of them needs a
new ADR, not a pull request.

Unlike an ADR, an invariant is not a trade-off we chose. It is a promise the
product makes.

---

**1. WireGuard private keys never leave the device that generated them.**
Not to the control plane, not to a backup, not into a support bundle.

**2. The control plane never carries user traffic.**
It distributes configuration. Packets travel device to device, device to relay, or
device to route advertiser. If a feature would put `meshp-control` in the data
path, the feature is wrong.

**3. Relays never need to decrypt user traffic.**
A relay forwards opaque bytes between public keys. A fully compromised relay
learns who talks to whom and how much, and nothing about what.

**4. Networks are isolated by default.**
Two networks in the same organisation, or under the same agency, have no
connectivity implied by that shared ownership.

**5. Cross-network connectivity requires an explicit network link.**
Never inferred from hierarchy, ownership or billing.

**6. Route-group access is explicitly authorised by policy.**
Knowing an advertiser's endpoint grants nothing. Authorisation is enforced by the
advertiser's own peer list, not by the secrecy of an address.

**7. A route group may contain many advertisers.**
Single-advertiser is a configuration, never an assumption in the code.

**8. An unhealthy advertiser receives no new assignments.**
A draining advertiser also receives none, while keeping the devices it already has.

**9. Failover requires no manual intervention when it is enabled.**

**10. Failover never flaps.**
Failure and recovery thresholds, cooldowns, hysteresis and a floor on reassignment
frequency are mandatory, not tunable-to-zero.

**11. Existing connections may break during an advertiser failure.**
meshp provides routing failover, not stateful connection migration. We say this
plainly in the product rather than implying otherwise.

**12. The networking core works with no commercial layer present.**
It builds, tests, runs and self-hosts standalone. Enforced by
`make standalone-check`.

**13. Every security-sensitive administrative mutation is auditable.**
Including the ones the system performs by itself, such as automatic failover.

**14. The agent converges toward server-defined desired state.**
Where the agent has local autonomy — liveness of route candidates — that autonomy
is granted by server-supplied policy, so exercising it is convergence rather than
an exception to it. See ADR-0003.

**15. A control-plane outage does not interrupt established networking.**
Peers, routes, DNS and route-group candidates persist locally and keep working.
Losing the control plane costs new configuration, not connectivity.

The control plane is not the agent. On a direct path the kernel carries packets
whether meshpd is running or not, and this promise is as strong as it sounds. On a
relayed path the agent is in the data path (ADR-0016), so losing it does stop
traffic that a direct path would have kept carrying — which is why meshpd must be
supervised, and why upgrading to a direct path is a resilience measure and not
only a performance one.

**16. No traffic leaves the device outside the tunnel while a default route is claimed.**
Across sleep, network change, agent crash and agent kill. See ADR-0011.

**17. A membership's address is stable for its lifetime and is not reissued immediately after release.**
Quarantine before reuse, because DNS and ACL caches outlive the device that left.

**18. Applying desired state is idempotent.**
Applying the same version twice produces identical system state. This is what
makes the reconciler testable.

**19. A WireGuard public key is never shared across networks.**
One key per membership, so two customer networks cannot correlate a device.

**20. Everything the agent installs, the agent can remove.**
Routes, DNS settings, firewall rules and interfaces. No crash, kill, upgrade or
uninstall may leave a host without working networking.

**21. Applying a delta reaches the same state as applying a snapshot.**
For any version F and head H, `apply(state at F, delta F→H)` holds exactly what a
snapshot at H holds. A delta that cannot be applied to what the agent has is refused
rather than applied to the wrong base: two versions that agree on their number and
disagree on their contents is drift nothing downstream can detect. See ADR-0008.

**22. Desired state handed to a reconciler belongs to it.**
What the agent is told to converge on does not change underneath it. A reconciler
that compares what it applied against what it is now asked to apply must be able to
keep the former, or the comparison is between something and itself and the work is
silently skipped.
