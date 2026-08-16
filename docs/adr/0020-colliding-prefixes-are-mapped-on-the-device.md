# ADR-0020: Colliding prefixes are mapped on the device that sees the collision

- **Status:** proposed
- **Date:** 2026-08-16

## Context

ADR-0019 settled that two customers both carrying `192.168.1.0/24` is an addressing
problem rather than a routing one, and handed the rest forward: *"Each membership's
colliding prefix gets its own mapped address range, and the name layer resolves to
the mapped address rather than to the customer's own. What that mapping looks like is
not settled here."*

This settles it. There are two questions left — **who allocates a mapped range**, and
**where the translation happens** — and the answers are not independent.

Today a collision is detected and refused (PR #70). A device in two networks that
both carry `192.168.1.0/24` carries neither and reports both route groups unhonoured.
That is deliberate and it is not a resting place: the technician ADR-0004 exists for
still cannot reach either customer.

Three constraints make most of the obvious answers wrong.

**ACLs are enforced at the destination (ADR-0007).** The authoritative check is
inbound, on the machine being reached, against the identity of the device reaching
it. Anything that rewrites the source address between the technician and the
customer's server destroys the input that check runs on. The customer's file server
would see one address for every technician in the MSP.

**Failover must not drop connections.** Route groups exist so that when an advertiser
fails, another one carries the prefix and traffic continues (ADR-0001, ADR-0003).
Connection tracking state does not move between advertisers. Any design that puts
per-connection state on the advertiser makes every failover an outage, which
dismantles the feature this project leads with.

**No single party can see both sides.** An MSP running one control plane can allocate
across all its networks. A technician joined to forty *customers'* independently
operated control planes cannot: those deployments do not know about each other and
never will. The only thing that can see both memberships is the device holding them.

## Decision

**The device allocates the mapped range, and the device performs the translation, per
membership, on its own interface.**

Concretely, when a device holds two memberships whose route groups carry an identical
prefix:

1. **The device allocates a mapped range for each colliding membership**, from a
   block reserved for this purpose inside its own address space. The allocation is
   device-local state, like the collision registry in PR #70, and it is stable for the
   life of the membership so a mapped address does not move under a running
   connection.

2. **Each membership already has its own interface.** `device_network_memberships`
   carries `interface_name`, and the reconciler is constructed per membership. This
   is what makes the rest work: after translation the destination is `192.168.1.5` on
   both interfaces, and it is unambiguous because each interface has exactly one peer
   holding that prefix in its allowed IPs.

3. **The routing table carries the mapped ranges, not the customer's.**
   `100.71.5.0/24` goes to `meshp0`, `100.71.6.0/24` to `meshp1`. The table holds two
   distinct prefixes, so there is nothing to contest.

4. **Translation happens on the way into the tunnel, after the interface is chosen.**
   The destination is rewritten from the mapped address to the customer's real one as
   the packet leaves for that membership's interface, and back on the reply. Source
   addresses are never touched.

5. **Names resolve to mapped addresses.** `fileserver.customer-a` resolves to
   `100.71.5.5`. The mapped range is an implementation detail a person should never
   have to type.

The packet that crosses the tunnel is therefore an ordinary packet: real source, real
destination. The advertiser forwards it without knowing any of this happened, and the
customer's server sees the technician's own mesh address, which is what ADR-0007
needs and what an audit log should show.

## Consequences

**The technician gets what ADR-0004 promised.** One agent, forty customers, and
`ssh fileserver.customer-a` reaches customer A even though customer B uses the same
addresses. That claim has been in ADR-0004 since the beginning and has never been
true when prefixes collide.

**This is not usable until DNS exists.** Without names, a technician has to know that
customer A is `100.71.5.0/24` this week — which is worse than the current refusal,
because it is the same cognitive load as remembering which customer is which *plus* a
layer of indirection. The mechanism can be built and tested before DNS; it should not
be presented to a user before it. That makes DNS a hard prerequisite for shipping this
rather than a nice pairing, and it is the main cost of this decision.

**It needs address translation on every platform that supports multi-network
membership.** On Linux that is nftables, which is already a dependency for policy and
for the egress kill switch. Elsewhere it is not written yet, and a host that cannot
translate must report the colliding groups unhonoured exactly as it does today rather
than carry one of them. The failure mode stays the honest one.

**The mapped block is a new reservation in the device's address space**, and it must
not collide with anything either — including the mesh addresses of the networks the
device is in, and whatever the local LAN uses. Choosing it badly recreates this
problem one level up.

**Two devices will disagree about which range means which customer**, because each
allocates its own. That is correct and worth stating plainly: a mapped address is
meaningful only on the device that minted it, and it must never appear in a control
plane, an audit log or a support ticket as though it identified something globally.
Anything that renders one for a person has to say which device it is relative to.

**Diagnostics get harder.** `meshp status` and `meshp doctor` will show addresses that
appear nowhere in the customer's own network, and a packet capture on the advertiser
will show the customer's real addresses rather than the ones the technician typed.
Both commands have to explain the mapping rather than print it, or this becomes a
feature that works and cannot be debugged.

## Alternatives considered

**Translate at the advertiser.** The branch router rewrites `100.71.5.0/24` into
`192.168.1.0/24` on the way in and back on the way out. Attractive because the
technician's device needs nothing special.

Rejected on two counts, either of which is sufficient. It puts per-connection state on
the advertiser, so failing over to a second advertiser drops every connection through
it — undoing the feature route groups exist to provide. And the reply path requires
the advertiser to source-NAT, so the customer's server sees the advertiser rather than
the technician, which destroys the input ADR-0007's destination-side enforcement runs
on and flattens every audit trail to one address.

**Let the control plane allocate the mapped ranges.** Tidier: IPAM already exists,
allocation is already a server-side concern, and the mapping could be sent as desired
state. It works for a single MSP running one control plane over many customer
networks — which is a real and important case.

Rejected because it does not work for the other one, and the other one is ADR-0004's
headline. A technician joined to forty customers' own control planes has forty parties
that cannot coordinate, do not know each other exists, and have no reason to. A
mechanism that works only when one organisation owns every network is a different
product. The device-side allocation covers both cases; the server-side allocation
covers one.

If that constraint disappeared — if every network a device joined were always
operated by the same control plane — server-side allocation would be the better
answer, and the ranges would be visible to operators, which would remove the
diagnostic cost above.

**Rewrite the source instead, and route by it.** `ip rule from <mapped source> lookup
<table>` disambiguates without touching the destination. Rejected for the reason
ADR-0019 gives for the same shape: the kernel picks a source address by looking up the
route, which is the question being asked. It works only if the application binds
first, which is a workaround a person has to know rather than a product.

**Ask the customer to renumber.** Free to build, and the honest reason it is here is
that it is what every competitor implicitly requires. Rejected because it is not a
decision an MSP can make: a technician cannot ask forty customers to renumber their
LANs because of a tool the technician chose, and the customer whose network is
`192.168.1.0/24` is the most common customer there is.

**Leave it refused, as PR #70 does.** The current behaviour, and correct as an interim
— a device that says it cannot reach either customer is better than one that quietly
reaches the wrong one. Rejected as an end state: it means ADR-0004's central claim is
false for exactly the users ADR-0004 was written for.
