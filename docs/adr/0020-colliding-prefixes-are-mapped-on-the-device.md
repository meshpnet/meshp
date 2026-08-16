# ADR-0020: Colliding prefixes are mapped, by the control plane that can see them

- **Status:** accepted
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

**The control plane allocates the mapped range where it can see the collision. The
device performs the translation, per membership, on its own interface.**

Those are separate choices and only the first one was ever in doubt. Translation
happens on the device in every design considered here; the question was who picks the
numbers.

Concretely, when a device holds two memberships whose route groups carry an identical
prefix:

1. **The control plane allocates a mapped range for each colliding membership**, from
   a block reserved for this purpose, and sends it as desired state. It can do this
   because one control plane sees every membership of a device it knows —
   `devices.identity_public_key` is unique and memberships hang off the device row —
   so the collision is visible to it, and IPAM already exists to allocate from.

   Where no single control plane can see both memberships, the collision stays
   **refused**, exactly as PR #70 leaves it today. That is the case of a contractor
   joined to several organisations' independently operated deployments, and it is
   deliberately not solved here: see the alternatives.

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

**Mapped ranges are visible to the operator**, because the control plane chose them.
They can be shown in the UI beside the route group, quoted in a support ticket, and
correlated across the devices of one deployment. This is the main thing gained by
moving allocation off the device, and it is worth the narrower coverage: a mapped
address that means something different on every laptop is a diagnostic that costs more
than it gives.

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

**Let the device allocate the mapped ranges.** Strictly more general: it covers the
contractor joined to several organisations' independent deployments, which the chosen
design refuses. The device is the only party that can see both memberships in that
case, so nothing else can work there.

Not chosen, and this is the amendment worth recording. The general case is not the
case this product is for. meshp's positioning is MSP-first: an MSP runs one control
plane across its customers' networks, and a technician's memberships all live on it.
Paying for the rarer case means every mapped address becomes device-local — meaningful
only on the laptop that minted it, absent from the control plane, useless in a support
ticket — and that cost lands on the common case to serve the uncommon one.

So the general mechanism is deferred rather than rejected. It is additive: a device
that finds a collision no control plane has resolved can allocate one itself later,
under a flag, without changing anything decided here. Until then that case keeps the
honest refusal from PR #70, which is a worse experience and not a wrong answer.

If the positioning changed — if independent-deployment contractors became a served
audience — this is the first thing to revisit.

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
