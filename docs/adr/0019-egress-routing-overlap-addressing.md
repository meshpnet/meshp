# ADR-0019: Egress is a routing problem; overlapping prefixes are an addressing one

- **Status:** accepted
- **Date:** 2026-08-15

## Context

Two pieces of open work were both filed as "needs policy routing", and the plan was
to design the mechanism once and let them share it.

**Egress (ADR-0011).** A device claims a default route through the tunnel. The
outer WireGuard packets to the relay are then captured by that same default route
and sent into the tunnel that is carrying them. The tunnel never establishes, and
because ADR-0011 requires the kill switch to be installed before the route is
claimed, the device is off the network with no way back short of a restart.

**Overlapping prefixes (ADR-0004).** A technician's laptop holds memberships in
forty customer networks. Two of them carry `192.168.1.0/24`, because two customers
both took the default their router shipped with. One flat routing table cannot hold
that prefix twice.

They look like the same shape — a destination that needs to be routed differently
depending on context — and they are not.

The egress case has the answer in the packet. A packet to the relay is
distinguishable from a packet to the internet, so a rule can be written that tells
them apart.

The overlapping case does not. A technician types `ssh 192.168.1.5`. Which
customer? The information needed to answer is not in the packet, was never in the
packet, and no routing rule can recover it — routing decides from what the packet
carries, and the packet does not say which network was meant. Any mechanism that
appears to solve this is really choosing one network and hiding it.

## Decision

**These are separate problems with separate mechanisms, and neither shares code
with the other.**

### Egress uses a firewall mark and policy routing

- WireGuard marks its own outer packets, via the device's firewall mark.
- An `ip rule` sends everything *without* that mark to a table whose default route
  is the tunnel.
- Marked packets fall through to the main table and follow whatever the real
  default route is.

The property that decides it: **nothing tracks the underlying gateway**, because
the main table already does. A device that moves from Wi-Fi to tethering rewrites
no meshp state at all — the mark still says "this is the tunnel's own traffic, send
it the ordinary way", and the ordinary way has already changed by itself.

This is what `wg-quick`'s automatic table does, and the reason is the same one.

### Overlapping prefixes are made distinct before routing sees them

Two identical destination prefixes cannot be told apart by a routing table, so they
must stop being identical. Each membership's colliding prefix gets its own mapped
address range, and the name layer resolves to the mapped address rather than to the
customer's own.

What that mapping looks like is not settled here. What is settled is that it is an
addressing and naming design, not a routing one, and that **task #3 should stop
being described as policy routing**.

## Consequences

The egress mechanism is bounded and can be built now. It needs a firewall mark on
the device, one routing table, and one rule — with the same teardown discipline the
kill switch already has, since a rule left behind sends traffic to a table whose
tunnel is gone.

The overlapping-prefix work is larger than it was filed as, and it is no longer a
prerequisite for anything. It needs a mapping scheme and a name layer to make the
mapping usable, which is a design of its own.

The uncomfortable consequence is about ADR-0004. That ADR says a technician "runs
one agent and reaches every customer they support", and calls it a feature no
competitor offers. That claim is still true for the ordinary case, and it is not
true today when two customers' prefixes collide: one membership's route wins, in
whatever order the table was written, and nothing says so. **Until the mapping
exists, a collision must be detected and reported as an unhonoured route group
rather than resolved silently.** A device that quietly reaches the wrong customer's
`192.168.1.5` is worse than one that says it cannot reach either, and it is the
kind of wrong that gets discovered by someone typing a command on the wrong
network.

## Alternatives considered

**One mechanism for both, keyed on source address.** `ip rule from <mesh address>
lookup <table>` genuinely disambiguates — if the application binds that source
address first. `ssh 192.168.1.5` does not; the kernel picks a source by looking up
the route, which is the question being asked. It works for `ssh -b 100.90.1.2`,
which is a workaround a person has to know, not a product.

**Host routes for each endpoint via the current gateway, for egress.** Simpler than
a mark: no table, no rule. Rejected because it has to be maintained as the
underlying network changes, so every roam becomes a race between discovering the new
gateway and the stale host routes pointing at the old one — on a laptop, which
roams constantly, while a kill switch is holding the line.

**A network namespace or VRF per membership.** Unambiguous, and it moves the
question to launch time: an application runs *in* customer A. Rejected for the
device this is for. A technician's laptop runs a browser and an editor that were
not started inside anything, and telling them to relaunch per customer is the
workflow ADR-0004 exists to remove.

**Pick one and move on, for collisions.** Which is what happens today by accident.
Kept as the interim behaviour because there is nothing else to do yet, and rejected
as a design: the requirement above is that it be reported, not that it be silent.
