# ADR-0021: Names resolve on the device, from desired state

- **Status:** proposed
- **Date:** 2026-08-16

## Context

DNS is named in the first line of this project's own description and does not exist.
`internal/dns` is an empty directory. What does exist is scattered and was designed
by people who had not yet had to make it work together:

- **On the wire**, `DnsConfig` carries `nameservers`, `search_domains`, per-domain
  `routes` and `prevent_leaks`. Nothing server-side has ever set it. The agent folds
  it into its peer set and reads exactly one field — `prevent_leaks`, for the egress
  kill switch.
- **In the schema**, `dns_zones` has an `is_split` flag ("queries for this zone go to
  meshp, everything else falls through to the system resolver") and `dns_records`
  holds A, AAAA and CNAME with a `managed_by` of `admin`, `device` or `service`. So
  an administrator was always meant to be able to write records by hand, alongside
  the ones derived from devices.
- **`Peer.device_name` is marked "display only"** on the wire, and `devices.name` has
  no uniqueness constraint and no validation.
- **The egress kill switch already permits loopback unconditionally**, and its comment
  names "a local resolver" among the things it must not break.

Three things force the decisions below.

**Resolution cannot depend on the control plane being up.** The moment somebody most
needs `ssh fileserver` to work is the moment something is broken, and the control
plane is a thing that can be broken. Every other part of this system is built so that
an agent keeps working from the state it last applied (ADR-0008); a name service that
queried the server would make DNS the one subsystem that fails when the server does.

**A device is in many networks at once (ADR-0004).** Two customers both have a machine
called `fileserver`. A bare `fileserver` typed by a technician is ambiguous, and it is
ambiguous in exactly the way an overlapping `192.168.1.0/24` is — the information
needed to resolve it is not in the query.

**Administrators write records the device cannot derive.** A CNAME for `git`, an A
record for something that is not a meshp device at all. Those are desired state; they
cannot be synthesised from a peer list.

## Decision

### 1. The agent resolves, from state it already holds

`meshpd` runs a resolver listening on loopback. It answers from the desired state it
has already applied — the peer list it uses to configure WireGuard is the same data
that answers an A query — and it keeps answering when the control plane is
unreachable, the same way the tunnel keeps carrying traffic.

`DnsConfig.nameservers` names that loopback address. The field is used for what it
says; the resolver it points at happens to be local.

### 2. Records are desired state, and travel with everything else

Admin-entered and service records are sent to the agent in `DnsConfig`, in a new
repeated `records` field, and are applied by the same reconciler that applies peers
and route groups. They are versioned, delta-compressed and acknowledged like anything
else (ADR-0008).

This is a proto change to the message the repository calls the most expensive thing to
change, and it is worth it: the alternative is a second, unversioned path by which
configuration reaches a device.

### 3. A name is `<device>.<network>.<suffix>`, and the suffix belongs to the operator

The default suffix is `internal`, giving `fileserver.acme.internal`. ICANN reserved
`.internal` for exactly this use, so it cannot be delegated out from under a
deployment.

An operator may set a domain they own instead. `.local` is not an option — RFC 6762
gives it to mDNS, and taking it breaks printer discovery on every machine that joins.
A `.meshp` TLD is not an option either: it is not ours, and squatting a namespace we
do not control is how a product acquires a migration it cannot schedule.

### 4. A bare name resolves only when it is unambiguous

`fileserver` resolves if exactly one of this device's memberships has a `fileserver`.
If two do, **it does not resolve**, and the error names both fully-qualified
alternatives.

There is deliberately no precedence order between memberships. An order would make the
query succeed and reach one customer, chosen by something the person typing had no
view of — which is the silent wrong answer PR #70 refuses for colliding prefixes, and
it should not be reintroduced one layer up because the layer is called DNS. A
technician who is told "`fileserver` is ambiguous: `fileserver.acme.internal` or
`fileserver.globex.internal`" has lost a keystroke. One who reaches the wrong
customer's file server has lost more than that.

Fully-qualified names always resolve, and are the answer when a bare one will not.

### 5. `device_name` stops being display-only

A resolvable name is load-bearing. It gets a syntax (an LDH label), uniqueness within
a network, and a rename path. Names that exist today and do not satisfy it must be
reported rather than silently mangled into something that resolves.

## Consequences

**Names work during a control-plane outage**, which is when they are wanted. They also
work on a device whose tunnel to the control plane is fine but whose route to it is
not, because nothing is queried across the network to answer them.

**The proto gains records, and the schema gains a reader.** `dns_zones` and
`dns_records` have sat unread since the first migration; this is what reads them. The
`managed_by` column was written for this — device-derived records are regenerated,
admin ones are not — so reconciliation has the discriminator it needs.

**Renaming a device becomes a user-visible event.** Today it is a label change. After
this it invalidates a name other people have in their shell history and their scripts,
so it needs to be deliberate, logged, and probably rate-limited.

**Uniqueness has to be enforced on names that already exist.** `devices.name` has no
constraint today, so a deployment may already hold two machines called `laptop` in one
network. The migration cannot silently rename one. It has to refuse, or quarantine,
and an operator has to choose — which is a worse upgrade experience than doing nothing
and the reason to do it before there are deployments rather than after.

**The agent now listens on a port.** Loopback only, but it is a new thing that can
fail to bind, a new thing to report in `meshp status`, and a new thing `meshp doctor`
has to explain when a machine can reach addresses but not names.

**Resolver configuration is per-platform and unpleasant.** systemd-resolved, plain
`/etc/resolv.conf`, `scutil` on macOS, the registry on Windows — each is a different
mechanism with a different failure mode, and several of them are shared mutable state
that other software also edits. A host that cannot configure its resolver must report
that it cannot, and leave the system's DNS alone, rather than writing a file it does
not know how to put back. This is where most of the work is, and it is the reason this
ADR does not promise every platform at once.

**Split DNS is not optional.** Only the mesh zones go to the mesh resolver; everything
else keeps using whatever the machine was already using. A resolver that captured all
queries would break split-horizon corporate DNS on the first laptop that joined, and
would make meshp responsible for the user's entire name resolution — which is a much
larger promise than the one being made.

**Bare-name refusal will surprise people.** Somebody with one network will use bare
names for months, join a second, and find that some of them stop working. The error
has to be good enough that the surprise is survivable, and this should be said plainly
in the documentation rather than discovered.

## Alternatives considered

**Serve DNS from the control plane over the tunnel.** `nameservers` points at a mesh
address the server answers on. Simpler agent, one place to change records, and
admin-entered records need no wire format at all.

Rejected because it makes name resolution depend on the control plane at query time.
That is the wrong dependency for this system specifically: ADR-0008 exists so agents
converge and then keep working, and a control-plane outage would take out names
everywhere at once — while somebody tries to `ssh` to the box that would let them fix
it. It also puts the control plane in a request path it is otherwise never in.

If that constraint disappeared — if the control plane were replicated to where it
could be treated as always-up — this would be the better answer, and it would remove
both the proto change and most of the reconciliation work.

**mDNS, or `.local`.** No server involvement, no records to distribute, and it is
what a small network would reach for. Rejected because RFC 6762 owns `.local` and
taking it breaks existing mDNS on the machine, because multicast does not cross the
tunnel, and because it answers only for hosts that are currently up — which is not
what a name is for.

**A precedence order for bare names**, by join time, or an administrator's ranking.
It is what `search` in `resolv.conf` does, so it would surprise nobody. Rejected for
the reason in Decision 4: it converts an ambiguous question into a confident wrong
answer, and this project has already decided, for prefixes, that it would rather say
it does not know. Doing the opposite here would mean the same collision behaves one
way for an address and another way for a name.

**One flat namespace with no network component** — `fileserver.internal` across every
membership. Fewer keystrokes and no ambiguity rule needed, because there is nothing to
disambiguate: the first network to claim a name owns it. Rejected because it makes two
customers' devices compete for names in a namespace neither of them can see, and
because the network component is what makes the fully-qualified escape hatch in
Decision 4 exist at all.

**Do nothing, and let people use addresses.** Which is today. Rejected because a mesh
address is allocated by IPAM and is not a thing a person can be expected to hold in
their head, and because every product this is compared against resolves names.
