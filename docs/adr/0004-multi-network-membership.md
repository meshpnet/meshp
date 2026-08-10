# ADR-0004: A device may hold memberships in several networks at once

- **Status:** accepted
- **Date:** 2026-08-10

## Context

The natural model is one device, one network: `devices.network_id`. Nearly every
comparable product does this.

It breaks the customer we are actually building for. A managed service provider's
technician supports forty customer networks, each with its own private address
space, often overlapping. Under a single-network model they need forty devices,
forty enrolments, or a jump host per customer — and switching networks means
disconnecting from the others.

Since the MSP layer is the commercial thesis and not a later add-on, the data
model has to support this before anything is built on top of it.

## Decision

`devices` holds identity and hardware facts. A separate
`device_network_memberships` row represents one device joining one network, and a
device may hold many active memberships simultaneously.

Each membership carries:

- its own local interface name, because overlapping customer LANs cannot share
  one routing table;
- its own addresses from that network's IPAM;
- its own WireGuard keypair. Reusing one public key across customer networks would
  let those customers correlate the device across their networks, so keys are
  per-membership, not per-device.

Revocation operates on a membership. Revoking a device revokes all of them.

## Consequences

An MSP technician runs one agent and reaches every customer they support, with
policy evaluated independently per network. This is a feature no competitor
offers and it falls out of the data model rather than being bolted on.

The costs are real. `meshpd` manages N interfaces rather than one, and N control
sessions. Overlapping prefixes across memberships mean the agent cannot install a
single flat route table and must use per-interface policy routing — on all three
desktop platforms, each with different mechanics. DNS gets harder too: two
memberships may both claim `*.internal`, so search-domain precedence must be
explicit and user-visible rather than accidental.

We also cannot assume a device has exactly one address in the UI, the CLI, or the
API, which touches almost every surface.

## Alternatives considered

**One network per device, with fast profile switching.** Much simpler, and the
agent stays single-interface. Rejected because "disconnect from customer A to look
at customer B" is precisely the workflow we are selling against.

**A jump host in each customer network.** Works today with no product changes,
which is exactly why MSPs already do it and why it is not a reason to buy
anything.
