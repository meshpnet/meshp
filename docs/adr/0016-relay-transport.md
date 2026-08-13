# ADR-0016: One relay port, multiplexed, with the agent carrying relayed packets

- **Status:** accepted
- **Date:** 2026-08-13

## Context

Two devices behind NAT cannot reach each other directly, and meshp is relay-first
(ADR-0002): a session starts on a relay and upgrades to a direct path if one can
be found. So the relay is not a fallback to be added later — it is how
connectivity works on the first day, and the shape of it decides the shape of the
agent.

The constraint that decides everything here is that a relay must not be able to
read what it forwards, and therefore cannot tell where a packet is going.
WireGuard's transport packets carry a receiver index chosen by the receiver, and
a handshake carries the initiator's static key encrypted. A forwarder that cannot
decrypt cannot demultiplex by destination. The destination has to be carried
outside the WireGuard packet, or implied by something the relay can see.

There is a second constraint. On Linux the data plane is the kernel's, and a
kernel WireGuard socket cannot be intercepted the way a userspace implementation
can — where Tailscale hands `wireguard-go` a fake endpoint and catches the
packets in process, we have no equivalent. Whatever we do has to work by giving
the kernel an address it is willing to send to.

## Decision

The relay listens on **one** UDP port for every agent and every network. Agents
identify themselves to it and prefix each forwarded packet with the public key it
is for. The relay keeps a map of public key to the address it last heard that key
from, and forwards.

The agent bridges the kernel to that protocol with a loopback socket per peer:

- Peer X's endpoint is `127.0.0.1:Px`, a port the agent owns.
- Outbound: the kernel sends a WireGuard packet to `127.0.0.1:Px`; the agent
  reads it there, prefixes X's key, and sends it to the relay.
- Inbound: the relay delivers a packet for X; the agent strips the key and writes
  the packet **from** `127.0.0.1:Px` to its own WireGuard listen port, so the
  kernel sees it arriving from exactly the endpoint it has configured for X.

The scarce resource becomes loopback ports on the device, of which there are
plenty, instead of ports on a shared relay, of which there are not.

Authorisation is a short-lived token issued by the control plane and verified by
the relay against a public key, so the relay holds no copy of the device
database. The token names the network. **The relay enforces "these two keys are
in the same network" and nothing more** — it does not evaluate ACLs, because ACLs
are enforced at the destination (ADR-0007) and a relay that also enforced them
would be a second implementation of the same policy, diverging quietly.

## Consequences

**An agent outage now interrupts relayed traffic.** This is the significant one.
Invariant 15 says a control-plane outage does not interrupt established
networking, and that still holds — but it held for a stronger reason than we
realised: the kernel carried packets whether meshpd was alive or not. On a
relayed path the agent is in the data path, so killing it stops traffic that a
direct path would have kept carrying. Two consequences follow: meshpd must be
supervised and restart quickly, and upgrading to a direct path is not a
performance nicety but a resilience one.

**Two extra userspace hops each way on relayed paths**, so relayed throughput
will be a fraction of direct throughput and will cost CPU on the device as well
as bandwidth on the relay. That is the price of working at all behind symmetric
NAT, and it is the argument for ICE being scheduled rather than aspirational.

**The MTU depends on the path.** A relayed packet carries the relay header
outside the WireGuard packet, so a tunnel MTU that fits a direct path may not fit
a relayed one, and the failure mode is fragmentation or silent loss for large
packets only — the worst kind to diagnose. The server already computes MTU and
sends it, so it must now know whether a peer is relayed and lower it accordingly.

**The relay learns metadata.** It cannot read traffic, but it sees which keys
talk to which, when, and how much. That is unavoidable for any relay and it
should be stated plainly rather than discovered by a customer: it is one more
reason to prefer a direct path, and a reason self-hosting the relay is a real
feature and not a checkbox.

**The relay is also the reflexive-address oracle.** It sees each agent's true
external UDP address and port, which is exactly the server-reflexive candidate
ICE needs, and exactly what cannot be inferred from the control channel's TCP
source address. Building the relay therefore delivers discovery as well as
connectivity, which is why it comes before endpoint distribution rather than
after.

**A relay restart does not invalidate anything the control plane has
distributed.** Endpoints are loopback addresses on the device; they do not change
when a relay process dies. The agent reconnects and traffic resumes. This is the
property that decided the choice.

## Alternatives considered

**A UDP port per peer-pair on the relay.** The relay allocates a port, the
endpoint is `relay:port`, and the kernel needs to know nothing at all — no
loopback socket, no agent in the data path, no new failure mode, and Invariant 15
keeps its stronger meaning. It is genuinely simpler and it was tempting.

Rejected for two reasons. Ports are a shared, exhaustible resource: a mesh where
many devices talk to many others consumes them per pair, and one relay serves
many customers. More decisively, the allocation is state that lives in the relay
— so a relay restart invalidates every endpoint it had handed out, every affected
peer needs a fresh state version, and a relay recovering from a crash triggers a
push to every device that was using it. Trading a small amount of agent
complexity for the absence of that failure is worth it.

**Demultiplexing by tracking handshake indices.** A relay could watch handshakes
and learn which sender index belongs to which pair, then forward transport
packets on one port without any header. Clever, and it needs no agent changes.
Rejected: it makes the relay stateful in a way that breaks on restart, it fails
for packets arriving before the handshake it depends on, and it couples a
forwarder to the details of the WireGuard protocol so that a future protocol
version could silently break relaying.

**TCP or TLS to the relay.** Necessary eventually for networks that block UDP
outright, and the multiplexed design accommodates it because the transport is now
ours to choose. Not in the first implementation, and noted here so that the
framing chosen for UDP does not make a stream transport awkward later.
