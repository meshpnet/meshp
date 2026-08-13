# ADR-0015: Kernel WireGuard where it exists, userspace where it does not, and say which

- **Status:** accepted
- **Date:** 2026-08-13

## Context

meshp has to move packets on Linux, Windows, macOS, Android and iOS. Only Linux
has WireGuard in the kernel; the others need a userspace implementation, a
driver, or the platform's own tunnel provider (ADR-0010 covers mobile).

The two implementations differ by a large factor in throughput and CPU. On a
relay carrying customer traffic, or a laptop on battery, that is not a detail.
They also differ in how the interface comes into existence: a kernel device is
created over netlink, a userspace device is a process that owns a tun device and
listens on a unix socket.

What they do *not* differ in is configuration. `wgctrl` speaks netlink to kernel
devices and the UAPI socket to userspace ones behind one interface, so "set this
private key, these peers, these allowed IPs" is written once either way.

There is a third thing that must not be conflated with either, and routinely is.
WireGuard's `AllowedIPs` is a cryptokey routing table: it decides which peer a
packet is encrypted for, and which source addresses are accepted from a peer. It
is not a system route. The kernel still needs a route pointing at the interface
before it will hand a packet over at all. Both are required, they are set through
different mechanisms, and a configuration with one and not the other fails in a
way that looks like the other layer's fault.

## Decision

Prefer the kernel implementation. Fall back to userspace when it is unavailable.
Report which one is in use, always, in `meshp status` and in the agent's
heartbeat.

The reporting is part of the decision, not a nicety. A silent fallback turns
"why is this host a tenth the speed of that one" into an unanswerable question,
and the answer — a missing kernel module — is one an operator can act on in a
minute if told.

Configuration goes through `wgctrl` for both. Interface lifecycle — create,
address, route, destroy — is per-platform and behind an interface, so a platform
meshp does not support yet is a missing implementation rather than a change to
everything else.

Addresses and routes:

- A membership's own address is assigned as a host prefix (`/32`, `/128`), not
  as a prefix covering the pool. A wider local address creates a connected route
  for the whole pool, so traffic to any unassigned address in it would be sent
  into the tunnel and dropped there instead of failing immediately.
- Every peer gets an explicit route to its own addresses via the interface.
  Precise, and precisely removable.
- `AllowedIPs` for an ordinary peer is exactly its own addresses. Wider
  prefixes belong to route groups (ADR-0001), which the server marks
  explicitly; an agent never widens on its own initiative.

Two peers on one interface may never claim overlapping `AllowedIPs`. WireGuard
resolves a collision by giving the prefix to whichever peer was configured last
and silently taking it from the other, which produces a network where one device
is unreachable and nothing logged a reason. The agent treats an overlap as a
control-plane bug and refuses the whole update rather than applying half of it.

## Consequences

Two interface-lifecycle implementations per platform family instead of one, and
a fallback path that will be exercised rarely and so must be tested
deliberately rather than incidentally.

Performance becomes environment-dependent in a way we now have to explain.
Support conversations will include "which implementation is this host using",
which is why it is in `meshp status` from the start.

Refusing an overlapping update means a control-plane bug can stop an agent from
converging, rather than degrading it. That is the intended trade: an agent that
converges onto a broken configuration reports success, and the failure surfaces
weeks later as an unreachable device. The refusal is loud, attributable, and
carries the two peers that collided.

Host-prefix addressing means the mesh has no on-link subnet, so anything that
assumes "same subnet means directly reachable" — some service discovery, some
naive broadcast — will not work. That is a real limitation and it is the correct
one: reachability in a mesh is per-peer policy, not a property of the address.

The pure part of this — turn desired state plus observed state into an ordered
list of operations — is separated from the syscalls so it can be tested
exhaustively without privileges, on any platform. The platform layer is then
thin enough to be tested against a real interface without needing to enumerate
cases there.

## Alternatives considered

**Userspace everywhere, one code path.** Tailscale does this and it buys real
simplicity: identical behaviour on every platform, no module dependency, no
fallback to test. Rejected because the throughput cost is paid by the customer
on every byte, forever, and because Linux servers — relays, exit nodes, the
hosts most likely to carry aggregate traffic — are exactly where the kernel
implementation is available.

**Kernel only, Linux only, for now.** Simpler and faster to build, and it would
move a packet sooner. Rejected because the interface boundary is cheaper to
design now than to retrofit around a kernel-shaped assumption, and because a
container without the module is a completely ordinary place to run a control
plane.

**Shell out to `wg` and `ip`.** Fast to write and easy to debug by hand.
Rejected: it needs those binaries present at the right versions, it turns every
error into a string to be parsed, and it makes the privileged surface "whatever
the shell will run" instead of a fixed set of netlink operations.
