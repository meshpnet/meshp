# What each platform can do

meshp has to move packets on Linux, Windows, macOS, Android and iOS (ADR-0015). Three of the
five do. This page is where that is written down, and it is the only place — the same claim
repeated across the README, the security policy and three guides went stale five times at a
time, which is what [#185](https://github.com/meshpnet/meshp/issues/185) is about.

<!-- BEGIN platform-table: derived from the build tags, see internal/docscheck -->
|  | Linux | macOS | Windows | Android | iOS |
|---|---|---|---|---|---|
| **A tunnel** — carries traffic at all | yes | yes | yes | no | no |
| **Names** — mesh names resolve, and only mesh names (ADR-0021) | yes | yes | yes | no | no |
| **A full-tunnel route** — everything can be sent through the tunnel | yes | yes | yes | no | no |
| **Fail-closed egress** — traffic is refused when the tunnel drops (ADR-0011) | yes | yes | yes | no | no |
| **A packet filter** — a network's policy is enforced on the device (ADR-0007) | yes | no | no | no | no |
| **Prompt recovery** — a change of network is noticed rather than waited out (#172) | yes | yes | yes | no | no |
<!-- END platform-table -->

That table is not maintained by hand. Each row is a package with an implementation per
platform and one stub for everywhere else, and the stub's build tag says which platforms have
it — a line the compiler already forces to be right, because an implementation that exists and
is not excluded there does not build. `internal/docscheck` reads those tags and fails if this
page disagrees.

## What a `no` costs

**A device with no tunnel still enrols**, holds an address, and reports honestly that it has
no tunnel rather than pretending. That is deliberate: a device that can be seen and named is
worth having before it can carry traffic.

**A capability a platform lacks makes a network's requirement unhonoured, not half-applied.**
A macOS or Windows device in a network with a packet-filter policy reports the route group
unconverged rather than accepting the policy and enforcing none of it — the dishonesty ADR-0007
and ADR-0011 are both written against.

## Why the same capability is a different mechanism on each

Nothing here is one implementation with three build tags. Each platform reaches the same
property by whatever it actually offers:

| | Linux | macOS | Windows |
|---|---|---|---|
| Tunnel | kernel WireGuard | `wireguard-go` on a utun | `wireguard-go` on WinTun (ADR-0028) |
| Names | systemd-resolved | the SystemConfiguration store | the Name Resolution Policy Table (ADR-0029) |
| Full tunnel | a firewall mark and a routing table | two routes beating a default | the same, through the IP Helper API |
| Fail closed | an nftables table | a `pf` anchor under `com.apple` (ADR-0026) | meshp's own filtering-platform provider (ADR-0030) |

The decision records are where the reasoning is. Each was written before its implementation,
and each turned on the same question: is there a real undo — can meshp remove what it
installed without keeping a copy of somebody else's configuration.

## The two that have nothing

Android and iOS. ADR-0010 records why they will wrap the official WireGuard libraries rather
than porting this data plane, and #144 records the part CI cannot help with: a
`NEPacketTunnelProvider` does not run in the Simulator, so the packet path there needs
hardware whatever else is arranged.
