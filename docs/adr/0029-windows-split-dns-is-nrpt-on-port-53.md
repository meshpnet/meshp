# ADR-0029: Windows split DNS is NRPT, and the resolver moves to port 53 there

- **Status:** accepted
- **Date:** 2026-08-30

## Context

ADR-0021 says only meshp's own names come to meshp: a resolver that captured every query
would break split-horizon corporate DNS on the first laptop that joined, and would make meshp
answerable for a user's entire name resolution — a much larger promise than the one being
made. `internal/resolved` implements that on Linux through systemd-resolved and on macOS
through the SystemConfiguration store, and reports honestly everywhere else.

Windows now has a tunnel (#175) and no names. This is the record of what it takes to give it
some, and it is longer than it looked, because the design meshp uses everywhere else does not
transfer.

**meshp's resolver listens on a high port.** `cmd/meshpd` binds `127.0.0.1:0` and lets the
kernel choose, because 53 is usually taken and binding it needs privilege the agent would
rather not depend on. Linux and macOS can both be told about a port: macOS carries one in the
same dictionary as the server address, which is why #153 was straightforward. The comment
that shipped with it said this would not be true everywhere and was worth checking before
somebody assumed it. Somebody assumed it.

## What Windows actually does

Established on `windows-latest` — Windows Server 2025, build 10.0.26100 — with a throwaway
workflow that is not kept. Four runs, because the first three each answered a different
question badly.

**NRPT does per-namespace routing, and it works.** A rule for `.control.meshp.test` naming
`127.0.0.1`, and a query for a name in that namespace arrived at a listener on
`127.0.0.1:53`. This is the mechanism, and it is the only one on this platform: interface DNS
— which is what `winipcfg.SetDNS` writes — sets nameservers and a search list on an adapter,
and Windows then chooses servers by interface metric rather than by domain. That is the
capture-everything behaviour ADR-0021 refuses.

**A rule is meshp's own and comes off cleanly.** Each lives under a GUID of its own at
`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{…}`, and removing
it leaves nothing behind. Nothing of anybody else's is read, merged or rewritten — the same
answer macOS's per-service key gives, and a stronger one than `resolvectl revert`, which
restores previous state rather than never disturbing any.

**A port in the nameserver is accepted and silently discarded.**
`Add-DnsClientNrptRule -NameServers "127.0.0.1:15353"` succeeded. Reading the rule back shows
its nameserver list **empty**. No query arrived. So the failure is not a refusal — it is a
rule that matches the namespace, names no server, and black-holes it, reported as success.

**A loopback address that is not 127.0.0.1 is bindable and not reachable.** A rule naming
`127.0.0.2` stored correctly and a listener bound `127.0.0.2:53`, and no query arrived. This
one was going to be the design: give meshp's resolver an address of its own so it need not
compete for `127.0.0.1:53`. A successful `bind()` proves a socket opened, not that anything
will be delivered to it.

**Windows reserves blocks of high ports.** `127.0.0.1:5353` was refused outright with
`ERROR_ACCESS_DENIED` — WinNAT and Hyper-V take ranges. Even had a port been honoured, asking
the kernel for any free one would fail unpredictably on machines that run either.

## Decision

**Split DNS on Windows is NRPT**, one rule per mesh domain, each removed by deleting the rule
that created it.

**meshp's resolver binds `127.0.0.1:53` on Windows**, rather than a port of the kernel's
choosing. Nothing else is expressible: the only nameserver Windows honoured is a plain
`127.0.0.1`, on the port it assumes.

**A resolver that cannot get port 53 reports that names will not resolve**, and the agent
carries on without them. That is what ADR-0021 already requires of a host whose resolver
meshp cannot configure safely, and it is the honest answer when something else on the machine
holds 53 — Docker Desktop and WSL both can.

## Consequences

**`dns.Server` gains a platform-dependent bind address**, which it did not have. The change is
confined to where `cmd/meshpd` chooses `dnsListenAddr`; the server itself does not care what
it is given.

**Windows is the first platform where meshp competes for a well-known port.** On Linux and
macOS the agent takes a high port precisely to avoid that fight. This is a real regression in
robustness on one platform, accepted because the alternative is no names at all there, and
because it fails loudly — a bind error at start-up, reported in `meshp status` — rather than
quietly.

**A rule with no nameserver is worse than no rule.** Windows will accept one and black-hole
the namespace, so what is written must be read back and checked rather than trusted to the
call's return value. This is the second time on this platform that a call reported success
having done nothing; the first was `route(8)` on macOS, and the lesson is the same one.

**Nothing here needs `winipcfg`.** NRPT is registry work and the dependency added in #175 does
not expose it, so this reaches for `golang.org/x/sys/windows/registry` instead.

## Alternatives considered

**Interface DNS through `winipcfg.SetDNS`.** One call, already available, and what WireGuard
for Windows uses. Rejected because it is not split DNS: Windows picks servers by interface
metric, so a tunnel adapter with a nameserver on it takes queries for names that have nothing
to do with meshp. WireGuard for Windows can accept that because it also blocks untunnelled
DNS outright; meshp's promise is the opposite one.

**Give the resolver its own loopback address.** Rejected on evidence: `127.0.0.2` was bindable
and queries did not arrive. Worth recording as tried, because it is the obvious idea and the
obvious idea does not work.

**Run the resolver on 53 on the tunnel adapter's own address** rather than loopback. Not
rejected — untested. It may avoid the competition for `127.0.0.1:53` entirely, and it is the
first thing to try if holding 53 on loopback turns out to be a problem in practice. It was not
tested because the tunnel's address is assigned by the control plane and the probe had no
network to get one from.

**Do not implement DNS on Windows.** What ships today, and honest: names answer to a direct
query and `meshp status` says so. Rejected because the mechanism has a real undo, which is the
bar ADR-0021 sets, and clearing it while declining to build is choosing less capability for no
property gained.
