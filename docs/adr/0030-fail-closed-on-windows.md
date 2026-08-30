# ADR-0030: Fail-closed egress on Windows is meshp's own WFP layer

- **Status:** accepted
- **Date:** 2026-08-30

## Context

Windows has a tunnel (#175), names (#178) and a full-tunnel default route (#180). What it does
not have is ADR-0011's lock: a device claiming a default route through meshp must refuse
traffic when the tunnel drops rather than putting the user's real address back on the wire.

This is the last slice of the Windows data plane and the same shape the other two platforms
took — ADR-0026 for macOS, and nftables for Linux before it. The question is the same one:
what mechanism, and is there a real undo.

## Why not Windows Firewall

The obvious answer, and it cannot express the policy.

Windows Firewall resolves conflicts by precedence, and an explicit block beats an explicit
allow. So the shape every other platform uses — refuse everything, then permit the tunnel, the
relay, the control plane and the local network — inverts: the blanket block wins over each
permit and the machine has no network at all.

The alternative is to set the profile's default outbound action to Block and add allow rules
underneath. That works, and it is a machine-wide setting belonging to whoever configured this
computer. Undoing it means putting back the value that was there before, which means having
kept a copy of somebody else's configuration and hoping it is still current — the argument
that ruled out `/etc/resolv.conf` in ADR-0021 and `/etc/pf.conf` in ADR-0026, arriving a third
time.

## Why the Windows Filtering Platform

WFP is what the firewall is built on, and it gives what the firewall's rule language does not:
**sublayers with weights**, so a permit at a higher weight genuinely beats a block at a lower
one, which is how "refuse everything except these" is expressed at all on this platform.

It also gives the cleanest undo of the three platforms. Every object belongs to a **provider**,
identified by a GUID its author chooses. meshp registers one of its own; everything it adds
hangs beneath it; removing meshp's provider and sublayer takes meshp's filters and nothing
else. Where macOS needed an anchor nested in Apple's namespace and Linux needs a table nobody
else happens to have named the same, this is a namespace the platform hands out on purpose.

## Why not the implementation that already exists

`golang.zx2c4.com/wireguard/windows/tunnel/firewall` does this, is MIT-licensed, and is
already in this repository's module graph as of #175. It cannot be used, for a reason that is
not a matter of taste.

**It opens a dynamic session.** `FWPM_SESSION_FLAG_DYNAMIC` means every object added is
deleted automatically when the process that added it exits. That is the exact inverse of what
ADR-0011 requires: the lock survives the daemon on purpose, because agent crash and agent kill
are two of the cases the feature exists to cover. A lock that vanished with the process would
fail open at precisely the moment it is needed.

**It generates a fresh provider GUID per session.** Sensible for objects that die with the
process, and fatal for objects that outlive it: a restarted daemon would have no way to find
what its predecessor installed, which is the other half of Invariant 20.

Those are established by reading the source, not inferred.

## Decision

**meshp writes its own WFP layer**, `internal/wfp`, with a **stable provider GUID** and a
**non-dynamic session**.

**The struct and syscall definitions are derived from wireguard-windows's MIT-licensed
firewall package, with its copyright retained.** Not written from scratch: `FWPM_FILTER0` and
its relatives are nested structures with layouts that differ between 32- and 64-bit, and
getting one wrong is a memory-corruption bug rather than a logic bug. What is meshp's is the
policy — which filters, at which layers, with what lifetime — and that is where this diverges
from the code it borrows from.

## The claim this rests on, which is not yet established

meshp wants a lock that **outlives the process and does not outlive the boot**. That is what
nftables gives on Linux and what a pf anchor gives on macOS: a reboot is a recovery path on
both, and a machine that comes up without meshpd comes up with networking.

WFP offers two documented lifetimes — dynamic, which ends with the session, and persistent,
which survives a reboot. The middle, a non-dynamic session with non-persistent objects, is
documented to survive the process and be lost when the filter engine restarts. **That is the
behaviour this design depends on and it has not been verified here.**

Verifying it costs writing most of the syscall layer, because there is no way to add a WFP
filter from PowerShell and `golang.org/x/sys/windows` does not expose the engine. A throwaway
probe would be the implementation with its policy removed, and would be thrown away.

So it is the implementation's first test rather than this record's finding, and this ADR is
weaker than ADR-0026 for exactly that reason. ADR-0026 could say "established on macOS 26.5,
not inferred" because ten minutes of `pfctl` answered it. This one cannot, and pretending
otherwise would be worse than saying so.

**If it turns out non-dynamic objects do not survive the process**, the design changes rather
than the schedule: persistent objects with a reclaim at start-up, and a documented divergence
from the other platforms about what a reboot does.

## Consequences

**A reboot may stop being a recovery path on this platform.** If persistent objects turn out
to be necessary, a machine that reboots without meshpd starting comes up with no network and
`meshp doctor` is the only way back. Linux and macOS both recover on their own. That would be
a real divergence and it belongs in `docs/troubleshooting.md` rather than in a comment.

**meshp gains a syscall surface it has to maintain.** Every other platform's lock is a program
meshp runs — `nft`, `pfctl` — whose interface is stable and whose failures are text. This one
is structures passed to a kernel API, where a wrong offset is a crash rather than an error
message. The tests have to be behavioural for that reason: a filter that was added is not the
same as a packet that was refused.

**The CI job has to prove the lock without stranding the runner.** The macOS test carved out
everything except TEST-NET-1 and asked pf's own counters what happened. The same shape works
here and WFP has per-filter statistics.

## Alternatives considered

**Fork wireguard-windows's firewall package and change the session flag.** Tempting and
rejected: the package's structure follows from its lifetime choice — a package-level session
handle, base objects generated per enable, no way to find yesterday's objects — so changing
the flag alone produces filters nothing can remove. The parts worth taking are the type
definitions, and those are taken.

**Windows Firewall with a Block default outbound action.** Covered above: it works and its
undo is somebody else's setting.

**Do not fail closed on Windows.** What ships today, and honest: the group is reported
unhonoured and nobody is misled. Rejected for the reason ADR-0026 gives — the mechanism has a
real undo, which is the bar this project sets, and declining after finding one is choosing
less capability for no property gained.
