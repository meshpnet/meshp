# ADR-0026: Fail-closed egress on macOS lives in a pf anchor under `com.apple`

- **Status:** accepted
- **Date:** 2026-08-26

## Context

macOS has a tunnel (#152), names (#153) and a full-tunnel default route (#166). What it
does not have is ADR-0011's lock: a device claiming a default route through meshp must
refuse traffic when the tunnel drops rather than putting the user's real address back on the
wire. Until it does, a macOS laptop cannot be given a full tunnel on any network whose policy
requires failing closed.

The Linux lock is an nftables table meshp owns outright. macOS has `pf`, which is not the
same shape: one main ruleset, shared by everything on the machine, with rules organised into
*anchors*. An anchor's rules are only evaluated if the main ruleset references it, and the
main ruleset is exactly the kind of shared mutable state `internal/resolved` refuses to touch
— the rule that decided macOS gets a DNS implementation is "is there a real undo", and
editing a file the operating system also owns does not have one.

#153 answered that question for the resolver by finding a per-service key nobody else reads.
This record answers it for `pf`.

## What macOS actually does

Established on macOS 26.5 with root, not inferred. The probe is not kept — what it proved is
below, and re-running it is a morning's work if any of this is ever in doubt.

**The main ruleset references exactly one anchor point.** `/etc/pf.conf` as shipped contains
`anchor "com.apple/*"` and nothing else that a third party could load into. Apple's own
anchor file nests `200.AirDrop/*` and `250.ApplicationFirewall/*` beneath it.

**pf is disabled until something enables it**, and enabling is reference counted. `pfctl -E`
returns a token; `pfctl -X <token>` releases it, and pf stays on until the last holder lets
go. So meshp turning pf on cannot turn it off underneath the application firewall, and vice
versa.

**An anchor nobody references is loaded and never evaluated.** Rules put in a top-level
`meshp` anchor sat at `Evaluations: 0` while the traffic they claimed to block flowed
normally. This is the finding that rules out the obvious approach: meshp cannot simply have
an anchor of its own.

**An anchor nested under `com.apple/*` is evaluated.** The same rule in `com.apple/meshp`
reached `Evaluations: 33, Packets: 3` and dropped what it said it would.

**A main-ruleset reload does not remove it.** After `pfctl -f /etc/pf.conf`, the rule was
still in place and still nested. This was the finding expected to disqualify `pf` entirely:
a lock any other program could remove by reloading the ruleset — which pfctl's own warning
suggests happens — would not be a lock. It survives.

**Both halves of it can be seen from userland.** `pfctl -s rules` reports `anchor
"com.apple/*"`, and `pfctl -a com.apple -s Anchors` lists what is nested there. meshp can
therefore check that its rules are somewhere they will be evaluated, rather than assuming it.

## Decision

The lock is a `pf` anchor at **`com.apple/meshp`**, loaded with `pfctl -a com.apple/meshp -f
-`, removed with `pfctl -a com.apple/meshp -F rules`, and pf is enabled and released with
`pfctl -E` / `-X` so the reference count is respected.

`/etc/pf.conf` is never written, never parsed and never reloaded by meshp. Nothing of
Apple's is read, merged or rewritten. Removing meshp's anchor leaves the machine's packet
filtering exactly as it would have been.

**Before the lock is trusted, it is verified.** On every application meshp confirms that the
main ruleset still contains an anchor point covering `com.apple/*`. If it does not, the lock
is not installed and the route group is reported unhonoured — the same answer a Linux host
with no nftables gives.

## The risk this accepts, and why the verification is the whole of it

`com.apple` is Apple's namespace and meshp has no business in it. It is used because it is
the only anchor point the shipped ruleset references, and the alternative — adding
`anchor "meshp/*"` to `/etc/pf.conf` — is editing a file a system update replaces, with no
way to put it back that does not involve having kept a copy.

The failure that matters is not that this is impolite. It is that a future macOS could rename
the anchor point, drop the wildcard, or stop loading `com.apple` from a file, and meshp's
rules would go on being *loaded* while quietly no longer being *evaluated*. A lock that has
silently stopped locking is worse than no lock, because the device goes on reporting that it
fails closed.

That is why the verification is not a nicety. It converts a silent fail-open into the state
this system already knows how to express: a device that says it cannot enforce what was asked
of it. ADR-0011 accepts support tickets from people whose network broke; it does not accept a
device claiming a property it does not have.

## Consequences

**macOS reaches parity for full-tunnel egress**, and a laptop can be given a fail-closed
route group.

**meshp becomes a pf user on a machine that may have others.** The reference-counted enable
is what makes that safe, and it must be used rather than `pfctl -e`, which does not count.

**A macOS update is now something to test after.** The verification means a change in Apple's
anchor arrangement surfaces as devices reporting `egress` unapplied rather than as a leak,
but somebody still has to notice and fix it. This belongs with the sleep-and-roaming testing
in #160, which is the other thing about macOS that no CI runner can tell us.

**The lock outlives the process, as on Linux.** ADR-0011 requires it: a lock that vanished
when the daemon died would fail open exactly when it is needed. On macOS that now sits
alongside a tunnel that *does* die with the process (#152), so a killed daemon leaves a
machine refusing traffic with no tunnel to carry it — which is the safe direction and is
exactly what `meshp doctor` exists to explain. It will need the `pfctl` commands, taken from
the platform that installed them, as the routing half already does.

## Alternatives considered

**Add `anchor "meshp/*"` to `/etc/pf.conf`.** What most third-party VPN software on macOS
does. It gives meshp a namespace of its own rather than squatting in Apple's, and the rules
are evaluated without depending on Apple's arrangement.

Rejected on the undo. The file is owned by the operating system and replaced by updates;
putting a line in it means either keeping a copy of somebody else's file to restore, or
leaving the line behind forever. `internal/resolved` refuses `/etc/resolv.conf` on precisely
this argument and it would be incoherent to accept it here. It also fails the verification
test in the other direction: a system update that replaced the file would remove meshp's
anchor point *and* meshp's ability to notice, since it would be looking for something it had
written itself.

**Use NetworkExtension's `includeAllNetworks`.** The platform-sanctioned way to make a VPN
refuse non-tunnel traffic, implemented by the system rather than by a firewall rule, and it
does not touch pf at all.

Rejected for this slice because it is not a change to the lock — it is a change to what meshp
*is* on macOS. `includeAllNetworks` belongs to a `NEPacketTunnelProvider`, which means an app
bundle, a Network Extension entitlement, and Apple's approval; ADR-0010 records that
entitlement as a multi-week lead time and is the reason the mobile clients wrap the official
libraries rather than porting the data plane. meshp on macOS today is a daemon that opens a
utun. Becoming a network extension is a distribution decision with its own record to write,
and it should not arrive disguised as a fail-closed feature.

If that decision is ever taken, this one is cleanly reversed: the pf anchor is removed and
nothing else changes.

**Do not fail closed on macOS.** Honest, and what ships today: the group is reported
unhonoured and nobody is misled. Rejected because the research found a mechanism with a real
undo, which is the bar this project set for the resolver and cleared here. Declining after
finding one would be choosing less capability for no property gained.
