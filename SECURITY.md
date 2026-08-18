# Security

## Reporting a vulnerability

Report privately, through [GitHub's private vulnerability reporting][report] on this
repository. Do not open a public issue.

[report]: https://github.com/meshpnet/meshp/security/advisories/new

That link works: private reporting is enabled, so the form is there rather than described.
If it ever stops working, that is itself worth reporting — by any means you can find.

## What to expect

meshp is maintained by one person. These are what that person can actually meet, not what
reads well:

| | |
|---|---|
| Acknowledgement | within 3 working days |
| An initial assessment | within 10 working days |
| A fix, or a plan with dates | within 30 days for anything exploitable |

If a deadline is going to be missed you will be told before it passes, not after.

## Scope

In scope: the agent (`meshpd`), the control plane (`meshp-control`), the relay
(`meshp-relay`), the command line (`meshp`), and the protocol between them.

Out of scope: anything you deploy meshp on top of, and the deployment examples under
`deploy/`, which are illustrative and say so.

**Read this before you spend time on it.** meshp is pre-alpha and the README says not to
deploy it. The data plane is Linux-only. Reports are still welcome and will be handled as
above — but a finding that a half-built feature is half-built is not one, and there are
several of those in the open issues already.

## What is not a vulnerability here

Three behaviours look like faults and are the product working as designed. Each has a
decision record explaining why.

**A device refusing traffic after its tunnel drops.** A full tunnel claims the default route
and installs a fail-closed lock, so a device that loses its tunnel stops passing traffic
rather than putting the user's real address back on the wire. ADR-0011 is explicit that
support tickets from people whose network broke this way are expected, and that the error
message is the product. `meshp doctor` explains it and how to undo it by hand.

**Firewall rules surviving the agent being killed.** The same lock is deliberately system
state that outlives the process. A lock that disappeared when the daemon died would fail open
at precisely the moment it is needed, which is what it exists to prevent.

**A name refusing to resolve when it is ambiguous.** A device in two networks that both have
a `fileserver` is told to say which one it means, rather than being sent to whichever sorted
first (ADR-0021). Being refused is the safe answer; being sent to another customer's machine
is not.

If you think one of these is wrong in a specific case, that is worth reporting — the
behaviours are deliberate, not beyond question.

## Disclosure

Coordinated. A fix, then a GitHub security advisory with a CVE where one is warranted, then
disclosure. 90 days from the report by default, sooner where a fix is out and users have had
a chance to take it, later only by agreement with you.

You will be credited in the advisory unless you would rather not be. Say so and you will not
be.

## Signing and provenance

Releases are built by the `release` workflow from a tag, and every GitHub Action in this
repository is pinned to a commit SHA rather than a tag — a tag is a movable reference, and
this project's CI holds a token that can read it. Artefact signing is not in place yet; when
it is, it will be documented here.
