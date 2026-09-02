# ADR-0032: The UI and the CLI are clients of the API, and parity is measured against it

- **Status:** accepted
- **Date:** 2026-09-02

## Context

The question keeps arriving as "should the web UI be able to do everything the logged-in CLI
can". It is the wrong comparison, and answering it in those terms would make one client the
specification for the other.

Where the three surfaces actually stand:

- **The API has 52 routes** — 21 GET, 14 POST, 11 DELETE, 6 PUT. Setting aside the device
  enrolment and session-challenge flows, which are machines talking rather than people, that
  is **26 administrative operations**: create a network, publish a policy, edit DNS, mint and
  revoke tokens, create and suspend users, bind and unbind roles, create route groups and
  their advertisers, steer failover, revoke a device, erase one.
- **The CLI implements seven commands**: `join`, `status`, `doctor`, `login`, `logout`, `up`,
  `down`. Its `--help` advertises ten nouns — `device`, `network`, `user`, `group`, `acl`,
  `dns`, `route-group`, `exit`, `relay`, `token` — carrying about thirty-seven verbs between
  them. **None of them is implemented.** Every one answers `"…" is not implemented yet`.
- **The page writes three things**: mint an enrolment token, revoke a device, forget a
  device. ADR-0022 §5 caps it at two by name; the third arrived with #218 and is already
  outside what that section describes.

So the CLI reaches none of the 26 and advertises that it reaches most of them; the page
reaches three. Neither number is a design, and the difference between the two is not the
interesting problem.

Three things decide what follows.

**The API is already the contract, and it has a third consumer.** ADR-0009 puts the core
under Apache 2.0 and requires the commercial layer to call the open control plane over its
HTTP API; ADR-0023 adds that shared surface cannot be reshaped freely once something depends
on it. The commercial layer is a client of the same routes the page and the CLI use. A rule
that made the CLI the reference would leave that third client describing itself against
something that is not the contract.

**ADR-0022 §5's limit was superseded in substance eleven days after it was written.** ADR-0024's
consequences say so directly: the read-only restriction existed only because there was
nothing to attach permissions to, "that is the moment the page can grow the write paths issue
#108 deliberately excluded, and §5 should be rewritten rather than amended a third time". The
rewrite happened for the credential and not for the limit, so a section describing a page
that reads is still carrying a sentence capping what it writes.

**§5 already recorded why enumerations go stale**, and then enumerated. Its own postmortem
is the best argument in this document:

> a section describing a credential in terms of the routes it reaches will go stale every
> time a route is added, and nobody weighs an amendment made to unblock a feature

That lesson was applied to the credential, one paragraph above a sentence that names two
write paths. "The page writes two things, and deliberately only two" is the same shape of
claim and has the same failure mode, and it went stale the first time a third was needed.

## Decision

### 1. Parity is measured against the API, and stated as a rule

**Every administrative capability the API exposes is reachable from the web UI and from the
CLI.** Not "the UI does what the CLI does" — both are clients, neither is the specification,
and the thing they are both measured against is the contract ADR-0009 already named.

A rule rather than a list, for the reason §5 learned the hard way. A list of what the page
may write goes stale on the next route; a rule does not, and a route that has no affordance
in either client is visibly a gap rather than an omission somebody has to notice.

This also gives the commercial layer the position it should have had: a third client of the
same contract, rather than a consumer of something the CLI happens to define.

### 2. What the rule does not cover, and why

**Device-local commands have no UI, because there is no device on the other side of a
browser.** `up`, `down`, `status` and `doctor` act on the machine they run on, through the
agent's local socket, and there is nothing for the control plane to render. They are not a
parity gap and must not be counted as one.

**Machine flows are not administrative capability.** `POST /api/v1/enroll`, the enrolment
challenge and the session challenge are how a device authenticates itself. They belong to
the agent and to `enrollclient`, and neither a person's browser nor their shell should have a
verb for them.

**Reads are not exempt, but they are cheaper to satisfy.** A CLI verb that prints what an
endpoint returns is a small thing; the rule covers reads so that `meshp audit` exists rather
than being a documented `curl`.

### 3. ADR-0022 §5's two-write limit is lifted; its argument is kept

That section says publishing a policy and editing DNS are "documents somebody composes rather
than buttons, and a form that got them subtly wrong would be worse than the command it
replaced".

**That is right about form shape and wrong as a reason not to build.** A checkbox matrix that
silently produces a policy nobody intended is the failure it describes. The conclusion is not
that the page stays out; it is that a document gets a document-shaped affordance:

- **The document itself, as text**, in an editor — not a form that reconstructs it. The
  thing an operator reviews is the thing that gets stored.
- **Parsed before it can be saved.** `acl.Parse` already exists and already rejects a
  malformed document; a page that cannot save an unparseable one is strictly ahead of a
  `curl` that can.
- **A diff against what is live**, so the change being made is visible as a change rather
  than as a new blob.
- **A dry-run before it takes effect.** `acl.Compile(doc, self, peers)` produces the packet
  filter a named device would actually enforce. Showing that — "publish this and this device
  stops being able to reach these" — is something the command line was never going to do,
  and the CLI's own advertised `acl test` verb is the same idea from the other side.

With those four, the page's version of publishing a policy is *safer* than the command it
replaces, which is the bar §5 was really setting.

### 4. The CLI stops advertising what it does not have

`--help` currently lists ten nouns and thirty-seven verbs and implements none of them. That
is worse than listing nothing: it is a promise the binary breaks the moment anybody takes it
up, and it makes the parity gap invisible by describing it as already closed.

**A verb appears in `--help` when it works.** Until then it is absent, and the roadmap lives
in issues and in this ADR where a roadmap belongs. A user who types `meshp device list` gets
`unknown command`, which is true, rather than `not implemented yet`, which is an apology for
a help text that should not have made the offer.

### 5. New capability arrives in every client at once

**An API capability lands with its CLI verb and its UI affordance in the same change.** This
is ADR-0018's rule — a mechanism is not done until something running reaches it — applied to
the clients rather than to the mechanism.

The existing gap is worked down deliberately rather than grandfathered: it is the reason
this ADR exists, and Decision 4 keeps it honest in the meantime. What this stops is the gap
*growing*, which is how it got to thirty-seven verbs in the first place — each one added to a
help text by somebody describing an intention.

### 6. Tests before a framework, and the framework question stays open

ADR-0022 §3 made the no-build-step decision expire on "a second view that needs to share
state with the first, or the day hand-written DOM updates start producing the bugs a
framework exists to prevent". Both halves have now been touched, and the answer is still not
a build step yet.

**The first half has fired.** What Decisions 1–3 describe is not one page: devices, networks,
users, tokens, roles, DNS, an ACL editor, route groups, the audit trail, and the topology
view the product needs. They share a network selection, a permission set and a poll.

**The second half has fired twice, and both were the same bug.** A node outlives the render
that built it, so a listener closes over something stale: once on the revoke button in #146,
and once when a *Forget* button was matched onto a *Revoke* node by position and kept its
click handler — a page that offered to erase a device and revoked it instead. Both were
caught by a person driving the page, which is exactly the thing that does not scale.

**And still: tests first.** Three reasons, in order of weight.

- **A framework migration with no tests is unverifiable.** The migration would be the largest
  single change this page has had, and there is nothing that would tell anybody it still
  works. Tests are the prerequisite for the decision, not an alternative to it.
- **A build step changes what `go build` means.** The page is embedded with `go:embed`
  (ADR-0022 §2). A toolchain that must run before `go build` means a clean checkout no longer
  produces a working binary, `go install ...@latest` produces one with a stale page or none,
  and both the CI job and the release job grow an ordering constraint. That is a larger
  commitment than the ADR that introduced the page anticipated, and it is separable from
  testing.
- **Dependencies are the artefact's supply chain.** The thing being served is the
  administrative interface of a security product, embedded in the same binary as the control
  plane, whose releases are not signed yet (#219). A lockfile of transitive dependencies
  inside that binary is a real cost, and it should be paid for a reason better than "the page
  got bigger".

So: **a Node toolchain enters CI for tests, and not for a build step.** `web/` stays
hand-written and embedded as written. This is the smaller decision ADR-0022's own #146 note
predicted — "an argument for *tests* rather than for a build step … one that should be taken
on its own rather than arriving attached to a feature" — and taking it is what makes the
larger one answerable.

**The new trigger, sharper than the old one.** Revisit when component-local state has to
survive a poll and the reconciler grows a lifecycle to hold it, or when the node-outlives-
render bug class reappears *after* tests exist to catch it. The first says the reconciler has
become a framework badly; the second says review and tests are both failing to hold the line.
Either is a real answer. "There are a lot of views now" is not.

### 7. Coverage is not the same as a good interface

The rule in Decision 1 can be satisfied by twenty-five forms, and that would be a worse
product than the page is today.

Parity is the floor. The standing requirement for the UI is a **visual view of the whole
network** — topology first, tables second — because the thing meshp does that nothing else
does is hold one device in several networks at once (ADR-0004), and that is a picture rather
than a row. A device in three customer networks with a separate key in each is legible as a
diagram and invisible as a table.

That requirement is not satisfied by this ADR and must not be crowded out by it. Per
ADR-0009 it belongs in the Apache core: only the cross-tenant roll-up is the commercial
layer's, and building the good visualisation in the closed repo would reverse that decision
without recording one.

## Consequences

**ADR-0022 §5's final write-path paragraph is superseded**, and §3's expiry condition is
replaced by the sharper trigger in Decision 6. The rest of ADR-0022 stands: one consistent
snapshot, embedded in the binary, polled, showing its own freshness, with a cookie that is a
person.

**The CLI's `--help` shrinks before it grows**, and that will look like a regression to
anybody reading the diff. It is the opposite: the binary stops describing a product that does
not exist.

**Every future API route costs more.** Three implementations rather than one, and the
temptation will be to skip the client work and record a gap. Decision 4 is what makes that
skipping visible — a capability with no verb is a capability nobody can see.

**The page acquires the first thing in this repository with no Go test**, and closing that is
now a prerequisite for the work rather than a follow-up. Until CI drives the page, every
change to it is verified by a person against `docs/testing/the-page.md`, which does not
survive a second contributor.

**The commercial layer gets a stable target.** Every capability is on the contract it already
depends on, rather than in one client and not another. That is also a constraint: ADR-0023
means these routes cannot then be reshaped freely, so the parity work is a commitment to the
API's current shape as much as an extension of its reach.

**A document-shaped editor is more work than a form.** Decision 3 asks for a diff and a
dry-run, not a textarea. A textarea with a save button would satisfy Decision 1 and would be
precisely the thing §5 was right to refuse.

## Alternatives considered

**Make the CLI the reference: the UI does whatever `meshp` can do.** It is the question as
usually asked, and it has an obvious appeal — the CLI is where an operator's muscle memory
is.

Rejected because it makes a client the specification. The target moves every time a verb is
added, the commercial layer is left describing itself against something that is not the
contract, and — today — it would set the bar at seven commands, six of which are device-local
and have no meaning in a browser.

**Keep the page small and put everything in the CLI.** A defensible product shape: the UI
answers "is anything broken", the CLI does the work, and the page stays the thing ADR-0022
describes.

Rejected because the audience is wrong. meshp is aimed first at people managing networks for
somebody else, and an MSP technician working across forty customers is not going to be issued
a terminal and a token per customer. It also contradicts the standing requirement in Decision
7: the differentiator is visual, and a small page cannot show it.

**Adopt a framework now, and build the tests against it.** Fewer total steps, no throwaway
work, and the bug class in Decision 6 disappears immediately rather than being caught twice
more.

Rejected on ordering rather than on merit, and this is the closest call in this document. A
migration with nothing to verify it is a migration nobody can review; the `go build` and
supply-chain costs are real and separable; and the reconciler has not yet failed at anything
tests would not have caught. If tests land and the second trigger fires anyway, this becomes
the answer and the work done in between is not wasted.

**Generate the CLI from the API's route table.** Parity by construction rather than by rule —
every route gets a verb because a generator emitted one.

Rejected because the mapping is not mechanical and pretending otherwise produces a bad CLI. A
good verb is not a route: `meshp exit use <name>` is a PUT to a failover endpoint with a
lookup in front of it, and `meshp acl edit` is an editor around a GET and a PUT. A generator
would produce `meshp networks-network-id-route-groups-slug-failover-put`, and the thing that
makes a command line worth using is exactly the part it cannot generate.
