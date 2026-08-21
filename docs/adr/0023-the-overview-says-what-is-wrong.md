# ADR-0023: The overview says what is wrong, not only what is true

- **Status:** accepted
- **Date:** 2026-08-21

## Context

`GET /api/v1/networks/{id}/overview` returns facts. A device's `unapplied_components`, an
advertiser's `health` and `admin_state`, whether a control session is up, how many peers
have ever handshaked. It says nothing about whether any of that amounts to a problem.

The page decided that for itself, in JavaScript. Four rules for devices and two for route
groups, plus a threshold — how long a control session must have been up before "no
handshakes" means a dead tunnel rather than a new one.

Three things make that the wrong place for them.

**There are two consumers, and the second one is not ours.** ADR-0009 requires the
commercial layer to build its cross-tenant roll-up on this same endpoint. To render "Acme:
5 problems" it has to reach the same conclusions, which today means reimplementing six
rules in another repository in another language. They will drift, and the failure that
produces — an MSP roll-up showing a customer green while that customer's own page shows
five faults — is the silent disagreement this project refuses for colliding prefixes
(ADR-0020) and for ambiguous names (ADR-0021).

**The rules cannot be tested where they are.** ADR-0022 §3 decided there is no JavaScript
toolchain, deliberately and with a stated expiry. The consequence went unstated: the logic
that decides whether an operator is alarmed is the only logic in this repository with no
tests. Every rule below has an edge — a stale handshake that is not a fault, a revoked
membership that is not a device in trouble, a clock that runs backwards — and none of them
had a test that could fail.

**The surface grew before it shrank.** #118 added tunnel reporting and with it a second set
of judgements, including the first threshold. Each new signal makes the duplicated rules
larger and the drift more expensive, so the moment to move them is before the roll-up
exists rather than after.

## Decision

**The overview computes faults, and consumers render them.**

### 1. A fault is a code and a message

```json
{"code": "tunnel_never_carried",
 "message": "tunnel has never carried anything: no peer has completed a handshake"}
```

The code is a stable identifier for a consumer that counts, groups or alerts. The message is
English for a person, and is the same sentence the page shows — this project already treats
the wording of a failure as part of the product (ADR-0011), and the wording belongs beside
the rule that produced it rather than in whichever client happens to be rendering.

The same shape as the error envelope this API already returns, for the same reason: a
caller should never have to parse prose to find out what happened.

### 2. Faults hang off the thing that has them, and are counted once

Each device and each route group carries `faults`, always present and always a list. The
response carries `fault_count` for the whole network, so a roll-up rendering forty tiles
does not have to walk forty device lists to draw one number.

### 3. Thresholds are the server's, and so is the clock

The grace period before an unhandshaked tunnel is called dead is applied here, against
`as_of` and the session's own start time. Both come from the same clock. A client comparing
a server timestamp against its own would be wrong by whatever its clock is wrong by, on the
machine somebody is reading this on.

### 4. An unknown code is not an error

Consumers must render or count a fault whose code they do not recognise, using the message.
New rules will be added, and a client that failed on one would make every rule addition a
breaking change — the opposite of what naming them is for.

### 5. The page holds no rules

It renders `faults` and sorts by whether the list is empty. Any rule that reappears there is
a bug, because it can only ever be a second opinion.

## Consequences

**"What counts as broken" is public API now.** Refining a rule changes what every consumer
reports, and removing a code is a breaking change. Decision 4 keeps additions cheap;
nothing makes removals cheap, which is the price of the endpoint being shared.

**The rules get tests, and immediately earn them.** Every edge in these six rules is a
table row now: a revoked membership is not a device in trouble; a stale handshake is not a
dead tunnel; a tunnel seconds old is neither.

**Messages are English in a JSON body.** A deployment wanting another language has the code
to key a catalogue on, and would have to supply its own wording. Not solved here, and
honest about that: nothing else in this API is localised either.

**The API is opinionated, and a deployment cannot argue with it.** An operator who thinks a
draining advertiser should not count as a fault has no knob. That is a real loss and the
deliberate trade — a knob would mean two deployments disagreeing about what "broken" means,
which is the drift this ADR exists to prevent, reintroduced as configuration.

**The page gets smaller.** Roughly sixty lines of judgement leave it, which is most of what
was hard to review in a file with no tests.

## Alternatives considered

**Publish the rules as a specification and let each consumer implement them.** No API
change, and each client renders exactly what it wants. Rejected because a specification two
implementations follow is a specification they drift from, and nothing would notice: there
is no test that can compare a private repository's TypeScript against this one's JavaScript.

**Leave them in the page.** What we had. Rejected for the three reasons in the Context, of
which the untestability is the one that would have bitten first.

**A separate `/health` endpoint returning verdicts.** Keeps the facts endpoint pure, which
is tidy. Rejected because two calls means two instants: a page that read facts from one and
verdicts from another would render a device shown as healthy beside a verdict saying it is
not. That is precisely the failure the single-snapshot decision in ADR-0022 §1 exists to
prevent, and it would be reintroduced by the endpoint meant to describe it.

**Return a severity or an overall status** (`healthy` / `degraded` / `down`) instead of a
list. Smaller responses and an obvious thing to colour a tile with. Rejected for now
because collapsing several faults into one word discards which ones, and the page's whole
argument is that the broken thing should be obvious without clicking. A severity per fault
can be added later without removing anything, which is the right order.
