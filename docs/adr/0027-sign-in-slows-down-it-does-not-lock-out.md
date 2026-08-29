# ADR-0027: A guessed-at account slows down; it is never locked out

- **Status:** accepted
- **Date:** 2026-08-28

## Context

ADR-0024 introduced password authentication and named the work that decision creates:

> Argon2id with sensible parameters, a constant-time comparison, rate limiting on sign-in,
> and lockout after repeated failures. None of it is novel and all of it has to be right.

Three of the four shipped with it. The fourth did not, and #148 is the record of what is
missing: sign-in sits behind the same per-address limiter the enrolment endpoints use, which
bounds a flood from one host and does nothing about a slow attempt spread across many, aimed
at one account. Argon2id at 64 MiB and two passes makes each guess cost real work — call it
a tenth of a second — which is expensive rather than prohibitive. One host can put something
like a million guesses a day against one address, and nothing counts them.

What makes this worth a record rather than an afternoon's work is that the obvious fix has a
victim. **Lockout is a denial of service aimed at the account holder.** Anyone who knows an
address can lock its owner out by getting the password wrong enough times, and the person who
suffers is the one who did nothing. A mechanism that protects an account by making it
unusable has handed an attacker a cheaper attack than the one it prevents.

## Decision

Consecutive failed sign-ins for an address make the next attempt wait. The wait doubles and
is **capped at one minute**. Nothing is ever locked out.

- The first five failures cost nothing. People mistype.
- The sixth costs a second, and each after that doubles: 2, 4, 8, 16, 32, then 60 for as long
  as the failures continue.
- A successful sign-in clears the count. So does an hour without an attempt.
- Refusal is a `429` with `Retry-After`, not a `401`. Somebody who has mistyped six times is
  told to wait, because "that email address and password do not match" would be a lie that
  makes them keep trying.

The count is keyed on the **submitted address**, whether or not an account exists for it, and
stored as a hash rather than as text. Both halves of that matter and neither is fastidiousness
— see the consequences.

It lives in Postgres rather than in memory, because the control plane is meant to run as more
than one instance and a counter held in one process is one an attacker walks around by
spreading attempts across replicas.

## Why a cap, and why one minute

The cap is what makes this defensible rather than a trade of one attack for another.

At a minute, an attacker's rate falls from roughly a million guesses a day to about fourteen
hundred — three orders of magnitude — while the worst thing that can happen to a real person
is that they wait a minute. That is an inconvenience they can sit through, not a support call,
and nobody has to be trusted to unlock anything.

It also dissolves a problem the issue raises: **whatever this does must not lock out the last
owner**, or the bootstrap secret becomes the only way back into a deployment. With a one
minute ceiling there is no such thing as locked out, so there is no exemption to write — and
an exemption would have been a permanent hole aimed at the highest-value account in the
system.

## What this does not fix, said plainly

**An attacker can still make an account inconvenient to reach.** One failed attempt a minute,
sustained, keeps an address in the penalty box more often than not. That is inherent to any
per-account throttle and this one has the mildest version of it: the window is a minute, a
successful sign-in during any gap resets it, and the attempt rate needed to sustain it is
loud in the log and bounded by the per-address limiter.

**Fourteen hundred guesses a day is still a lot against a bad password.** This buys time and
makes the attempt visible; it does not make a weak password safe. The answer to that is the
second factor ADR-0024 §1 commits to, and this is what protects an account until it has one.

## Consequences

**Failures are counted for addresses that have no account.** Not doing so would be an oracle:
if a known address is throttled and an unknown one is not, response time answers "does this
person have an account here" for anybody who cares to measure — the same question the single
shared refusal message exists to avoid answering. So the counter does not know whether the
address exists, and cannot leak it.

**The address is stored as a SHA-256 hash.** It follows from counting unknown addresses: an
attacker choosing what goes in this table would otherwise be choosing what text this
deployment stores, and the table would fill with the addresses of people who have no account
here. A hash is a fixed-size key that answers the only question this table is asked, and it
means a dump of it discloses nobody.

**An account under sustained attack is reported once rather than per attempt.** Crossing ten
consecutive failures logs a distinct warning naming the address; the individual refusals go
on being logged as they were. #148's third complaint was that nothing tells anybody this is
happening, and a line per attempt is not telling anybody — it is the thing an operator has
already muted.

**There is a new table to sweep.** It joins `user_sessions`, whose sweep existed and was
called by nothing until this change, so both are now swept on the same hourly loop that
prunes the delta log.

## Alternatives considered

**Lockout after N failures, expiring after some minutes.** What most systems do. Rejected on
the victim: fifteen minutes is long enough to be a support call, and an attacker who can
impose it repeatedly has denied service to somebody who did nothing. Every argument for it
is an argument for the cap being higher, and the cap being higher is the whole of the harm.

**Per-address counting only, without the per-account limit.** What exists today. It is the
right tool for a flood and the wrong one for a patient attacker on one account, which is the
threat that matters once a deployment is on the internet.

**Requiring a second factor after repeated failures instead of slowing down.** Better, and
unavailable: `users.mfa_enrolled_at` exists and nothing writes it. An account with no second
factor cannot be asked for one, and that is most of them until ADR-0024 §1 is built. Worth
revisiting then — the natural shape is that this slows down an account with no second factor
and challenges one that has it.

**Counting in memory.** Simpler, and wrong for a deployment running more than one control
plane instance: an attacker spreads attempts across replicas and each one sees a count of one.
The redundancy this project requires is what rules it out.
