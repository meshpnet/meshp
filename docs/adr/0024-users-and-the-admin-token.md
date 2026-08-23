# ADR-0024: Local user accounts, scoped API tokens, and what becomes of the admin token

- **Status:** accepted
- **Date:** 2026-08-22

## Context

Every administrative route in this control plane is gated by one boolean: whether the caller
presented `MESHP_ADMIN_TOKEN`. The code that checks it has said what it is since it was
written:

> This is a bootstrap mechanism, not an authentication system. It is a single shared secret
> with no identity, no scoping and no audit trail beyond "the admin token was used". It
> exists so tokens can be minted before users and sessions are built, and it should be
> removed when they are.

Users and sessions were never built. What has been built instead is a growing amount of
design that works around their absence:

- **The browser's credential is derived from the shared secret** (ADR-0022 §5). Its whole
  justification is that it can only read, because there is no identity to attach permissions
  to. That section has been amended twice in two days and was wrong once.
- **The audit trail cannot attribute anything to a person.** Four subsystems write to
  `audit_events`, and every administrative action lands as `actor_kind = 'api_token'` with
  no actor. A record that says "the administrator revoked this device" answers half the
  question an audit trail exists for.
- **Five tables have sat unread since the first migration** — `users`, `roles`,
  `role_bindings`, `groups`, `group_members` — and are the largest block of deferred work
  in `scripts/reachability-allow`.
- **`MESHP_ADMIN_TOKEN` appears 32 times across the documentation.** Every quickstart, every
  runbook, every troubleshooting recipe hands somebody a credential that can do everything.

The schema is not silent about what was intended. `users` carries an Argon2id hash that is
nullable "when the user authenticates via OIDC only", an MFA enrolment timestamp, and
uniqueness per organisation. `roles` holds bags of permission strings with a comment saying
behaviour is never keyed off the role name. `role_bindings` scopes a grant to an
organisation or narrows it to one network. `devices.user_id` exists and nothing sets it.

Three constraints decide most of what follows.

**There are three kinds of caller, and only one of them is a person.** People use a
browser. Machines — the commercial layer above all, but also CI and an operator's
scripts — call the API without one. Devices already authenticate with their own identity
keys (ADR-0006) and are not in scope here. A design that gives machines a person's
credential, or people a machine's, gets one of them wrong.

**ADR-0009 puts SSO and SCIM in the commercial layer.** So the open core cannot make an
identity provider a prerequisite for logging in, and must not build the integration either.
What it needs is somewhere for one to attach.

**A self-hoster must not need to run a mail server.** Password reset and invitation flows
conventionally assume email. Making SMTP a dependency of `docker compose up` would be a
larger tax than the feature is worth, on exactly the users this project is for.

## Decision

### 1. Local accounts, per organisation, with a seam for SSO

A user is an email address and an Argon2id password hash, unique within an organisation, as
the schema already describes. `password_hash` stays nullable: a user provisioned by the
commercial layer's SSO has no password here, and that is the seam. The open core never
speaks OIDC, and never requires it.

MFA is open core, not a paid feature. TOTP, recorded in the `mfa_enrolled_at` column that is
already there. Selling a second factor back to people who are trying to secure their own
network is the kind of thing ADR-0009 refuses when it says redundancy is not a paid feature.

### 2. Machines get API tokens, and they are not sessions

A new `api_tokens` table: a hashed secret, an owning user, a scope, an expiry, a
last-used-at, and a revocation. `audit_events.actor_kind` already allows `'api_token'`.

Separate from user sessions on purpose. A machine cannot answer an MFA prompt, cannot rotate
a password, and must not be logged out because a person closed a laptop. The commercial
layer is a machine, and the API it builds on (ADR-0009) has to be reachable by one.

A token carries the permissions of the user who minted it, intersected with a scope chosen
at creation. It can never grant more than its owner has, which is what stops a token
outliving a demotion.

### 3. Sessions live in the database

A `user_sessions` table, unlike the in-memory browser sessions ADR-0022 §5 ships today.

ADR-0012 keeps ephemeral state out of PostgreSQL because presence is high-frequency and
losing it costs a reconnect. A login is neither: it happens rarely, and losing one costs a
person their place. Every deployment restart logging out every operator is a bad property to
build in deliberately, and the multi-replica case has no other answer.

One row per login, not per request. The row is what makes a session revocable — which
is the whole reason not to put the session in a signed token instead.

### 4. Permissions are strings; roles are bags of them

As the schema says, and behaviour is never keyed off a role's name. A permission is
`<resource>.<action>` — `network.devices.revoke`, `network.dns.write`,
`organization.users.invite` — and the catalogue is defined by the routes, one entry per
thing a route does.

A binding grants a role within an organisation, optionally narrowed to a single network.
That narrowing is what an MSP needs and what the open core should support without knowing
anything about agencies: a technician with `network.devices.revoke` on one customer's
network and nothing on another's.

Built-in roles are seeded and marked `is_builtin`: an owner, an administrator, an operator
who can act but not change who may act, and a reader. Deployments may add their own.

### 5. The admin token becomes bootstrap and break-glass, and stops being the recommendation

It is not removed, and it does not silently stop working.

It creates the first user, which is the only way a fresh deployment can have one. After
that it keeps working, because a deployment that has locked itself out of its own control
plane needs a way back and a self-hoster has no support line to call. What changes is
everything around it:

- **Every use is audited**, as `actor_kind = 'api_token'` with a label naming it the
  bootstrap secret, so "somebody used the root credential" is a thing an operator can see
  rather than infer.
- **Every use is logged at warning level** once a user exists, because at that point it is
  being used instead of an account, and that is a fact worth surfacing.
- **The documentation stops teaching it.** All 32 mentions become "create a user, then use a
  token you minted"; the admin token appears in one place, described as what it is.

Removing it entirely is a later decision that needs an answer to "how does a locked-out
deployment recover", and that answer is not "read the database" for a product whose whole
argument is that self-hosting should be ordinary.

### 6. No email is required to run meshp

Invitations produce a link. An administrator creates a user, gets a single-use enrolment URL
back, and passes it on by whatever means they already have. Password reset works the same
way: an administrator issues a reset link, or a user who can still log in changes their own.

A deployment that configures SMTP may have those links delivered for it. Nothing
requires it, and the flows are identical either way — which is what stops the no-email
path from being the neglected one.

## Consequences

**ADR-0022 §5 is superseded in substance.** The browser's credential stops being derived
from a shared secret and becomes a real session with a real identity, which means the
read-only restriction can be lifted — it existed only because there was nothing to attach
permissions to. That is the moment the page can grow the write paths issue #108 deliberately
excluded, and §5 should be rewritten rather than amended a third time.

**The audit trail starts naming people.** `actor_kind = 'user'` with a real `actor_id` and
the user's email as the label. This is the single largest thing users buy, and everything
already written to `audit_events` gets it without changing a call site.

**Five tables leave `scripts/reachability-allow`** — which is the test of whether this was
finished or merely started.

**Password storage is a liability this project did not previously have.** Argon2id with
sensible parameters, a constant-time comparison, rate limiting on sign-in, and lockout after
repeated failures. None of it is novel and all of it has to be right; the security policy
will need a section, and the threat model changes from "a shared secret leaked" to "a
password database leaked".

**Session invalidation becomes something with rules.** Changing a password ends other
sessions. Suspending a user ends theirs. Revoking a role changes what a live session may do,
which means permissions are read per request rather than baked into the session at login —
the alternative is a demoted user keeping their old powers until they happen to log out.

**Every existing deployment keeps working on upgrade.** The admin token still functions, no
migration invalidates it, and nothing forces the creation of a user. That is deliberate and
it is also the risk: a deployment that never creates one gets none of this, and the warning
log is the only thing that will tell them.

**The API grows a substantial surface** — users, tokens, roles, bindings, sessions — and
ADR-0009 makes all of it the commercial layer's to depend on, with ADR-0023's constraint
that shared surface cannot be reshaped freely afterwards. This is the largest single
addition to the public API that has been proposed, and it should be built in slices with
that in view rather than landed at once.

**Devices gain owners eventually, and this does not settle it.** `devices.user_id` and the
`groups` tables describe an ACL model where policy references people rather than tags. That
is a real design and it needs its own record; what this decision does is make the identity
it would reference exist.

## Alternatives considered

**OIDC only, with no local passwords.** No password storage, no reset flow, no lockout
logic, and the security burden moves to somebody who does identity for a living. It is what
a product built for enterprises would do.

Rejected because it makes an identity provider a prerequisite for logging into a
self-hosted control plane. A person running meshp for their own household would have to
stand up Keycloak before they could see a page. It also contradicts ADR-0009, which puts SSO
in the commercial layer — the open core would then depend on something it does not ship.

If that constraint disappeared, this would be the better answer, and the seam in Decision 1
is deliberately the shape that would let it become one.

**Keep the shared secret and add scoped API tokens, without users.** Much smaller. Tokens
could carry permissions and be revoked individually, which fixes scoping and rotation
without any password handling at all.

Rejected because it does not fix attribution. A token can be labelled "alice's laptop" and
nothing checks that it is Alice's; the audit trail would record a string somebody typed.
Half of what an audit trail is for is answering "who", and a self-declared label is not an
answer.

**Signed session tokens instead of a sessions table.** No table, no lookup per request, and
horizontal scaling for free.

Rejected because a signed token cannot be revoked before it expires without keeping a
revocation list — which is a table, holding the same rows, minus the ability to see who is
currently logged in. Sessions are rare enough that the lookup is not the expensive part of a
request.

**Per-network logins**, so an MSP technician has one account per customer. It maps neatly
onto how the work is actually divided.

Rejected because it multiplies credentials per person, which is how passwords get reused,
and because `role_bindings` already expresses the same thing with one account: a binding
narrowed to a network is a technician who works on that customer and no other.

**Do nothing, and keep the admin token.** It works, every deployment already has one, and
the project is pre-alpha with no users to migrate.

Rejected because the cost is not paid at the moment of the decision. Each thing built while
identity is absent is built around its absence — the read-only browser session, the
unattributable audit trail, the fault rules with no owner — and each is more expensive to
revisit than it would have been to write once. The code comment quoted at the top has been
asking for this since the first commit.
