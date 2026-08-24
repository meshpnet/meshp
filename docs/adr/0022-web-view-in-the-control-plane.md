# ADR-0022: The web view ships inside the control plane and polls one snapshot

- **Status:** accepted
- **Date:** 2026-08-20

## Context

meshp has no user interface. An operator sees a device by logging into it and running
`meshp status`, or sees a network by opening `psql`. Issue #108 scopes the first slice of
a view to one network and one question — *is anything unreachable, and what is carrying
for it* — and lists four things that must be decided before any of it is written.

What exists today decides most of them:

- **The HTTP API creates things.** Every route under `/api/v1/networks/{id}` mints a
  token, publishes a policy, or edits a route group. `GET .../devices` lists memberships
  with their addresses and revocation state, and knows nothing about whether any of them
  is connected. There is no endpoint that answers a question about a network.
- **Liveness is in memory and in one process.** `session.Hub` holds the connected
  sessions and can answer `Get`, `Count` and `NetworkCount`. It cannot enumerate a
  network's sessions, and a second replica would hold its own separate set. ADR-0012's
  `Presence` and `Bus` interfaces, which exist to close that, have no implementations —
  there is no Redis anywhere in the tree.
- **What a device could not apply already reaches the database.** `membership_state`
  carries `unapplied_components`, written on every acknowledgement, read by nothing.
- **Authentication is one shared secret.** `MESHP_ADMIN_TOKEN`, compared in constant
  time, granting every administrative route. `users`, `roles`, `role_bindings` and
  `groups` are in the schema from the first migration and no query reads them.
- **There is no Node toolchain.** No CI job runs one. The release workflow cross-compiles
  five targets with `CGO_ENABLED=0` and nothing else. `.gitignore` has carried
  `/web/node_modules/`, `/web/dist/` and `/web/.vite/` since early on — an assumption
  somebody made, not a decision anybody took.

Two constraints make the obvious answers wrong.

**The read API has two consumers, and the second one is not ours to change.** ADR-0009
puts the whole core under Apache 2.0 and requires the commercial layer to call the open
control plane over its HTTP API. The cross-tenant roll-up an MSP pays for is built on
whatever this endpoint returns. So it cannot be shaped to what one page happens to need
this month, and it cannot be reshaped freely afterwards.

**A view assembled from several polls shows a state that never existed.** Devices from
one instant and route groups from another render a page in which a device is down and
the group it advertises for is healthy. That is the same silent wrong answer this project
refuses for colliding prefixes (ADR-0020) and for ambiguous names (ADR-0021), arriving
by a different door.

## Decision

### 1. One endpoint returns one consistent snapshot

`GET /api/v1/networks/{networkID}/overview` answers the whole question in one response:
every device with its liveness, applied version and `unapplied_components`; every route
group with its prefixes, its advertisers, which are healthy and which is currently
assigned.

Read in a single database transaction, with presence sampled once, so everything in the
response describes one instant. The response says which instant, in `as_of`.

It is bounded and says so. A response that could not carry every device carries a
truncation marker rather than a shorter list, and the marker exists from the first
version — adding one later is a breaking change for a consumer that is already
paginating by not paginating.

`GET /api/v1/networks` comes with it. A page reachable only by pasting a UUID is not a
product, and there is no way to list networks today.

### 2. The page is embedded in `meshp-control`

Served from the same binary, on the same port, behind the same TLS configuration, via
`embed.FS`. `migrations/embed.go` is the precedent and states the reason: a binary should
not need files on disk beside it. A self-hoster's deployment story stays what
`deploy/systemd` describes — one unit — rather than gaining a second artefact, a second
port and a CORS policy between two halves of the same product.

The API stays under `/api/`. The page is served at the root. Nothing about embedding is
load-bearing for the commercial layer, which talks to the API and never to the page.

### 3. No build step, for now

`web/` holds hand-written HTML, CSS and ES modules, embedded as written. No bundler, no
transpiler, no `package.json`, no Node in CI or in the release job.

The embed directive lives in `web/embed.go`, beside the files, because `go:embed` cannot
reach out of its own directory — the constraint `migrations/embed.go` already documents.

This is a decision with a visible expiry. It holds while the view is one page answering
one question. The trigger to revisit is a second view that needs to share state with the
first, or the day hand-written DOM updates start producing the bugs a framework exists to
prevent. Revisiting means an ADR, a CI job that runs the toolchain, and a release job that
runs it before `go build` — not a `package.json` appearing in a pull request.

The `.gitignore` entries stay. They cost nothing and they will be right.

### 4. The page polls, and the server sets the interval

The page calls the overview endpoint on a timer. The response carries
`poll_after_seconds`, defaulting to 5, so a deployment can be slowed down without
shipping a new page.

Each response is a complete answer. There is no incremental state in the browser to get
wrong, no reconnect and backoff logic in a page that has no framework to provide it, and
no second fan-out mechanism in a control plane that already runs one for agents.

**The page shows its own freshness.** `as_of` is rendered, and a poll that fails makes the
page visibly stale rather than leaving old data on screen looking current. A monitoring
view that lies about when it last heard anything is worse than no view, in the same way
that a tunnel silently failing open is worse than one that refuses traffic (ADR-0011).

### 5. A browser gets a cookie, and the cookie is a person

*Rewritten 2026-08-24, when ADR-0024's permission slices landed. What this section said
before is at the end, because how it was wrong is the useful part.*

`POST /api/v1/ui/session` takes an email address and a password and returns a session
cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, sliding idle window, fixed ceiling,
revocable server-side because it names a row in `user_sessions`. `DELETE` on the same path
signs out. No credential ever reaches JavaScript.

**What the cookie authorises is what the person holds.** There is no separate browser
credential and no separate rule about what a browser may do: the session identifies a user,
the user has role bindings, and every route checks a permission against them (ADR-0024 §4).
A reader signs in and sees a page with no buttons on it. An owner signs in and sees the same
page with buttons. The middleware that used to mean "reads only" is gone, because there is
nothing left for it to distinguish.

**The page asks what it may do before it renders.** `GET /api/v1/me/permissions?network=`
answers for the caller, in that scope. This is never enforcement — the API refuses
regardless, and a page that believed itself would be one edit away from being the security
boundary — it is so that a control that would be refused is never drawn. A button that
returns 403 teaches somebody the product is broken rather than that they lack a permission.

**Writes are defended twice, and the two fail independently.** `SameSite=Strict` means a
browser does not attach the cookie to a request another site caused; this is the strong one
and the browser enforces it. Behind it, an unsafe method authenticated by cookie must carry
an `Origin` naming this host — a cross-origin form POST cannot suppress that header, and a
cross-origin `fetch` that sets an acceptable one cannot get past a preflight this server
never answers. Hosts are compared and schemes are not, because a TLS-terminating proxy
leaves `r.TLS` nil and this package refuses to take `X-Forwarded-Proto` on trust; scheme
downgrade is the cookie's problem, and the cookie is `Secure`.

While the credential could only read, `SameSite` alone was adequate — the worst a forged
request could achieve was making somebody's browser read something on their behalf. A cookie
that can revoke a device is a different proposition, and a defence with one layer is one
nobody has asked what happens if it fails.

**The page writes two things, and deliberately only two.** Minting an enrolment token, and
revoking a device: the two halves of a device's life, which is what this page is already
about and what an operator otherwise reaches for `curl` to do. Publishing an access policy
and editing DNS records are not here — they are documents somebody composes rather than
buttons, and a form that got them subtly wrong would be worse than the command it replaced.

**A minted token pauses the page.** The control plane stores only a hash, so the moment
after minting is the only moment that secret exists; the view is replaced wholesale on every
poll, which would wipe a half-made text selection. So polling stops while it is on screen and
the page says that it has, which is the same rule about freshness as everywhere else.

The login endpoint still refuses to mint a cookie over plaintext to anything but loopback,
which makes configuring TLS a requirement for any deployment somebody actually browses to.

**What is gone.** The in-memory session store, the credential derived from the
administrative token, and the read-only middleware. A deployment with no user accounts
cannot sign in to this page at all, which is correct: it has nothing to look at until
somebody creates the first account, and creating one is an API call the bootstrap secret
still makes (ADR-0024 §5).

#### What this section used to say, and how it was wrong

It said the cookie was minted from the administrative token and could only read, and that
this was what made shipping a UI before user accounts defensible. That was true and it was
also a bound with no principle underneath it — there was nothing to attach permissions to,
so "reads only" was the only honest thing to say.

It was amended twice in two days and wrong once, both times for the same reason: it
enumerated. Naming the endpoints meant the audit trail (#125) shipped behind the
administrative token purely because it was not on the list, leaving the page unable to
answer "why did my outbound IP change?" while the record that answers it sat one route away.
Replacing the endpoints with a rule — read against write — fixed the granularity, but the
*next* amendment claimed the cookie could not read across networks, which had not been true
since `GET /api/v1/networks` shipped in #113.

The lesson worth keeping is not "check your claims", though that too. It is that a section
describing a credential in terms of the routes it reaches will go stale every time a route
is added, and nobody weighs an amendment made to unblock a feature. A credential described
in terms of what its holder is does not have that failure mode, which is why this rewrite
describes a person rather than a list.

## Consequences

**The control plane gains a read path it has never had**, and with it a query that will be
run every five seconds per open page. It has to be one round trip and it has to stay
cheap, because the commercial layer will call it per-network on a timer of its own.

**`session.Hub` has to learn to enumerate.** It cannot list a network's sessions today.
The endpoint reads liveness through a `Presence`-shaped accessor rather than reaching into
the hub, so that ADR-0012's interface can arrive later as a swap rather than a redesign.

**Multi-replica gets a second visible symptom.** Liveness is per-process, so two replicas
would each report only their own sessions and the page would show devices as disconnected
that are not. This does not create the problem — `NotifyNetwork` is already in-process, so
a configuration change on one replica already fails to wake agents on another — but it
makes it something an operator can see. Running more than one `meshp-control` stays
unsupported until `Presence` and `Bus` are real.

**`unapplied_components` becomes visible for the first time.** A device that could not
apply its policy has been telling us so on every acknowledgement, into a column nobody
reads. That is the ADR-0018 failure — a mechanism nothing running reaches — and this is
what reaches it.

**The audit trail says "the administrator", not who.** One shared credential means
`audit_events` cannot attribute anything to a person. That is a real cost, accepted
knowingly, and it is the second reason the cookie may not write.

**The browser view requires TLS in practice**, which some self-hosters will meet by
putting the control plane behind something they already run, and some will meet by
discovering `MESHP_TLS_DOMAINS`. Either way it is a step that did not exist before.

**The page requires JavaScript** and will not degrade to anything useful without it.

**No build step means no TypeScript, no npm, and hand-written DOM updates.** For one page
that is a saving. It stops being one at a size this decision does not try to predict, and
the expiry condition in Decision 3 exists because the cost of noticing late is a rewrite.

**The overview response is public API from its first commit.** ADR-0009 makes the
commercial layer its consumer, which means field names and shapes carry a compatibility
obligation immediately — there is no period during which this is "just what the page
needs".

**An organisation-level aggregate is a legitimate future addition; a cross-organisation
one is not.** A self-hoster has one organisation and may reasonably want every network on
one screen. Forty customers on one screen is the proprietary feature, and building its
server-side half into the core would move the licence boundary that ADR-0009 draws.

## Alternatives considered

**A separate frontend artefact** — its own container or a static host, calling the API
across an origin. It is the conventional shape and it is right for a large deployment that
wants a CDN in front. Rejected because it makes a self-hoster run two things to see one
product, adds CORS and a second TLS configuration, and introduces version skew between a
page and an API that ship from the same repository. Embedding does not foreclose it: the
contract is the API, and anything may serve those files.

**Streaming — SSE or a WebSocket.** The control plane knows the instant a session drops,
so pushing is the natural fit, and it removes the latency floor polling imposes. Rejected
for now because fanning out to browsers across replicas needs the `Bus` that does not
exist, because it puts reconnection and incremental-state handling into a page that has no
framework to provide them, and because the thing bought is sub-five-second latency on a
page a person is looking at. If this became a wall display in a NOC, or if enough
concurrent viewers made polling the expensive option, that calculation changes and this is
the answer.

**React, Vite and TypeScript now.** What most people would reach for, and it would make the
second and third views cheaper. Rejected because it buys a Node toolchain, a lockfile, a
new Dependabot ecosystem, a CI job, a release-ordering change and either a committed bundle
or a build that must run before `go build` — all of it paid up front, for one page.

**Put the bearer token in the browser** and send it from JavaScript. Simplest possible
answer and no new endpoint. Rejected because it puts an organisation-wide credential that
can write everything into a place XSS can read, with no revocation and no expiry.

**Build real user accounts first.** Password storage, invitations, reset, lockout, and the
`roles` and `role_bindings` tables finally read. It is the correct end state. Rejected as
the price of admission for a read-only page: it is a larger project than the view, and it
would keep the product invisible for the length of it. Decision 5 is what makes deferring
it honest rather than merely convenient.

> *Two weeks later, done.* ADR-0024 built exactly this, and Decision 5 above is now written
> in terms of it. The deferral turned out to be worth what it cost — the page shipped, was
> used, and the shape of what it needed from accounts was clearer for having had it — but
> the estimate was right too: it was a larger project than the view, in four slices.

**Three endpoints, polled separately.** Resource-shaped, more RESTful, and each one
simpler. Rejected for the reason in the Context: the page would render an instant that
never happened, and it would do it most often exactly when something is changing — which
is when somebody is looking.

**Ship `meshp status --json` (#62) and let people build their own.** Worth doing regardless.
Rejected as an answer to this, because it reports what one device believes about itself,
and the question is about a network.
