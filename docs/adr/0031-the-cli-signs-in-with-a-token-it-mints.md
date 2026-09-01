# ADR-0031: `meshp login` mints an API token and keeps it for one person

- **Status:** accepted
- **Date:** 2026-09-01

## Context

`meshp --help` advertises six nouns — `device`, `network`, `user`, `group`, `acl`, `dns` —
and none of them exists (#213). They are missing together rather than one at a time, and the
reason is underneath all of them: the five verbs that do work (`join`, `up`, `down`, `status`,
`doctor`) talk to **meshpd over a unix socket**, and every noun talks to a **control plane over
HTTP**, with a credential. `cmd/meshp` has no HTTP client, no base URL and nowhere to keep a
credential.

So `login` is not one more verb. It is the thing six nouns are waiting for, and what it decides
they inherit.

ADR-0024 already divides credentials, and a CLI does not obviously land on either side:

- **Sessions** are for people. A row in `user_sessions`, revocable, with a sliding idle window
  and a fixed ceiling. The browser holds one in an `HttpOnly` cookie it cannot read.
- **API tokens** are for machines. Hashed, scoped, with an expiry and a last-used-at, carrying
  the permissions of the user who minted them intersected with a scope. ADR-0024's reasoning is
  that "a machine cannot answer an MFA prompt, cannot rotate a password, and must not be logged
  out because a person closed a laptop".

A CLI is a person at a keyboard and a long-lived process on their disk. The last of those three
reasons applies to it exactly; the first two do not.

## Decision

### 1. `meshp login` authenticates as a person and keeps a token

It asks for an email address and a password, opens a session the way the page does, uses that
session once to mint an API token, and then ends the session. What it stores is the token.

Three properties follow, and they are the reason for the indirection:

**A password is never stored, and never needed again.** The session exists for the length of
one command.

**The credential on disk is revocable and enumerable.** `GET /api/v1/me/tokens` lists it,
`DELETE` removes it, and it carries a `last_used_at`. A person who has lost a laptop can see
what it holds and take it away, which a stored password would not allow.

**It cannot outlive a demotion.** A token carries its owner's permissions intersected with its
scope, evaluated per request — so a person whose role is reduced has a CLI that is reduced with
them, without anybody reissuing anything.

The token is named for the machine it is on and expires. Ninety days, which is the mint
endpoint's own default: long enough not to be a nuisance, short enough that an abandoned
laptop stops being a credential within a quarter.

### 2. It is a per-person credential, and the daemon must not use it

`~/.config/meshp/credentials.json`, `0600`, owned by the person who ran `login`.

Deliberately the opposite of the daemon's socket, which is root-only because anything reaching
it can enrol the device and decide where its traffic goes. This credential administers a
control plane and must not be reachable by a root daemon on a shared machine; that daemon has
its own identity and its own key material (Invariant 19), and the two are not the same person.

`XDG_CONFIG_HOME` is honoured where it is set, because a person who has moved their
configuration has said where they want it.

### 3. One control plane at a time, and it is named in the file

`meshp login --control-url https://control.example.com` records the address beside the token,
and the nouns use it. `meshp network use` selects the network within it.

Not a per-command flag, because the nouns are what somebody types twenty times during an
incident, and not an environment variable alone, because a shell that has forgotten it is a
person wondering why they are unauthorised.

More than one control plane per person is a real case — an MSP is the product — and it is
deliberately not solved here. The file holds one, and the shape it holds it in is a list of
one, so that adding profiles later is not a migration.

### 4. The API is still the contract

The CLI is a client with no privileges of its own. Anything it can do, a token can do, and
nothing is reachable only through it. ADR-0009 makes the HTTP API what the commercial layer
builds on, and a CLI that grew its own private path would be a second interface to keep honest.

## Consequences

**A person's CLI credential is as strong as their account.** A token minted by an owner can do
what an owner can do, because `login` scopes it to the whole permission catalogue and the
control plane intersects that with what the person actually holds, per request. Asking for
everything is not the same as receiving it, and a CLI that could do less than the person
driving it is one they will work around.

The catalogue is read from the control plane rather than compiled in. A CLI carrying its own
copy would grant nothing new against a deployment that had learned a permission, and would be
refused outright by one that had dropped it — `MintToken` rejects a scope naming anything it
does not know.

There is no `--permissions` flag yet. A shared machine wants one, and the shape is a narrowing
of what is asked for rather than a new mechanism.

**`login` needs TLS in practice**, like the page: the control plane refuses to open a session
over plaintext to anything but loopback. That is the same requirement ADR-0022 already imposes
and not a new one.

**Signing out asks for a password, and that is a consequence rather than a wart.** A token may
not revoke itself: the control plane refuses it in those words — "a token that could mint a
token would survive its own revocation" — so taking one away is something only the person can
do. `meshp logout` therefore always forgets the credential locally, which needs nothing, and
then offers to sign in to revoke it. `--local` skips the second half, and so does having no
terminal; either way it says exactly what is still valid and where to remove it.

Getting this wrong is what the first version did. It presented the stored token to revoke the
stored token, which is precisely the operation the boundary exists to refuse.

**A stolen credentials file is a valid credential until it is revoked or expires.** This is
true of every token and is the reason for `last_used_at` and for the expiry. It is worse than a
browser cookie in that it survives a reboot, and better in that it is listed, named, and
removable without changing a password.

**Nothing here is multi-tenant yet.** One control plane, one person, one token. An operator
holding forty customers' networks needs profiles, and the file format leaves room for them.

## Alternatives considered

**Store the password and re-authenticate per command.** Simplest to write and the worst
outcome: a password on disk is not revocable without changing it everywhere, and it is the one
credential that also opens the page.

**Keep a session cookie, as the page does.** It is what a person gets in a browser, and it is
wrong here. Sessions have a sliding idle window and a fixed ceiling, so a CLI would log out
during a long afternoon; they carry a CSRF story that exists for browsers and costs a CLI
nothing but confusion; and `SameSite` is meaningless outside one.

**Ask for a token and let people mint it themselves.** `POST /api/v1/me/tokens` already exists
and an operator can call it with `curl`. Rejected as the *only* answer, not as an answer:
`meshp login --token` remains the way a CI job authenticates, and it is what somebody
automating this wants. What it is not is the first thing a new operator should have to do.

**Use the daemon's identity.** The device already has one, and it is already talking to the
control plane. Rejected because a device's identity says what the device may do, not what the
person at the keyboard may do — and the two must not be conflated on a machine several people
can log into.
