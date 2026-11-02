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
deploy it, and the data plane is on three platforms of five with gaps on each —
[docs/platforms.md](docs/platforms.md) says which, and is checked against the code rather than
written from memory. Reports are still welcome and will be handled as above —
but a finding that a half-built feature is half-built is not one, and there are several of
those in the open issues already.

## Accounts, credentials and what happens to them

This is worth its own section because the threat model changed. Until ADR-0024 landed there
was one credential, a shared secret in an environment variable, and the worst case was that
it leaked. There are now passwords in a database, and that is a liability this project did
not previously have.

**Passwords** are hashed with Argon2id at 64 MiB, two passes, one lane, stored in PHC
string format so the parameters travel with the hash and can be raised later. Verification
is constant-time, and an address that does not exist is put through the same work as one
that does — so the time a sign-in takes does not say whether the account is real.

**Every way a sign-in can fail looks the same**: no such address, wrong password, suspended,
deleted, an organisation that does not exist. One status, one message, one log line. Being
able to tell "no such account" from "wrong password" would let a stranger enumerate who has
an account here, which is worth more to them than the specificity is worth to the person
typing, who already knows which of the two they got wrong.

**Sessions** live in PostgreSQL, one row per sign-in, so they are revocable rather than
merely expiring. What the database holds is a SHA-256 of what the browser presents, so a
backup does not hand somebody a live session. A sliding idle window of 12 hours keeps a
dashboard somebody is watching alive; a fixed 30-day ceiling that no amount of use raises
means a page left open on a wall does not hold a credential forever.

**Changing a password ends every session, including the one that changed it.** A password is
usually changed because somebody else may have seen it, and the change would be worth much
less if it left their session running. Suspending an account ends its sessions too, and
stops its API tokens working immediately.

**API tokens** carry the permissions of the person who minted them, intersected with a scope
chosen at creation, and that intersection is evaluated *at every use*. Demoting somebody
demotes their tokens on the next request rather than whenever they happen to sign out. A
token cannot mint another token, and cannot change its owner's password. Tokens expire —
ninety days by default, a year at most, with no unexpiring option.

**Permissions are read per request**, for the same reason: a role revoked in one tab takes
effect on the next request made in another.

**Writes from a browser are defended twice.** `SameSite=Strict` means a browser does not
attach the session cookie to a request another site caused; behind that, any unsafe method
authenticated by cookie must carry an `Origin` naming this host.

### What we know is missing

Said plainly, because a security policy that only lists strengths is not one:

- **An account can still be guessed at, more slowly.** Five consecutive failures for an
  address cost nothing; after that each attempt waits, doubling to a ceiling of one minute
  (ADR-0027). That takes an attacker from roughly a million guesses a day to about fourteen
  hundred. It is a slowdown and not a lockout, deliberately — a lockout is a denial of
  service aimed at the account holder, and anyone who knows an address could impose it. So
  fourteen hundred guesses a day is the residual exposure, and a weak password is still a
  weak password. The answer to that is the second factor below.
- **An attacker can make an account inconvenient to reach.** One failed attempt a minute,
  sustained, keeps an address waiting more often than not. That is inherent to any
  per-account throttle; here the window is a minute, any successful sign-in clears it, and
  ten consecutive failures are reported in the log.
- **There is no second factor.** The `mfa_enrolled_at` column exists and nothing writes it.
  ADR-0024 §1 commits to TOTP in the open core rather than as a paid feature.
- **There is no password reset flow yet.** An administrator sets a password directly. The
  design (ADR-0024 §6) is a link rather than an email, so that running meshp never requires
  running a mail server.
- **The bootstrap secret still exists**, deliberately: it is how a locked-out deployment
  gets back in. Every use of it is audited as itself and logged at warning level once an
  account exists.

Reports about any of the above are welcome and will be treated as reports about a known gap
rather than a discovery — see the note on half-built features in Scope.

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
this project's CI holds a token that can read it.

Every release after v0.2.2 carries three things beside its archives:

- **`SHA256SUMS`**, the SHA-256 of every file on the release.
- **`SHA256SUMS.sig`**, a signature over `SHA256SUMS` by the meshp release key: ECDSA P-256,
  made with `openssl dgst -sha256 -sign`. The release workflow will not publish a release
  without it, or with one that the key below does not verify.
- **A build provenance attestation** for every archive and for `SHA256SUMS`, recording which
  repository, workflow, commit and tag built it, in Sigstore's public transparency log.

`install.sh` checks the signature, then the archive against `SHA256SUMS`, before it unpacks
anything, and refuses on either. It needs only `openssl`, which is already on macOS and on
Debian and Ubuntu; a machine without it is refused rather than installed on the checksum
alone, and `MESHP_INSECURE_SKIP_SIGNATURE=1` is the only way to go on without it, which says
what it skipped. Why it is built this way, and exactly what it does and does not protect
against, is [ADR-0035](docs/adr/0035-releases-are-signed-with-a-key-install-sh-carries.md).

### The release key

There is no release key yet. It is created once by the maintainer (ADR-0035 §5) and lands
here, in `install.sh` and on [meshp.net](https://meshp.net) together, with its fingerprint; CI
refuses a change that puts it in this file or in `install.sh` but not both. Until then the
releases that exist are the four below, and the release workflow will not publish another.

### The releases from before signing

v0.1.0 to v0.2.2 were published before releases were signed, and never will be. `install.sh`
pins each by the SHA-256 of its `SHA256SUMS`, installs one only when it is named with
`MESHP_VERSION`, and refuses it if the checksum file is not this one:

| Release | SHA-256 of its `SHA256SUMS` |
|---|---|
| v0.1.0 | `ff429bcbb41e801d1db3be1652e931d856e3d39b3853756c403fc7b669ff8fbe` |
| v0.2.0 | `5a0013ebf192a8505f239180c4433067255974b58c9c350010c228f87bf3808b` |
| v0.2.1 | `638c91de1aaa4ebfdce36aea1be576e44cda16f54833eaf935f41ceea455cf34` |
| v0.2.2 | `c6ff31ef9fa3b30520e4f5f58656416430953a207add663c9d6d7234c8e288f4` |

These are what GitHub served on 2026-11-02, and they match the digests GitHub recorded when
the release workflow uploaded each file. That shows the files have not changed since they were
published; it cannot show who published them, which is what a signature would have done.

### Verifying a release

Without `install.sh`, with the tag of the release you are checking and the platform you
downloaded:

```sh
v=vX.Y.Z
base="https://github.com/meshpnet/meshp/releases/download/$v"
curl -fsSLO "$base/SHA256SUMS"
curl -fsSLO "$base/SHA256SUMS.sig"
curl -fsSLO "$base/meshp_${v}_linux_amd64.tar.gz"
```

**With openssl**, which is all `install.sh` uses. Save the key above as `meshp-release.pub`,
and check that its fingerprint is the one above *and* the one on meshp.net — the second is the
comparison that does not depend on trusting this page:

```sh
openssl pkey -pubin -in meshp-release.pub -outform DER | openssl dgst -sha256

# The checksums are signed by that key. Prints "Verified OK"; anything else, stop.
openssl dgst -sha256 -verify meshp-release.pub -signature SHA256SUMS.sig SHA256SUMS

# And the archive is the one the checksums describe.
sha256sum --ignore-missing -c SHA256SUMS          # Linux
shasum -a 256 --ignore-missing -c SHA256SUMS      # macOS
```

**With the GitHub CLI**, which needs no key: it checks the attestation instead. Name the
workflow and the tag as well as the repository, or it proves only that something in this
repository built the file:

```sh
gh attestation verify "meshp_${v}_linux_amd64.tar.gz" \
  --repo meshpnet/meshp \
  --signer-workflow meshpnet/meshp/.github/workflows/release.yml \
  --source-ref "refs/tags/$v" \
  --deny-self-hosted-runners
```

The two are independent. The signature says the checksums were signed with the release key,
which only the release workflow can use, only on a release tag, and only once the maintainer
has approved that run. The attestation says the
file was built by that workflow, from that tag, on GitHub's runners, and that the record of it
is public. Either one failing is a reason not to install.

### Checking install.sh before running it

`install.sh` and the key it checks against come from the same place, so whoever could change
one could change the other. Two things narrow that, and both are cheap.

Compare the key it carries with the fingerprint on meshp.net, which is not served from GitHub:

```sh
curl -fsSLO https://raw.githubusercontent.com/meshpnet/meshp/main/scripts/install.sh
sed -n '/^-----BEGIN PUBLIC KEY-----$/,/^-----END PUBLIC KEY-----$/p' install.sh \
  | openssl pkey -pubin -outform DER | openssl dgst -sha256
```

Or fetch it from a release tag rather than from `main`. Release tags cannot be moved or
deleted, so that copy is fixed in a way `main` is not:

```sh
curl -fsSLO "https://raw.githubusercontent.com/meshpnet/meshp/$v/scripts/install.sh"
```

### What this does not protect against

Said plainly, as above. Somebody with administrative control of this repository, or of the
maintainer's GitHub account, can sign a release, because the key is a secret held by GitHub and
the approval is a click in it; somebody who can merge to `main` can change the key that
`curl … main … | sh` trusts. Neither a
signature nor an attestation says the source or its dependencies were sound, only that this
workflow built them. And neither carries a date, so an older genuine release offered as the
newest would pass both. ADR-0035 goes through each, with what narrows it.
