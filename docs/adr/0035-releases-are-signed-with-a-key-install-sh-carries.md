# ADR-0035: Releases are signed with a key install.sh carries, and attested by the workflow that built them

- **Status:** accepted
- **Date:** 2026-11-02

## Context

Every release carries `SHA256SUMS`, and `install.sh` checks the archive against it before
unpacking anything. That catches a corrupted download. It does not say who made the release,
because the archive and the checksums come from the same place, and whoever can replace one can
replace the other (#219).

The people who can do that are not on the network path — TLS covers that — but anyone able to
publish a release: a stolen GitHub token, a compromised or malicious step in the release
workflow, which until now held `contents: write` while handling the archives, or a takeover of
the account. Against any of them `sudo sh install.sh` runs whatever they uploaded, on a machine
whose purpose is to sit on a private network.

Four constraints decide most of the answer:

- **The default must check, with what is already there.** `install.sh` is run on bare servers
  and on Macs. A check that needs `cosign`, `gh`, `minisign` or `gpg` either becomes a
  dependency for exactly the people least likely to have one, or becomes optional, and an
  optional check is one that does not run.
- **macOS ships LibreSSL, not OpenSSL.** On macOS 26.0 it is LibreSSL 3.3.6, which has no
  Ed25519: `openssl genpkey -algorithm ed25519` answers "Algorithm ed25519 not found", and
  `pkeyutl` has no `-rawin`. What both libraries do have, with the same command line, is ECDSA
  over P-256 through `openssl dgst -sha256 -sign/-verify`. A round trip — signed by OpenSSL 3,
  as the release runner will, and verified by that LibreSSL — was checked before this was
  written, and the release workflow's install tests exercise each library on every change to
  the install path: OpenSSL on Linux, and the LibreSSL in `/usr/bin` on a Mac.
- **What people install today must keep installing.** v0.1.0 to v0.2.2 were published unsigned,
  the site tells people to install v0.2.2 by name, and nothing merged here may break that before
  a signed release exists.
- **The script comes from where the key comes from.** `install.sh` is fetched from `main` on
  GitHub, so any key it carries is one it learned from the same origin as the releases. Signing
  the archives without saying what that leaves open would move the problem rather than solve it.

## Decision

### 1. Two layers: a signature install.sh checks, and an attestation anyone can

**A detached signature over `SHA256SUMS`**, published beside it as `SHA256SUMS.sig`: ECDSA
P-256 over SHA-256, DER-encoded, exactly what `openssl dgst -sha256 -sign` writes. Signing the
checksum file rather than each archive means one signature covers every file on the release,
and since every line names its archive with the version in it, the signature also binds the
archives to the release they belong to — a signed `SHA256SUMS` from one release cannot vouch
for another release's archive.

**A build provenance attestation** for every archive and for `SHA256SUMS`, made by
`actions/attest` and checked with `gh attestation verify`. It records which repository,
workflow, commit and tag built each file, signed with a short-lived Sigstore certificate and
written to Sigstore's public transparency log. There is no key to keep. It is also the weaker
statement — it says this workflow built the file, not that anybody meant to release it — and
nothing on a bare server can check it, which is why it sits beside the signature rather than
instead of it.

### 2. The key lives in one job, and that job cannot publish

The private key is `MESHP_RELEASE_SIGNING_KEY`, a secret of the GitHub environment `release`.
The environment is restricted to `v*` tags, so a pull request or a pushed branch cannot reach the
key however the workflow is edited. That matters here: several agents push branches to this
repository, and a run started by a pull request from one of them can read every *repository*
secret. The environment also names the maintainer as a required
reviewer, so the job that signs waits until that person approves the run. That approval is the
one thing in this design that is a human's intent to release rather than a machine's report that
it built something, and it costs one click per release.

A tag rule is not a commit rule: whoever can push a `v*` tag can point it at any commit,
including one whose workflow was changed, and the run it starts is in the environment. The
required reviewer is what stands between that and the key.

The release workflow splits along the key:

- **`sign`** holds the key and `contents: read`. It signs, then verifies the signature against
  the key `install.sh` carries *at that tag*, so a secret that does not match the published key
  fails the release rather than the first install. It attests, after the key has been removed
  from the runner.
- **`publish`** holds `contents: write` and no key. It verifies again, immediately before
  uploading, that the signature is the key's, that every file matches `SHA256SUMS`, and that
  every file on the release is listed in it — so nothing is published beside the signature that
  the signature does not cover.

A step that went bad in `sign` could take the key, and from there still could not put up a
release; a token stolen from `publish` could put up a release and could not sign it. Taking the
key and using it later is the case this does not close, which is why so little runs before it:
GitHub's own checkout and artifact actions, then a shell script in this repository. The secret is
in the environment of that one step, and the attestation step runs after it. **If the secret is
absent, `sign` fails and nothing is published.** There is no unsigned path out of the workflow.

`scripts/release-signature.sh` is what both jobs run, and `install-test.sh` runs it on every pull
request against a key it makes up, so none of it is first executed on the day of a release
(ADR-0018). The test never sees the real key, and nothing needs it to.

### 3. install.sh checks by default, and skipping is a sentence

The public key is a constant in `install.sh`, not a setting. Everything else in that script can
be pointed elsewhere through the environment so it can be tested; a trusted key that could be
would be a way to skip verification that does not say it is one.

- The signature is checked before the archive is checked against `SHA256SUMS`, and both before
  anything is unpacked. A bad signature is refused the way a bad checksum always was.
- **A release with no signature is refused.** Accepting one would let anyone able to publish a
  release strip the signature and be believed, which is the whole of what it is for.
- **A machine without openssl is refused, not downgraded.** The message says how to install it,
  and names the one way to go on without it.
- That way is **`MESHP_INSECURE_SKIP_SIGNATURE=1`**, and only `1`. The archive is still checked
  against `SHA256SUMS`, and a warning before and after the install says what was not checked.

### 4. The releases from before signing are a closed list, not a version floor

`install.sh` pins v0.1.0, v0.2.0, v0.2.1 and v0.2.2 by the SHA-256 of each release's
`SHA256SUMS`, as GitHub served it on 2026-11-02. Each digest also matches the one GitHub recorded
for that asset when the release workflow uploaded it, by `github-actions[bot]`, within two
seconds of the release being published — so these are the files the workflow produced, not
files replaced since.

Any other version needs a signature. One of the four is installed only when it is named with
`MESHP_VERSION`: none of them was ever a stable release, so nothing legitimate resolves "latest"
to one, and if something does, the default path is not where that should be quietly accepted.

**Why not a floor.** "Signatures are required from v0.3.0" is the obvious transition and it is a
downgrade path. It accepts any unsigned release below the floor, so whoever had taken the account
could publish an unsigned v0.2.3 — or replace v0.2.2's files in place — and both would install.
Comparing versions in POSIX shell, with pre-release suffixes, is a second way to get it wrong.
The list is four lines, it can never grow because the workflow cannot publish anything unsigned,
and it can only shrink.

So the transition is:

1. **This merges.** Installing any of the four by name works as it did, now against its pinned
   checksums.
   The default path still refuses, as it already did, because there is no stable release. A tag
   pushed now fails at `sign`: there is no key in `install.sh` and no secret.
2. **The maintainer creates the key** (below) and merges its public half into `install.sh` and
   `SECURITY.md`. CI refuses the change unless both carry the same P-256 key and `SECURITY.md`
   gives its fingerprint.
3. **The next tag is the first signed release.** From then on `install.sh` verifies it.

A copy of `install.sh` fetched before step 2 carries no key and refuses anything after v0.2.2,
saying to fetch the script again. A copy from before this change does not know about signatures
and keeps installing on the checksum alone, exactly as protected as it always was.

### 5. One-time setup

Once, by the maintainer, on their own machine. Nothing in the repository generates or stores the
private key, and in CI it exists only inside the `sign` job.

```sh
umask 077
openssl ecparam -name prime256v1 -genkey -noout -out meshp-release.key
openssl ec -in meshp-release.key -pubout -out meshp-release.pub
openssl pkey -pubin -in meshp-release.pub -outform DER | shasum -a 256    # the fingerprint

# The environment: the maintainer (aswinsam, 62598639) approves each run, and only v* tags
# may deploy to it. Then the secret, inside it.
gh api -X PUT repos/meshpnet/meshp/environments/release --input - <<'EOF'
{
  "reviewers": [{ "type": "User", "id": 62598639 }],
  "prevent_self_review": false,
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
EOF
gh api -X POST repos/meshpnet/meshp/environments/release/deployment-branch-policies \
  -f name='v*' -f type=tag
gh secret set MESHP_RELEASE_SIGNING_KEY --env release --repo meshpnet/meshp < meshp-release.key
```

`prevent_self_review` is off because there is one maintainer and they push the tags; on the day a
second person can approve, turn it on.

Then, in one pull request: `meshp-release.pub` replaces `RELEASE_KEY=''` in `install.sh` as

```sh
RELEASE_KEY='
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
'
```

and replaces the "no key yet" paragraph in `SECURITY.md` with the same block in a code fence and
its fingerprint. Then the fingerprint goes on meshp.net, which is served from Cloudflare out of a
different repository and is the one place a person can compare it from that GitHub does not
control. Then the private key file is deleted. If an encrypted copy is kept offline, losing the
secret is not a rotation; if not, it is.

## Consequences

**What each layer stops, and what it does not.** Said per attacker, because "signed" on its own
reads as stronger than it is:

| Who | Checksum only (before) | With the signature | With the attestation |
|---|---|---|---|
| A corrupted or truncated download | refused | refused | refused |
| Anyone who can change files on a release but cannot get a signing run approved: a bad step in `publish`, whose token cannot start a workflow; a file swapped on a release already published; a mirror | **installed** | refused — they cannot sign | fails by hand — they have no attestation for their file |
| Anyone who can push a `v*` tag — write access, or a token carrying it | installed | refused while the maintainer declines to approve the signing run; **installed** if they approve it, or if the environment has no reviewer | passes, and the tag, the run and the log entry all stay public |
| Anyone who changes the key in `install.sh` on `main` | installed | **installed** by `curl … main … \| sh`, which fetches their key; refused by a copy fetched earlier, by a copy from a release tag, and by anyone who compares the fingerprint with meshp.net | passes |
| The maintainer's GitHub account, or GitHub | installed | installed | passes |
| An older genuine release offered as the newest | installed | **installed** — a signature carries no date | passes |
| A compromised dependency or toolchain at build time | installed | installed | passes |

The second row is the one this exists for. The third is why the environment has a reviewer: a
tag can be pushed by anything that can write to the repository, and without the approval the
signature would say no more than the attestation does. The fourth row is the bootstrap problem,
stated rather than solved — `main` takes changes only through a pull request that passes CI,
with no bypass for anyone (`scripts/protect-repo.sh`), so changing the key is at least a public
act and not a quiet one. What narrows it costs the person installing one step each:
compare the fingerprint with meshp.net, a different origin; fetch `install.sh` from a release
tag, which the tag ruleset forbids moving or deleting; or keep a copy from a moment you trusted,
which is what a distribution packager or a configuration management repository does anyway.
`SECURITY.md` says how. Without a key held offline by a person — the fifth row — that is as far
as anything here goes.

**The key is in GitHub, so GitHub is in the trust model.** The issue named the alternative — a
key on the maintainer's machine, signing by hand — as the only one that survives GitHub itself
being the problem. It is not taken: with one maintainer, that key sits on the same laptop as the
GitHub session that could misuse it, and a release that waits for a person to sign it is one
that does not happen while they are away. The format leaves it open. The signature is a detached
ECDSA signature over `SHA256SUMS` wherever it is made, so moving signing offline later changes
the workflow and not `install.sh`. The trigger is a second maintainer, or somebody paying for
meshp whose security review asks for it.

**Rotation is a new install.sh.** Copies of the old one refuse releases signed with the new key
— closed, with a message to fetch the script again. After a compromise that is the right
outcome; after a lost secret with no offline copy it is merely the cost.

**openssl becomes a requirement for the default install.** It is present on macOS, and on
Debian and Ubuntu wherever `curl` can make an HTTPS request, because their `ca-certificates`
package depends on it. Other server distributions generally install it; minimal container images
and Alpine may not. Those get a refusal that says how to install it, or the flag.

**The four unsigned releases are pinned, not proven.** The digests are what GitHub served on the
day they were written down, corroborated by GitHub's own upload records and nothing stronger. If
those files had been replaced before then, the pin preserves the replacement. That is the
ceiling for releases nobody signed, and it is why the list can only shrink: dropping it, once a
signed stable release exists, means those versions stop installing through this script, which
is a decision for that day.

**`install-test.sh` now reaches github.com**, to install the real v0.2.2 with the script as it
is. "This does not break what people install today" is a claim about a file on GitHub, so it is
checked against that file. If GitHub is down, that CI job fails.

**A Mac runner joins the release workflow.** The claim is about LibreSSL as much as OpenSSL, and
the runner puts Homebrew's OpenSSL first on its PATH, so the job puts `/usr/bin` back in front
and asserts that `openssl` is the LibreSSL macOS ships before it tests anything.

**Nothing here checks the attestation automatically.** It needs `gh`, a network and Sigstore's
trust root. It is for the person who wants a second, keyless answer, and for anyone auditing a
release long after it was published.

## Alternatives considered

**Attestations alone**, or **cosign keyless**. No key anywhere, which is their whole appeal, and
`install.sh` could not check either on a bare server: verifying a Sigstore bundle means a
certificate chain, a transparency log inclusion proof and a trust root, none of which a shell
script with openssl should be reimplementing. So the default install would check nothing. Kept as
the second layer; this is what would be chosen if `install.sh` could rely on `gh` being present.

**minisign.** The cleanest of the key-based tools, and the one the issue leaned towards. Not on
any machine by default, and its Ed25519 signatures cannot be checked with the LibreSSL macOS
ships. This would be the choice if the deciding constraint were not "already installed".

**GPG.** Not on macOS, a keyring to manage on every machine that verifies, and a signature format
whose failure modes are well documented and still regularly hit.

**Ed25519 through openssl.** Smaller and deterministic, and refused by macOS's LibreSSL 3.3.6.
Revisit if macOS ships a LibreSSL that has it and the versions without it have aged out.

**"Verify the signature if there is one."** The downgrade attack in a sentence: removing the
signature becomes the way to skip the check.

**A version floor.** §4.

**A repository secret rather than an environment secret.** One fewer thing to set up, and
readable by any run a same-repository pull request starts, with nobody asked. The workflow reads
the same name either way, so a key stored as a repository secret still signs; it just loses the
tag restriction and the approval.

**A trusted key that tests can override.** It would let `install-test.sh` run the script itself
rather than a copy. It would also be a silent skip. The test instead runs a copy that differs in
that one assignment, and asserts that it differs in nothing else.

**GitHub's immutable releases.** Complementary rather than an alternative: once a release is
published its files and tag cannot be changed, which closes the "file swapped after publication"
case at the source, and GitHub attests the release itself. It does not stop a new release being
published, and `install.sh` could not check its attestation either. Worth turning on once the
first signed release has gone out through this workflow — `gh release create` already creates a
draft, uploads and then publishes, which is the order immutability requires.
