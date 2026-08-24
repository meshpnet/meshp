# Self-hosting

The [quickstart](quickstart.md) runs a control plane on loopback over plaintext, which is
fine for seeing the shape of it and nothing else. This is the version you would put in front
of real devices.

Three pieces: a **control plane** (needs PostgreSQL and a certificate), one or more
**relays** (need a UDP port and nothing else), and an **agent** on every device.

The install script deliberately does not set up the first two. They need a database, a
certificate, and decisions about who may reach them, and a script that guessed at any of
that would be configuring a security boundary on your behalf.

## What runs where

The control plane is never in the data path. It decides what should be true and hands that
to agents; traffic between devices does not pass through it, and it can be down without
anybody losing connectivity — agents keep the state they last applied and keep converging on
it. Relays carry ciphertext they cannot read.

That shapes the sizing: the control plane wants a small VM and a reliable database; relays
want bandwidth and a stable address.

## The control plane

### Database

PostgreSQL 14 or later. The control plane applies its own migrations on start, so an empty
database is all it needs — give it a user that owns its own schema.

```
MESHP_DATABASE_URL=postgres://meshp:...@db.internal:5432/meshp?sslmode=require
```

It is the sole source of truth for desired state, so back it up like one. Presence and
health are deliberately not stored here — they are high-frequency and ephemeral (ADR-0012) —
so a restore loses observations rather than configuration.

### Secrets

```
MESHP_SECRET_KEY=<openssl rand -base64 32>
MESHP_ADMIN_TOKEN=<openssl rand -base64 32>
```

`MESHP_SECRET_KEY` is the master secret that enrolment challenges and session signatures are
derived from. The control plane refuses to start without it. **Changing it invalidates every
outstanding challenge and session**, so agents reconnect — survivable, but not something to
do casually.

`MESHP_ADMIN_TOKEN` is the **bootstrap secret**, and it has exactly two jobs (ADR-0024 §5):

- it creates the first account on a deployment that has none, which is the only way a fresh
  deployment can have one;
- it is how you get back in when nobody else can — the last owner left, everybody forgot
  their password — because a self-hosted deployment has no support line to call.

It is not the credential to run anything with. It is a single shared secret with no
identity, so the audit trail can only ever record that "the bootstrap secret" did
something; it cannot be scoped to one network; and it cannot be revoked without locking out
whatever else was using it. Treat it as a root credential for every network on this control
plane, keep it somewhere you would keep a root password, and use an account for everything
else.

**Once an account exists, every use of it is logged at warning level.** That line means
something is still reaching for the shared secret when it could be using an account — an
old script, usually. It is throttled to at most one an hour, so it is a nudge rather than
noise.

Leaving it unset is supported and is the right end state for a deployment whose people all
have accounts. What you lose is the way back in, so do not unset it until somebody other
than you holds the owner role, and be aware that a deployment with no accounts *and* no
bootstrap secret cannot be administered at all without editing the database.

### Accounts, roles and API tokens

Every person gets an account, and what they can do is what their role allows. The four
built-in roles nest:

| Role | What it is for |
| --- | --- |
| `reader` | Sees everything this control plane shows and changes nothing. |
| `operator` | Adds and removes devices, and moves traffic between advertisers when a link dies. Cannot change the access policy, DNS, or which routes exist. |
| `administrator` | Configures networks completely. Cannot create accounts, grant roles, or revoke anybody else's credentials. |
| `owner` | Everything, including deciding who may act. |

A role can be granted across the whole organisation, or narrowed to a single network — which
is what a technician who looks after one customer needs. A grant narrowed to a network never
carries an organisation-wide permission, so somebody given a role inside one network cannot
create accounts across the organisation it belongs to.

`GET /api/v1/permissions` lists the catalogue;
`GET /api/v1/organizations/{id}/roles` lists what this deployment can grant.

**Scripts and CI use API tokens, not passwords and not the bootstrap secret.** A token
belongs to the person who minted it, carries the permissions they name — intersected with
what they hold *at the time it is used*, so demoting somebody demotes their tokens — and is
revoked on its own without touching their password. Mint one at `POST /api/v1/me/tokens`,
list them at `GET /api/v1/me/tokens`, and revoke one at `DELETE /api/v1/me/tokens/{id}`.
An owner can see and revoke everybody's at
`/api/v1/organizations/{id}/tokens`, which is what you want the day somebody leaves.

Tokens expire: ninety days by default, a year at most, and there is no unexpiring one. That
is deliberate — a bearer secret that never expires outlives the reason it was made.

### TLS

Agents refuse a plaintext control URL to anything but loopback, so a control plane serving
real devices needs a certificate. Either supply one:

```
MESHP_TLS_CERT=/etc/meshp/tls/fullchain.pem
MESHP_TLS_KEY=/etc/meshp/tls/privkey.pem
```

or have it obtain one from Let's Encrypt:

```
MESHP_TLS_DOMAINS=control.example.com
MESHP_TLS_CACHE_DIR=/var/lib/meshp/certs
```

The automatic path needs port 80 reachable for the challenge and a cache directory that
survives restarts — without one you will re-issue on every restart and meet a rate limit at
the worst time.

Terminating TLS at a reverse proxy instead is a perfectly good choice. The systemd unit does
not force either way; it just has `CAP_NET_BIND_SERVICE` so it can hold 443 without running
as root.

### Relays

Tell the control plane where its relays are, and give it the private half of a signing key:

```bash
meshp-control --generate-relay-key      # prints a keypair; use it once, keep the output
```

```
MESHP_RELAY_SIGNING_KEY=<the private half>
MESHP_RELAYS=lon1=relay1.example.com:51820;fra1=relay2.example.com:51820
```

Several addresses per relay are allowed — `id=host:port,host:port` — and agents try them in
order, so put the port most likely to get through a hostile network first.

Without these, the control plane starts and warns that peers will know about each other and
be unable to reach each other. That is not a soft failure to skim past: nothing discovers
direct paths yet, so **a deployment with no relay has no data plane**.

### Running it

```bash
sudo install -m 0755 meshp-control /usr/local/bin/
sudo useradd --system --no-create-home meshp
sudo install -d -o meshp -g meshp /etc/meshp /var/lib/meshp
sudo install -m 0600 -o meshp -g meshp control.env /etc/meshp/control.env
sudo install -m 0644 systemd/meshp-control.service /etc/systemd/system/
sudo systemctl enable --now meshp-control
```

The unit runs unprivileged and reads its configuration from an owner-only environment file
rather than from the unit itself, which keeps the database URL, the secret key and the admin
token out of `systemctl show`.

Check it with `/readyz`, which reports the database and the schema — so it answers "can this
serve agents" rather than "is the process alive". `/healthz` is the liveness probe.

## A relay

A relay needs the public half of the signing key and a UDP port. It verifies a capability it
cannot mint, so a compromised relay cannot invent access — and it only ever sees ciphertext
(ADR-0016, ADR-0017).

```
MESHP_RELAY_ISSUER_KEY=<the public half>
MESHP_RELAY_LISTEN=:51820
MESHP_RELAY_ADMIN_ADDR=127.0.0.1:9090
```

```bash
sudo install -m 0644 systemd/meshp-relay.service /etc/systemd/system/
sudo systemctl enable --now meshp-relay
```

Keep the admin address on loopback. It is diagnostics, not an API anyone else should reach.

## Devices

```bash
curl -fsSLO https://raw.githubusercontent.com/meshpnet/meshp/main/scripts/install.sh
less install.sh && sudo sh install.sh
sudo systemctl enable --now meshpd
sudo meshp join <token> --control-url https://control.example.com
```

The agent runs as root because it creates a WireGuard interface, writes routes and loads
firewall rules. `meshp` does not: it is a thin client that asks the daemon over a local unix
socket, and the daemon is what generates and stores key material. A private key never
crosses that socket in either direction.

That socket is owner-only, so `meshp` needs `sudo` too. `meshpd --socket-group <group>`
relaxes it to a group — read that as the privilege grant it is, because anything able to
reach the socket can enrol this device and decide where its traffic goes.

## Upgrading

Agents and the control plane are versioned independently and the protocol is
backward-compatible within a major version, so the order does not matter much. Upgrade the
control plane first if you want new server-side behaviour available when agents arrive
asking for it.

An agent that has been offline longer than `MESHP_DELTA_RETENTION` (72 hours by default) is
sent a full snapshot rather than a delta when it returns. That is correct but expensive, so
the setting is the trade-off between the size of the change log and how cheap a reconnection
is after a weekend or a closed laptop.

## What to watch

- **`/readyz` on the control plane.** It goes unready when the database is unreachable or
  the schema is behind, which are the two states where agents cannot be served.
- **Convergence lag.** The gap between a network's desired version and what each device has
  applied. A device that never closes the gap is a broken agent; a network where the gap is
  widening is a broken control plane.
- **Certificate expiry**, if you are supplying your own.

## What is not here yet

Users, roles and sessions — the admin API is one shared token. Multi-tenant management,
white-label branding and billing live in the hosted service rather than here (ADR-0009); the
boundary is an API rather than a licence, and nothing in this repository is crippled to
create it.

A web dashboard. Everything above is the API, because the API is all there is today.
