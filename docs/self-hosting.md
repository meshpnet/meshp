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

`MESHP_ADMIN_TOKEN` is the **bootstrap secret**, and it now has exactly one job: getting you
back in when nobody else can — the last owner has left, or everybody has forgotten their
password — because a self-hosted deployment has no support line to call.

It used to have two. Creating the first account was the other, and `meshp-control
--bootstrap` does that against the database instead, so **a deployment can run without ever
setting this**:

```bash
meshp-control --bootstrap --organisation acme --email you@example.com
```

It asks for a password on the terminal, makes the first person an owner, and can print an
API token if you name the permissions it should carry. It refuses to run on a deployment
that already has accounts, and adopts an organisation that already exists rather than
refusing.

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

### Running more than one control plane

One `meshp-control` is a single point of failure. More than one works, and needs one setting:

```
MESHP_REPLICAS=2
```

That is a statement about the deployment rather than a count anything verifies — nothing in
a replica knows how many others exist. What it decides is whether the replica connects to
the bus that carries "network N changed" between them (ADR-0025), which is PostgreSQL's own
`LISTEN`/`NOTIFY`. **There is no second data store to run**: redundancy costs you a second
container and nothing else.

Point every replica at the same PostgreSQL and put them behind whatever already balances
your traffic. They share no state of their own; PostgreSQL is the source of truth and always
was.

Two things are worth knowing before you rely on it.

**An agent holds a session with one replica at a time**, so a replica going away drops its
agents and they reconnect — to whichever replica the balancer gives them, with no loss of
configuration. What they lose is the seconds it takes to notice.

**Whether a device is connected is shared; what it last reported is not.** Every replica
knows which devices have a control session open, because that is recorded when a session
opens and closes. What a device says on each heartbeat — the version it applied, what its
tunnel is doing — stays in the replica that received it, which is deliberate: writing it
where every replica could see it would mean a database write per heartbeat per device
(ADR-0012).

So the overview shows every connected device, and for the ones attached to another replica
it says `reported to another replica` in place of tunnel detail rather than implying the
device has gone quiet.

Leave it at 1, or unset, for a single-replica deployment. A replica that connects to the bus
when there is nobody to talk to holds a database connection open for nothing.

### Taking a relay out of service

`MESHP_RELAYS` names your relays and still does. What it cannot express is "stop sending new
sessions here", which is what you want before turning a machine off.

```bash
curl -fsS -X PUT -H "Authorization: Bearer $MESHP_BOOTSTRAP" \
  -H 'Content-Type: application/json' -d '{"state":"draining"}' \
  http://localhost:8080/api/v1/relays/relay1/state
```

`GET /api/v1/relays` lists them with their states. Three states:

| | |
| --- | --- |
| `active` | agents are told about it |
| `draining` | agents are not told about it; sessions already using it keep working |
| `disabled` | agents are not told about it, and it is not expected back |

**Draining does not move anything.** A drained relay is still running and still carrying
what it has; what stops is new sessions being pointed at it. It empties as devices reconnect
for their own reasons, which is gentle and is not quick.

**Nothing here reports when it is empty.** Relays do not check in, so the control plane
knows which relays exist and not whether any traffic is flowing through them. Judging when
it is safe to switch a drained relay off is yours to do, and `last_seen_at` in the listing
is always null for the same reason. That is the remaining half of #128.

A restart does not undo a drain. Endpoints are refreshed from `MESHP_RELAYS` on every boot;
state is not, because a restart quietly putting a relay back into service is the failure this
exists to remove. Removing a relay from `MESHP_RELAYS` removes it from the list entirely.

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
```

**Port 443 is enough.** The challenge is answered over TLS itself (`TLS-ALPN-01`), so a host
that only accepts 443 can still obtain and renew a certificate — which is worth knowing,
because some providers firewall port 80 by default and the failure would otherwise look like
a DNS problem. Port 80 is used when it is reachable, both for the other challenge type and to
redirect anyone who types `http://`.

**The certificate has to be saved somewhere that survives a restart**, or every restart asks
Let's Encrypt again and a crash loop exhausts a week's rate limit in an afternoon. The unit
below handles this: `StateDirectory=meshp-control` gives the service `/var/lib/meshp-control`,
which is where `MESHP_TLS_CACHE_DIR` points by default. Set it only if you want it elsewhere —
and if you do, make sure the unit can write there, because `ProtectSystem=strict` leaves
everything else read-only.

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
sudo install -d -o meshp -g meshp /etc/meshp
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
```

Then start it the way this machine starts services, and join:

```bash
# Linux
sudo systemctl enable --now meshpd
```

```bash
# macOS
sudo install -m 0644 -o root -g wheel deploy/launchd/net.meshp.meshpd.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/net.meshp.meshpd.plist
```

```bash
sudo meshp join <token> --control-url https://control.example.com
```

The Mac daemon is loaded into the **system** domain rather than a user's, because creating a
utun goes through `PF_SYSTEM` and needs root — and because a device on a network should not
stop being on it when somebody logs out. Its log goes to `/var/log/meshpd.log`, since there
is no journal to inherit. `sudo launchctl kickstart -k system/net.meshp.meshpd` restarts it,
and `sudo launchctl bootout system/net.meshp.meshpd` stops it for good.

```powershell
# Windows, as Administrator. wintun.dll ships beside meshpd.exe (ADR-0028).
sc.exe create meshpd binPath= "C:\Program Files\meshp\meshpd.exe" start= auto
sc.exe start meshpd
```

The space after `binPath=` and `start=` is `sc.exe`'s own syntax and is not a typo; without it
the command is rejected. The service logs to `meshpd.log` inside its state directory, because a
Windows service has no console and anything written to stderr is discarded. `sc.exe stop meshpd`
stops it and `sc.exe delete meshpd` removes it.

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
