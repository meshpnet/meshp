# Quickstart

A control plane, a relay and one device joined to a network, on one Linux machine, in
about ten minutes.

This is the smallest thing that works, so you can see the shape of it. It is **not** a
deployment — it runs the control plane over plaintext on loopback and uses a throwaway
database. [Self-hosting](self-hosting.md) is the version you would put in front of real
devices.

Every command on this page has been run. Steps 1 to 5 were executed exactly as written
against a fresh checkout; the tunnel coming up is covered by `make e2e-tunnel` in CI, on
Linux, because that is the only place it can be. If something here does not work, that is a
bug and worth an issue.

## What you need

- Linux, with root. This page is written for Linux because that is where the data plane is
  complete. macOS is complete too — a tunnel, mesh names, a full-tunnel default route and
  fail-closed egress — except that it cannot enforce a network's packet filter. Windows
  brings a tunnel up and has nothing above it yet: no names, no full tunnel, no fail-closed
  egress. The mobile platforms enrol, hold an address, and report honestly that they have no
  tunnel.
- Docker with the Compose plugin, for the control plane and its database.
- A kernel that can create WireGuard interfaces. `sudo ip link add dev wgcheck type
  wireguard && sudo ip link del dev wgcheck` tells you in one line.

## 1. Start a control plane

```bash
git clone https://github.com/meshpnet/meshp.git
cd meshp
cp .env.example .env
```

One secret. `MESHP_SECRET_KEY` is what enrolment challenges and session signatures are
derived from, and the control plane refuses to start without it.

```bash
echo "MESHP_SECRET_KEY=$(openssl rand -base64 32)" >> .env
```

You may have seen `MESHP_ADMIN_TOKEN` mentioned elsewhere. It is a shared secret that can do
everything, it exists so a deployment with no accounts has a way back in, and **this page
does not use it**. Leave it unset until you want that way back in; [self-hosting](self-hosting.md)
says what it is for.

```bash
docker compose up -d
```

Wait for it to be ready. `/readyz` reports the database and the schema, so it answers
"can this serve agents" rather than "is the process alive":

```bash
until curl -fsS http://localhost:8080/readyz >/dev/null 2>&1; do sleep 1; done
echo "control plane is ready"
```

## 2. Give yourself an account

One command, against the database, before anything is serving:

```bash
docker compose run --rm control --bootstrap \
  --organisation acme \
  --email you@example.com \
  --token-permissions organization.networks.create,organization.networks.read,network.read,network.enrollment_tokens.write
```

It asks for a password twice — on the terminal, so it is never in your shell history — and
prints three things:

```
organisation  acme
account       you@example.com (owner)
token         meshp_api_...
```

**The first person in an organisation becomes its owner**, because somebody has to be able
to grant a role and on a fresh organisation there is nobody who can. Everybody you add later
is an administrator unless you say otherwise.

**The token is shown once.** It carries only the permissions you named above and never more
than you hold at the time it is used, so demoting yourself later demotes it too. Keep it in
the shell for the rest of this page:

```bash
export MESHP_TOKEN=meshp_api_...   # the token printed above
```

Ask for no permissions and it mints none — say what a credential is for, or do without one.
`GET /api/v1/permissions` lists what there is to choose from once you are signed in.

## 3. Make a network

With your token now. Note that you do not name the organisation: a token acts within its
owner's, and you belong to exactly one.

```bash
NETWORK=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"hq","name":"HQ",
       "address_pools":["100.90.0.0/24","fd7c:6d65:7368::/120"]}' \
  http://localhost:8080/api/v1/networks | jq -r .network_id)

echo "network: $NETWORK"
```

A network with no address pool enrols nobody, so this is refused rather than defaulted —
the failure would otherwise surface much later, as an enrolment that cannot allocate an
address.

Pick addresses that do not collide with anything your devices already reach. `100.90.0.0/24`
sits inside the carrier-grade NAT range, which is unusual enough on a LAN to be a
reasonable default and is what the rest of these docs assume.

## 4. Mint an enrolment token

```bash
TOKEN=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"max_uses":1,"expires_in_seconds":600}' \
  "http://localhost:8080/api/v1/networks/$NETWORK/enrollment-tokens" | jq -r .token)
```

Two kinds of token, and they are not interchangeable. `MESHP_TOKEN` is yours and
authenticates you to the API; this one is a device's, it is presented once by a machine
that has nothing yet, and it is spent on use. The prefixes tell them apart at a glance:
`meshp_api_` and `meshp_tok_`.

It is single-use here and expires in ten minutes. Treat it like a password.

## 5. Join a device

Build the binaries, or install a release:

```bash
make build     # puts meshp and meshpd in ./bin
```

Start the agent and join:

```bash
sudo ./bin/meshpd &
sudo ./bin/meshp join "$TOKEN" --control-url http://localhost:8080
sudo ./bin/meshp status
```

The control plane's address is given to `join`, not to the daemon: a device can hold
memberships in several networks at once (ADR-0004), so which control plane to talk to is a
property of a membership rather than of the machine.

Both commands need `sudo`. `meshp` is a thin client: everything that touches a key or the
network stack is a request to `meshpd` over a local unix socket, and that socket is
owner-only because anything able to reach it can enrol this device and decide where its
traffic goes.

`meshp status` should show a live session and an applied state version that matches the
network's. With one device there are no peers yet, which is correct rather than broken.

## 6. Join a second device

Mint another token — tokens here are single-use, so the first one is spent:

```bash
TOKEN2=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"max_uses":1,"expires_in_seconds":600}' \
  "http://localhost:8080/api/v1/networks/$NETWORK/enrollment-tokens" | jq -r .token)
```

On the second machine, point it at the first machine's address rather than `localhost`,
and run the same two commands. Agents refuse a plaintext control URL to anything but
loopback, so a second machine needs TLS — which is [self-hosting](self-hosting.md), and is
the point at which this stops being a demo.

To see two devices talking without leaving one machine, run
`make e2e-tunnel`: it stands the whole stack up in network namespaces, brings real tunnels
up between two agents, and asserts a packet crosses.

## What you have

Two devices with stable private addresses, reaching each other through a relay. Nothing
discovers direct paths yet, so everything is relayed — that is relay-first working as
designed rather than a gap (ADR-0002), and a direct path is an optimisation layered on
later rather than a prerequisite for connectivity.

## Look at it

Open <http://localhost:8080> and sign in with the email address and password from step 2.

The page shows one network: every device and whether its control session is up, every
route group and which devices are offering to carry it, and anything a device reported it
could not apply. It says at the top whether anything needs attention, and it says in the
corner how old what you are looking at is — a poll that fails leaves the last answer on
screen and marks it stale rather than letting old numbers pass for current.

**What you can change there is what your role allows.** As the owner you get a button to
create an enrolment token and a button to revoke a device — the same two things steps 5 and
6 did by hand. Somebody signed in as a reader sees the same network and no buttons at all,
because a control that would be refused is never drawn.

Anything you do there is recorded against your name, and shown on the same page: revoke a
device and the history panel below says who did it.

Signing in needs TLS anywhere that is not loopback; `localhost` is the exception that keeps
this quickstart working without a certificate.

## About that admin token you did not need

Nothing on this page used `MESHP_ADMIN_TOKEN`, and the deployment you just built has none.

That is the point. It is a single shared secret that can do everything, with no identity —
so the audit trail can only ever record that "the bootstrap secret" did something, and it
cannot be scoped or revoked without locking out whatever else is using it.

What it is still good for is getting back in when nobody can sign in: the last owner has
left, or everybody has forgotten their password. A self-hosted deployment has no support
line to call, and the alternative recovery is editing the database by hand. Set it if you
want that, keep it where you keep a root password, and expect a warning in the log every
time something uses it once accounts exist.

## Where to go next

- [Self-hosting](self-hosting.md) — TLS, systemd, backups: the version you would actually run.
- [Route groups](route-groups.md) — make one device carry an office LAN, or the whole internet, with failover.
- [Troubleshooting](troubleshooting.md) — when something refuses to connect.

## Tearing it down

```bash
sudo ./bin/meshp down 2>/dev/null || sudo pkill meshpd
docker compose down -v
```

`meshp down` is not implemented yet, so the agent is stopped directly. Note that a device
that was claiming a default route leaves firewall rules behind on purpose — they are what
stop traffic leaking when the tunnel drops (ADR-0011), and they survive the process dying.
`meshp doctor` finds them and prints the exact commands to remove them.
