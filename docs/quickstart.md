# Quickstart

A control plane, a relay and one device joined to a network, on one Linux machine, in
about ten minutes.

This is the smallest thing that works, so you can see the shape of it. It is **not** a
deployment — it runs the control plane over plaintext on loopback and uses a throwaway
database. [Self-hosting](self-hosting.md) is the version you would put in front of real
devices.

Every command on this page has been run. Steps 1 to 6 were executed exactly as written
against a fresh checkout; the tunnel coming up is covered by `make e2e-tunnel` in CI, on
Linux, because that is the only place it can be. If something here does not work, that is a
bug and worth an issue.

## What you need

- Linux, with root. The data plane is Linux-only today: elsewhere a device enrols, holds
  an address, and reports honestly that it has no tunnel.
- Docker with the Compose plugin, for the control plane and its database.
- A kernel that can create WireGuard interfaces. `sudo ip link add dev wgcheck type
  wireguard && sudo ip link del dev wgcheck` tells you in one line.

## 1. Start a control plane

```bash
git clone https://github.com/meshpnet/meshp.git
cd meshp
cp .env.example .env
```

Two secrets. `MESHP_SECRET_KEY` is required — the control plane refuses to start without
it. `MESHP_ADMIN_TOKEN` is the **bootstrap secret**: it exists to create the first account
on a deployment that has none, and to get back into one that has locked itself out. It is
used twice on this page and then not again.

```bash
export MESHP_BOOTSTRAP="$(openssl rand -base64 32)"
{
  echo "MESHP_SECRET_KEY=$(openssl rand -base64 32)"
  echo "MESHP_ADMIN_TOKEN=$MESHP_BOOTSTRAP"
} >> .env
```

Kept in a shell variable as well as written to the file, because steps 2 and 3 use it.
Reading it back out of `.env` is the obvious thing and it does not work: the example file
already declares both keys empty, so appending leaves two lines with the same name.
Compose takes the last one and is fine; a `grep`-and-`cut` takes both, and the resulting
`Authorization` header has a newline in the middle of it — which the server rejects as a
malformed request, with no hint that the token was the problem.

It is called `MESHP_BOOTSTRAP` in the shell here to keep it visible that this is not the
credential you will be using. A shared secret that can do everything, with no identity
behind it, is the thing accounts exist to replace (ADR-0024).

```bash
docker compose up -d
```

Wait for it to be ready. `/readyz` reports the database and the schema, so it answers
"can this serve agents" rather than "is the process alive":

```bash
until curl -fsS http://localhost:8080/readyz >/dev/null 2>&1; do sleep 1; done
echo "control plane is ready"
```

## 2. Make an organisation and give yourself an account

Both with the bootstrap secret, because there is nobody yet who could do it otherwise.
This is the whole of what that secret is for.

An organisation is the tenant a network belongs to. The slug is what appears in URLs and
in the page's network picker; the name is what people read.

```bash
ORG=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_BOOTSTRAP" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"acme","name":"Acme"}' \
  http://localhost:8080/api/v1/organizations | jq -r .organization_id)
```

Now an account for yourself. **The first person in an organisation becomes its owner** —
somebody has to be able to grant a role, and on a fresh organisation there is nobody who
can. Everybody you add afterwards is an administrator unless you say otherwise.

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_BOOTSTRAP" \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","name":"You","password":"a passphrase you will remember"}' \
  "http://localhost:8080/api/v1/organizations/$ORG/users" | jq -r '.email + " is the " + .role'
```

That is the last time the bootstrap secret appears on this page. From here on you are a
person, and everything is done as you.

## 3. Sign in and mint a token for your scripts

Sign in, keeping the session cookie:

```bash
curl -fsS -c meshp-cookies.txt -o /dev/null -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"a passphrase you will remember"}' \
  http://localhost:8080/api/v1/ui/session
```

Then mint an API token. This is the credential the rest of this page uses, and the one to
put in a script or a CI job: it belongs to you, it carries the permissions you name and
never more than you hold, and it can be revoked on its own without touching your password.

```bash
MESHP_TOKEN=$(curl -fsS -b meshp-cookies.txt \
  -H "Origin: http://localhost:8080" \
  -H 'Content-Type: application/json' \
  -X POST -d '{
    "name": "quickstart",
    "permissions": [
      "organization.networks.create", "organization.networks.read",
      "network.read", "network.devices.read", "network.enrollment_tokens.write"
    ]
  }' \
  http://localhost:8080/api/v1/me/tokens | jq -r .token)

echo "token: ${MESHP_TOKEN:0:18}..."
```

Three things about that request are worth a sentence each.

**`Origin` is required**, and only for a cookie. Anything that changes something and
authenticates with a session cookie has to say which site it came from — a browser always
does, and `curl` has to be told. A request carrying a bearer token instead, like every
other command on this page, needs no such header.

**Permissions are named, not implied.** A credential minted without saying what it is for
ends up being used for everything, and this is the one moment somebody is thinking about
the question. `GET /api/v1/permissions` lists what there is to choose from.

**The token is shown once.** The control plane stores only a hash, so if you lose it you
mint another and revoke this one — which is `DELETE /api/v1/me/tokens/{id}`, and
`GET /api/v1/me/tokens` lists what you have out.

## 4. Make a network

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

## 5. Mint an enrolment token

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

## 6. Join a device

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

## 7. Join a second device

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

## What to do with the bootstrap secret

Leave it configured, and stop using it.

It is how you get back in if everybody forgets their password or the last owner leaves, and
a self-hosted deployment has no support line to call — so removing it would mean the only
recovery was editing the database by hand. What it should not be is the credential in your
scripts: it has no identity, so the audit trail can only ever say "the bootstrap secret did
this", and it cannot be scoped or revoked without locking out whatever else is using it.

Once an account exists, every use of it is logged at warning level for exactly that reason.
If you see that line, something is still reaching for the shared secret when it could be
using an account.

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
