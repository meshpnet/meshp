# Quickstart

A control plane, a relay and one device joined to a network, on one Linux machine, in
about ten minutes.

This is the smallest thing that works, so you can see the shape of it. It is **not** a
deployment — it runs the control plane over plaintext on loopback and uses a throwaway
database. [Self-hosting](self-hosting.md) is the version you would put in front of real
devices.

Every command on this page has been run. Steps 1 to 4 were executed exactly as written
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

Two secrets, both required. The control plane refuses to start without a secret key, and
leaves its administrative API switched off — returning 503 rather than running open —
without an admin token.

```bash
export MESHP_ADMIN_TOKEN="$(openssl rand -base64 32)"
{
  echo "MESHP_SECRET_KEY=$(openssl rand -base64 32)"
  echo "MESHP_ADMIN_TOKEN=$MESHP_ADMIN_TOKEN"
} >> .env
```

Kept in the shell as well as written to the file, because the rest of this page uses it.
Reading it back out of `.env` is the obvious thing and it does not work: the example file
already declares both keys empty, so appending leaves two lines with the same name.
Compose takes the last one and is fine; a `grep`-and-`cut` takes both, and the resulting
`Authorization` header has a newline in the middle of it — which the server rejects as a
malformed request, with no hint that the token was the problem.

```bash
docker compose up -d
```

Wait for it to be ready. `/readyz` reports the database and the schema, so it answers
"can this serve agents" rather than "is the process alive":

```bash
until curl -fsS http://localhost:8080/readyz >/dev/null 2>&1; do sleep 1; done
echo "control plane is ready"
```

## 2. Make a network

A network needs an organisation to belong to, so make one. The slug is what appears in
URLs and in the page's network picker; the name is what people read.

```bash
ORG=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"acme","name":"Acme"}' \
  http://localhost:8080/api/v1/organizations | jq -r .organization_id)
```

Now the network, with the addresses its devices will be given. A network with no address
pool enrols nobody, so this is refused rather than defaulted — the failure would otherwise
surface much later, as an enrolment that cannot allocate an address.

```bash
NETWORK=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"organization_id\":\"$ORG\",\"slug\":\"hq\",\"name\":\"HQ\",
       \"address_pools\":[\"100.90.0.0/24\",\"fd7c:6d65:7368::/120\"]}" \
  http://localhost:8080/api/v1/networks | jq -r .network_id)

echo "network: $NETWORK"
```

Pick addresses that do not collide with anything your devices already reach. `100.90.0.0/24`
sits inside the carrier-grade NAT range, which is unusual enough on a LAN to be a
reasonable default and is what the rest of these docs assume.

## 3. Mint an enrolment token

```bash
TOKEN=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"max_uses":1,"expires_in_seconds":600}' \
  "http://localhost:8080/api/v1/networks/$NETWORK/enrollment-tokens" | jq -r .token)
```

The token is the credential a device that has nothing yet presents to prove it is allowed
in. It is shown once, it is single-use here, and it expires in ten minutes. Treat it like
a password.

## 4. Join a device

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

## 5. Join a second device

Mint another token — tokens here are single-use, so the first one is spent:

```bash
TOKEN2=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_ADMIN_TOKEN" \
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

Open <http://localhost:8080> and sign in with the same `MESHP_ADMIN_TOKEN` you set in step 1.

The page shows one network: every device and whether its control session is up, every
route group and which devices are offering to carry it, and anything a device reported it
could not apply. It says at the top whether anything needs attention, and it says in the
corner how old what you are looking at is — a poll that fails leaves the last answer on
screen and marks it stale rather than letting old numbers pass for current.

The token is exchanged once for a session cookie that may read and may not write, so the
page cannot mint a token or revoke a device even if somebody else is sitting at it
(ADR-0022). Signing in needs TLS anywhere that is not loopback; `localhost` is the
exception that keeps this quickstart working without a certificate.

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
