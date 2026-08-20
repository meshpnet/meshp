<h1 align="center">meshp</h1>

<p align="center">
  Self-hostable private networking built on WireGuard.<br>
  Connect Linux, Windows, macOS, Android and iOS into one private network — with
  policy, private DNS, LAN gateways and automatic egress failover.
</p>

<p align="center">
  <a href="#status"><img alt="status: pre-alpha" src="https://img.shields.io/badge/status-pre--alpha-orange"></a>
  <a href="LICENSE"><img alt="license: Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

---

## Status

**Pre-alpha, and packets now cross.** On Linux, a device enrols, brings up a kernel
WireGuard interface, attaches to a relay and carries traffic to its peers through it.
Everything is relayed: nothing discovers direct paths yet, which is the design working
as intended rather than a gap to apologise for (ADR-0002).

What exists: enrolment end to end, a control channel carrying versioned desired state,
kernel WireGuard interfaces reconciled against what the control plane asked for
(ADR-0015), a relay that verifies a capability it cannot mint, and the agent side that
attaches to it (ADR-0016, ADR-0017).

Devices can also be revoked: an administrator removes one and every other agent drops
its key, which is what actually cuts it off — enforcement is at the peers, not at the
device being removed, so a machine that is switched off or hostile is out just the same.

Policy works on Linux: an ACL document published to a network compiles per device and
is enforced by nftables at the destination (ADR-0007). A network with no policy is
unfiltered, and a host that cannot enforce says so rather than accepting a policy and
ignoring it.

The control plane serves TLS, from a certificate you supply or one it obtains from
Let's Encrypt, and agents refuse a plaintext control URL to anything but loopback.

Full-tunnel egress works on Linux, and fails closed (ADR-0011). A device sending
everything through the tunnel refuses traffic that would leave any other way, so a dropped
tunnel cannot quietly put a real address back on the wire — and those rules are firewall
state, so they survive the agent being killed. `meshp doctor` explains that to whoever
finds the machine, without needing a network to do it.

Route groups carry traffic and fail over. A device is told an ordered list of advertisers
and picks among them itself, so it can move off a broken one during a control-plane outage
(ADR-0003) — and it decides by sending real traffic through the advertiser to targets an
administrator named, rather than by trusting a WireGuard handshake, which a gateway with a
dead uplink answers perfectly.

Names resolve, on Linux. `meshpd` runs a resolver on loopback and answers from the desired
state it has already applied, so names keep working when the control plane is unreachable,
the same way the tunnel keeps carrying traffic (ADR-0021). A device is
`<device>.<network>.internal` by default, and a bare name resolves only when exactly one of
this device's memberships holds it — when two do it does not resolve, and the error names
both fully-qualified alternatives rather than picking one.

Networks that collide are held at once. Two customers both using `192.168.1.0/24` is the
ordinary case for whoever supports both, and one flat routing table cannot hold that prefix
twice. Each colliding prefix is given a mapped range allocated by the control plane, and the
name layer resolves to the mapped address (ADR-0020), so a technician reaches both rather
than reaching whichever membership was written last.

What does not, and matters: direct paths are unimplemented, and the data plane is
Linux-only — elsewhere a device enrols, holds an address, and reports honestly that it has
no tunnel and cannot filter. There is no web dashboard and no user accounts: the
administrative API is one shared token.

It is public from the first commit because the design decisions are the
interesting part and we would rather be argued with early.

Do not deploy this. Read [`docs/adr/`](docs/adr/) instead.

If you want to try it anyway, [`docs/`](docs/) has a quickstart, a self-hosting guide, a
guide to route groups and a troubleshooting page. Every command in them has been run against
a live control plane rather than written from the source.

## What it is

Every device runs an agent and gets a stable private address. Devices reach each
other directly when the network allows it and through a relay when it does not.
A control plane decides *what should be true* — who may reach what, which names
resolve, which machine provides internet egress — and every agent converges
toward that.

What makes meshp different from the other WireGuard orchestrators:

- **Route groups.** Internet egress, LAN gateways and service gateways are one
  primitive: a set of prefixes with an ordered set of health-checked
  advertisers. Redundancy for your office subnet router and redundancy for your
  exit node are the same feature, so both exist.
- **Egress failover that actually fails over.** When an exit node's internet
  breaks, traffic moves to another node in the group without an admin touching
  anything — and if you have allowlisted an outbound IP with a bank or a vendor,
  the group keeps that IP across the failover.
- **Built for the people who manage other people's networks.** A device can hold
  memberships in many networks at once, because a technician supporting forty
  customers should not need forty laptops.
- **Relay-first.** Connectivity starts on a relay and upgrades to a direct path
  when hole punching succeeds. Your network working is never contingent on NAT
  traversal winning.

## Honest comparison

| | meshp | Tailscale | Headscale | NetBird |
|---|---|---|---|---|
| Self-hostable control plane | yes | no | yes | yes |
| Control plane open source | yes | no | yes | yes |
| Automatic exit-node failover | yes | no | no | partial (route groups) |
| Stable egress IP across failover | yes | n/a | n/a | no |
| Device in multiple networks at once | yes | no | no | no |
| NAT traversal maturity | **immature** | excellent | excellent (Tailscale clients) | good |
| Client platform maturity | **immature** | excellent | n/a | good |
| Production ready today | **no** | yes | yes | yes |

If you need something that works this afternoon, use one of the other three. We
mean that. The two rows in bold are where we are years behind, and no amount of
architecture makes up for it yet.

## Install

On a device that is joining a network, there is no need to build anything:

```bash
curl -fsSLO https://raw.githubusercontent.com/meshpnet/meshp/main/scripts/install.sh
less install.sh && sudo sh install.sh
```

It checks the download against the release's checksums, installs `meshp` and `meshpd`,
and installs the agent's systemd unit without starting it — joining a network needs a
token, so it stops before making that decision for you.

```bash
sudo systemctl enable --now meshpd
sudo meshp join <token>
```

If anything ever refuses to connect on a device running meshp, `meshp doctor` says what is
being blocked and why, and works on a machine with no internet access at all.

The control plane and the relay are deliberately not installed by that script: they need a
database, a certificate, and decisions about who may reach them. Their unit files ship in
the same archive, under `systemd/`.

## Building it yourself

Requires Go 1.26+, Docker and Node 20+.

```bash
git clone https://github.com/meshpnet/meshp.git
cd meshp
cp .env.example .env

# Both are required. The control plane refuses to start without a secret key, and
# leaves the administrative API switched off without an admin token.
#
# Kept in the shell too, because the commands below need it. Reading it back out of
# .env does not work: the example declares both keys empty, so appending leaves two
# lines with the same name — compose takes the last, a grep takes both.
export MESHP_ADMIN_TOKEN="$(openssl rand -base64 32)"
{
  echo "MESHP_SECRET_KEY=$(openssl rand -base64 32)"
  echo "MESHP_ADMIN_TOKEN=$MESHP_ADMIN_TOKEN"
} >> .env

make build
docker compose up -d
```

Then enrol a device. An organisation still has to be seeded with SQL — there is no API for
creating one yet — and everything after that is API calls:

```bash
ORG=$(docker compose exec -T postgres psql -U meshp -d meshp -tAqc \
  "INSERT INTO organizations (slug,name) VALUES ('acme','Acme') RETURNING id")

NETWORK=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"organization_id\":\"$ORG\",\"slug\":\"hq\",\"name\":\"HQ\",
       \"address_pools\":[\"100.90.0.0/24\",\"fd7c:6d65:7368::/120\"]}" \
  http://localhost:8080/api/v1/networks | jq -r .network_id)

TOKEN=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"max_uses":1,"expires_in_seconds":600}' \
  "http://localhost:8080/api/v1/networks/$NETWORK/enrollment-tokens" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

sudo ./bin/meshpd &                # holds the keys and the sessions
sudo ./bin/meshp join "$TOKEN"
sudo ./bin/meshp status
```

`meshp` is a thin client: every command that touches a key or the network stack is a
request to `meshpd` over a local unix socket, and the daemon is what generates and
stores key material. Both commands need `sudo` because that socket is owner-only by
default — anything able to reach it can enrol this device and, once tunnels exist,
decide where its traffic goes. `meshpd --socket-group <group>` relaxes that to a
group, which is a privilege grant and should be read as one.

```bash
make help         # every available target
make ci           # everything CI runs, except the jobs that need Postgres or Docker
make e2e          # enrol a device against a real database, start to finish
make image        # build the server-side container image
make image-smoke  # start that image against a real database and wait for readiness
make dataplane    # real WireGuard interfaces, and a packet across a tunnel
make e2e-tunnel   # the whole stack on Linux, with tunnels that really come up
```

`make ci` deliberately excludes the container build and the data plane: one needs Docker,
the other needs Linux and root, and both add a minute to a target meant to be run
constantly. CI gates them instead. `make dataplane` runs the WireGuard tests in a
privileged Linux container, so it works from macOS; on a Linux host,
`sudo -E go test ./internal/wglink/` is the same thing without Docker.

## How this is tested

The claims in [`docs/INVARIANTS.md`](docs/INVARIANTS.md) are meant to be checked
by machines, not asserted in a README. So the interesting tests are properties
rather than examples:

| Invariant | How it is checked |
|---|---|
| An unhealthy advertiser gets no new assignments (8) | 3,000 randomised combinations of health and administrative state, asserting nothing failing, disabled, or draining-for-someone-else is ever offered |
| Failover never flaps (10) | Randomised observation sequences asserting no advertiser's health may improve twice inside one cooldown, plus a simulated hour of an advertiser breaking and recovering as fast as it can be observed |
| An address is not reissued immediately after release (17) | A model-based test running an allocator against a naive shadow implementation, checking every rule after every operation |
| Selection is deterministic | Shuffling the input 200 times must not change the output — a weak comparator would otherwise leak Go's randomised map order onto the wire |
| Capacity changes are minimally disruptive | 10,000 devices: removing 1 of 5 advertisers must move ~1/5 of them and leave the rest untouched |

Anything that depends on elapsed time uses an injected clock, so a test for "does
not fail back for five minutes" takes microseconds and actually proves something.
Three fuzz targets run their seed corpora on every pull request and get real time
nightly.

Two of these tests have already earned their place. The minimal-disruption test
caught a hash whose distribution was skewed enough that adding one advertiser to
four moved half the fleet instead of a fifth. The IPAM model test independently
found an allocation sweep that reported a full pool while an address was free.

## Architecture

```
                       ┌────────────────────────────┐
                       │       meshp-control        │
                       │                            │
                       │  identity · IPAM · policy  │
                       │  DNS · route groups        │
                       │  health · desired state    │
                       └─────────────┬──────────────┘
                                     │
                            desired state (never traffic)
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
     meshpd                       meshpd                       meshpd
   (a laptop)                   (a server)              (advertises 0.0.0.0/0
        │                            │                   and 192.168.1.0/24)
        │                            │                            │
        └──────── WireGuard ─────────┘                            ├──▶ LAN
                       │                                          └──▶ internet
              ┌────────┴────────┐
              ▼                 ▼
        direct path      meshp-relay (fallback, sees only ciphertext)
```

The control plane is never in the data path. Relays never decrypt. Private keys
never leave the device they were generated on.

## Repository layout

```
proto/          device control protocol — the most expensive thing to change
migrations/     PostgreSQL schema
cmd/meshp           CLI (unprivileged)
cmd/meshpd          device agent (privileged, owns the WireGuard key)
cmd/meshp-control   control plane
cmd/meshp-relay     encrypted packet relay
internal/       implementation, grouped by subsystem
docs/           guides, invariants, and the decision records
docs/adr/       why things are the way they are — start here
deploy/docker/  self-hosting
```

## The project

meshp is developed by the [meshpnet](https://github.com/meshpnet)
organisation. Everything that touches a packet is open source and always will
be: the agent, the CLI, the protocol, the relay, the control plane, policy, DNS,
route groups and failover. Our hosted service adds multi-tenant management,
white-label branding and billing on top of this same code, over its public API —
it is not a fork and it does not unlock features that are disabled here.

Related repositories:

| Repo | What | Status |
|---|---|---|
| [`meshp`](https://github.com/meshpnet/meshp) | this one — agent, CLI, control plane, relay | public |
| `meshp-infra` | deployment: how a control plane and its relays are stood up | private, empty |
| `meshp-web` | the website at meshp.net | private |
| `meshp-cloud` | the commercial layer, over this one's public API (ADR-0009) | private, empty |
| `meshp-ios` | iOS client | not started |
| `meshp-android` | Android client | not started |
| `meshp-testlab` | network-namespace conformance suite, including NAT types and failover | not started |
| `meshp-sdk` | generated API clients | not started |

They are created when there is something to put in them, not in advance. Almost
everything still lives here, because almost everything is Go, open source and released
together; a repository splits off only when it crosses a licence boundary, a toolchain
or a release cadence.

Issues and discussions for **all** of these live in this repository — the
satellite repositories have their issue trackers disabled on purpose, so there is
one place to look rather than twelve.

## Contributing

Read [`docs/adr/`](docs/adr/) first — if you disagree with a decision there,
that disagreement is more valuable to us than a patch. [`docs/`](docs/) has the guides.

```bash
make ci        # everything the pull request will check, minus the Postgres jobs
git commit -s  # sign-off is required and enforced
```

`main` is protected: changes arrive by pull request, the aggregate `ci` check has
to pass, and force-pushes and deletions are refused. Branches must be current with
`main` before merging, so expect to rebase rather than merge. Squash and rebase
merges only — history stays linear.

## Security

Report vulnerabilities privately through GitHub's security advisories on this
repository, not in a public issue. [SECURITY.md](SECURITY.md) says what is in scope,
how long you should expect to wait, and which three alarming-looking behaviours are
the product working as designed.

## License

[Apache 2.0](LICENSE), with copyright and attribution in [NOTICE](NOTICE).

Commercial use is permitted, including running this as a service and reselling it. That
is deliberate rather than an oversight — see
[ADR-0009](docs/adr/0009-licensing-and-commercial-boundary.md) for what is proprietary and
why the boundary is an API rather than a licence.
