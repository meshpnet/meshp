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

**Pre-alpha. No packet has ever crossed a meshp network.** A device can now be
enrolled — it gets an identity, a WireGuard key and an address, and a replayed token
is refused — but nothing brings up a tunnel yet.

What exists: the schema, the device protocol, the decision records, the logic that
decides addressing and where traffic goes (IPAM, advertiser health, route-group
selection), a control plane that applies its own schema and reports honest
readiness, and enrolment end to end.

What does not: WireGuard, the relay, the control channel, policy enforcement, DNS.
`meshpd` still idles. `meshp status` reports a membership and says `(not up)`,
because it is not.

It is public from the first commit because the design decisions are the
interesting part and we would rather be argued with early.

Do not deploy this. Read [`docs/adr/`](docs/adr/) instead.

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

## Quick start

Requires Go 1.25+, Docker and Node 20+.

```bash
git clone https://github.com/meshpnet/meshp.git
cd meshp
cp .env.example .env

# Both are required. The control plane refuses to start without a secret key, and
# leaves the administrative API switched off without an admin token.
echo "MESHP_SECRET_KEY=$(openssl rand -base64 32)" >> .env
echo "MESHP_ADMIN_TOKEN=$(openssl rand -base64 32)" >> .env

make build
docker compose up -d
```

Then enrol a device. There is no `network create` command yet, so the network and
its address pools are seeded with SQL:

```bash
NETWORK=$(docker compose exec -T postgres psql -U meshp -d meshp -tAqc "
  WITH o AS (INSERT INTO organizations (slug,name) VALUES ('acme','Acme') RETURNING id),
       n AS (INSERT INTO networks (organization_id,slug,name) SELECT id,'hq','HQ' FROM o RETURNING id),
       p AS (INSERT INTO address_pools (network_id,prefix,family,purpose)
             SELECT id,'100.90.0.0/24'::cidr,4,'device' FROM n
             UNION ALL SELECT id,'fd7c:6d65:7368::/120'::cidr,6,'device' FROM n
             RETURNING network_id)
  SELECT DISTINCT network_id FROM p")

TOKEN=$(curl -fsS -X POST \
  -H "Authorization: Bearer $MESHP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"max_uses":1,"expires_in_seconds":600}' \
  "http://localhost:8080/api/v1/networks/$NETWORK/enrollment-tokens" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

sudo ./bin/meshp join "$TOKEN" --state-dir /var/lib/meshp
sudo ./bin/meshp status --state-dir /var/lib/meshp
```

`join` needs write access to the state directory because it writes the device's
private keys there. That moves behind meshpd's local socket shortly — keys belong to
the privileged daemon, not to whoever runs the CLI.

```bash
make help    # every available target
make ci      # everything CI runs, except the jobs that need Postgres
make e2e     # enrol a device against a real database, start to finish
```

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
web/            React dashboard, embedded into meshp-control at build time
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
| `meshp-ios` | iOS client | not started |
| `meshp-android` | Android client | not started |
| `meshp-testlab` | network-namespace conformance suite, including NAT types and failover | not started |
| `meshp-sdk` | generated API clients | not started |
| `meshp-web` | website and documentation | private, empty |

Issues and discussions for **all** of these live in this repository — the
satellite repositories have their issue trackers disabled on purpose, so there is
one place to look rather than twelve.

## Contributing

Read [`docs/adr/`](docs/adr/) first — if you disagree with a decision there,
that disagreement is more valuable to us than a patch.

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
repository, not in a public issue. See the organisation `SECURITY.md`.

## License

[Apache 2.0](LICENSE).
