# Route groups

A route group is a set of prefixes and an ordered set of devices willing to carry them.

Internet egress, an office LAN gateway and a service gateway are the same thing in meshp,
differing only in which prefixes they carry (ADR-0001). They share advertisers, health,
priority, draining and failover — so redundancy for your branch office subnet router and
redundancy for your exit node are one feature rather than two, and both exist because
writing that machinery three times is how two of the three end up worse.

Every command here has been run against a live control plane.

Set up first:

```bash
export MESHP_TOKEN=...     # an API token of yours; the quickstart shows how to mint one
export NETWORK=...         # the network id
BASE="http://localhost:8080/api/v1/networks/$NETWORK"
```

The permissions this page needs are `network.routes.read` and `network.routes.write`, plus
`network.devices.read` to find a membership id. Changing which advertiser carries a prefix —
the failover section below — is `network.routes.failover`, which an operator holds as well:
it is what somebody does at two in the morning when a link is down, and it is deliberately
separate from being able to change which routes exist at all.

## Carrying an office LAN

A branch office has `192.168.10.0/24` behind it. One machine there — a small server, a
router running Linux — joins the network and offers to carry it.

```bash
curl -fsS -X POST -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"branch-lan","name":"Branch LAN","kind":"subnet",
       "prefixes":["192.168.10.0/24"]}' \
  "$BASE/route-groups"
```

Nothing carries it yet. Find the membership id of the device that will, then offer it:

```bash
curl -fsS -H "Authorization: Bearer $MESHP_TOKEN" "$BASE/devices"

curl -fsS -X POST -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"membership_id":"<the branch router>","priority":1}' \
  "$BASE/route-groups/branch-lan/advertisers"
```

Every other device in the network is now told to send `192.168.10.0/24` through that
device, and that device is told to forward it. Being an advertiser is a role a machine
plays, not a separate kind of machine: the same laptop that is an ordinary peer can carry a
branch office's subnet, and stopping is a withdrawal rather than a rebuild.

The advertiser is never offered its own group. Routing its own LAN into a tunnel that comes
back out of the same machine is at best a loop and at worst takes the site off the internet.

## Adding redundancy

A second machine at the same site, at a lower priority:

```bash
curl -fsS -X POST -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"membership_id":"<the backup>","priority":2}' \
  "$BASE/route-groups/branch-lan/advertisers"
```

Lower priority is preferred, and equal priorities share the load — two devices offered the
same pair are spread between them rather than both landing on whichever sorts first.

The server sends every device the whole ordered list, and each device decides how far down
it needs to be (ADR-0003). That split is the point: an agent that had to ask the control
plane before failing over could not fail over during a control-plane outage, which is
exactly when it is most likely to need to.

## Failover: how patient a device should be

```bash
curl -fsS -X PUT -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true,
       "fail_threshold":2,
       "recover_threshold":10,
       "min_hold_seconds":120}' \
  "$BASE/route-groups/branch-lan/failover"
```

| Field | Meaning |
|---|---|
| `enabled` | Whether the device may move itself at all. False means the control plane decides, in **both** directions — a device that obeyed on the way out and not on the way back would still be choosing for itself, just more slowly. |
| `fail_threshold` | Consecutive failed probes before moving on. |
| `recover_threshold` | Consecutive successes before returning to the server's first preference. |
| `min_hold_seconds` | Floor on time between switches. |

Leaving is cheap and returning is not, and the numbers should reflect that. A device that
moves to a working advertiser has lost nothing; one that returns to a flapping advertiser
loses every connection through it on each pass. So `recover_threshold` should be well above
`fail_threshold` — a policy where it is lower is refused rather than corrected, because
silently swapping an operator's numbers is worse than telling them.

`min_hold_seconds` applies to coming back and never to leaving. A minimum time between
switches exists to stop a device oscillating back to something broken, not to keep it
sitting on something that has already failed.

A **PUT replaces the whole policy.** Anything left out returns to its default rather than
keeping what was there — a fail threshold from today beside a recover threshold from last
month is a combination nobody chose.

Zero means "the agent's default" rather than zero, and reading the policy back shows what is
stored rather than what the agent would apply in its place. An unset field that displayed
as `3` would look like a decision somebody made.

## Probing: what "working" means

By default a device decides an advertiser is alive from its WireGuard handshake. That
catches a gateway that is off or unreachable. It does **not** catch one that is present and
useless: a branch router whose own uplink has failed handshakes perfectly, and every device
steered at it sits there with no route to anything while everything reports health.

Probe targets fix that. The device dials them *through the tunnel* and requires a quorum to
answer:

```bash
curl -fsS -X PUT -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true,
       "fail_threshold":2,
       "recover_threshold":10,
       "probe_targets":["192.168.10.1:22","192.168.10.20:445"],
       "probe_quorum":1,
       "probe_interval_ms":60000}' \
  "$BASE/route-groups/branch-lan/failover"
```

**Pick targets inside what the group carries.** For a branch LAN that means hosts on that
LAN — the gateway, a file server, a printer. For an egress group it means somewhere on the
internet. A target outside the carried prefixes does not go through the advertiser at all,
so it measures nothing about it.

**Literal addresses and a port. Never hostnames.** Resolving a name needs DNS, and DNS is
one of the things that stops working when a gateway fails, so a probe that resolved first
would blame the advertiser for a resolver's outage. A device that fails closed also refuses
plaintext DNS outside the tunnel, which would make the lookup depend on the very path being
tested.

**Use more than one, from more than one machine.** A single target measures that target's
path, not the advertiser's health. `probe_quorum` is how many must answer; leaving it at
zero means a majority, which is the right default for three or five targets. A quorum larger
than the number of targets is refused — it could never be met, so every advertiser would
fail forever and every device would end up parked on the last candidate reporting it dead.

**Connection refused counts as working.** The packet arrived and the far end answered — with
a reset rather than an acceptance, but it answered, which is the whole question. Otherwise
the verdict would depend on whether that host still runs something on that port.

`probe_interval_ms` is a floor, not a schedule: a group can be quieter than the agent's
reconcile interval (a minute by default) but never noisier, so a burst of unrelated updates
cannot turn a probe policy into a flood. Every device carrying the group dials every target
on every round, so this is a number you are multiplying by your fleet.

There is deliberately no default target list. Only you know what a working path looks like
for your network, and picking public addresses on your behalf would have every device you
own dialling a third party nobody asked it to.

## Internet egress

An exit node is a route group of kind `egress`. It carries the default route, so it names no
prefixes of its own — and the store refuses one that tries:

```bash
curl -fsS -X POST -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"exit-lon","name":"London exit","kind":"egress"}' \
  "$BASE/route-groups"
```

Devices assigned to it send everything through the tunnel. Both address families are
claimed together, so there is no way to tunnel IPv4 while IPv6 quietly goes direct.

### Fail-closed

A device claiming a default route installs firewall rules that refuse traffic which would
leave any other way. This is on by default and is the reason full-tunnel egress is worth
having: without it, the tunnel dropping silently puts the user's real address back on the
wire, at exactly the moments it is most likely to happen — waking from sleep, moving from
Wi-Fi to tethering, the agent being killed during an upgrade (ADR-0011).

Those rules are firewall state rather than process state, so they survive the agent dying.
That is the point, and it is also the sharp edge: a machine whose tunnel is gone refuses
almost everything until something takes them off. What stays reachable is the tunnel itself,
the relay, the control plane that can call this off, the local network, DHCP and neighbour
discovery.

To turn it off for a whole network:

```bash
curl -fsS -X PUT -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enforced":false}' \
  "$BASE/egress-fail-closed"
```

```bash
curl -fsS -H "Authorization: Bearer $MESHP_TOKEN" "$BASE/egress-fail-closed"
```

`enforced` must be stated. A body that leaves it out is refused rather than read as false,
because false is the setting that lets a fleet leak.

This is a fleet-wide policy, not a rescue tool. To recover one machine that is refusing
traffic, use [`meshp doctor`](troubleshooting.md) on the machine itself — it works with no
network at all and prints the exact commands to undo what meshp installed.

### A stable outbound address

If a customer has allowlisted your egress IP with a bank or a vendor, failing over to
another exit would change the address and break it. Set `stable_egress_ip` on the group and
the address follows the traffic. Alternatively `"selection_mode":"pinned"` means never move:
a broken path is a better outcome than a working path from an address that will be refused.

## Draining a machine for maintenance

```bash
curl -fsS -X POST -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"membership_id":"<the one going down>","priority":1,"admin_state":"draining"}' \
  "$BASE/route-groups/branch-lan/advertisers"
```

Draining keeps the devices already using it and refuses new ones, which is how maintenance
happens without dropping anybody. A draining advertiser goes on forwarding — one that
stopped would drop every session it was meant to be letting finish, which is the opposite of
what draining is for. `disabled` stops it outright.

To remove it entirely:

```bash
curl -fsS -X DELETE -H "Authorization: Bearer $MESHP_TOKEN" \
  "$BASE/route-groups/branch-lan/advertisers/<membership id>"
```

A group whose last advertiser is withdrawn is not sent as an assignment with an empty
candidate list — that would have every device install a route to nowhere, blackholing the
prefix. It is withdrawn instead, which says the same thing without the route.

## Two networks that use the same addresses

A technician supporting several customers holds memberships in several networks at once
(ADR-0004), and two customers who both accepted the default their router shipped with both
use `192.168.1.0/24`. One routing table cannot hold that prefix twice.

meshp refuses to guess. Neither group is carried, both report themselves unhonoured, and the
agent logs the collision naming both interfaces. A device that says it cannot reach either
is worse to use and better to trust than one that quietly reaches the wrong customer —
`ssh 192.168.1.5` landing on a different company's server, silently, and differently after a
restart.

Overlapping prefixes that are not identical are left alone: longest-prefix match resolves
those the same way on every machine, so they are not ambiguous even when they are surprising.
A default route from an egress group overlaps every LAN and is fine for the same reason.

Making the prefixes distinct is the real fix and is not built yet — it is an addressing
problem rather than a routing one (ADR-0019).

## Reading it back

```bash
curl -fsS -H "Authorization: Bearer $MESHP_TOKEN" "$BASE/route-groups"
```

Each group comes back with its prefixes, selection mode and full failover policy.
