# Troubleshooting

## Something on this machine cannot reach the internet

```bash
sudo meshp doctor
```

This is the first thing to run and usually the last. It reads the kernel before it talks to
the daemon, contacts nothing over the network, and works on a machine with no connectivity
at all — which is the case it exists for.

On a machine meshp is not interfering with, it says so plainly:

```
Nothing here is interfering with this machine's networking.

  meshpd          running, 1 live session(s)
  tunnel          0 interface(s) up
  blocking        false
  default route   false

Traffic goes wherever it would have gone without meshp, except for
the addresses inside your network.
```

On a machine that *is* refusing traffic, it says which of meshp's mechanisms is doing it,
and prints the exact commands to undo each one.

### Why a machine can end up refusing traffic

A device carrying a default route installs firewall rules that block anything not going
through the tunnel. That is the feature working: without it, the tunnel dropping silently
puts your real address back on the wire (ADR-0011). Those rules are firewall state rather
than process state, so **they survive `meshpd` being killed, crashing, or being upgraded**.
That is deliberate — a lock that died with the process would not cover the cases it exists
for — and it is also why a machine can be found in this state with nothing obviously running.

What stays reachable while it is locked: the tunnel itself, the relay, the control plane
that can call this off, the local network, DHCP and neighbour discovery. So the intended
recovery is to tell the control plane to stop, not to reach for a console.

### Recovering one machine

`meshp doctor` prints the commands, and it prints the ones for the machine it is running on:
the lock is an nftables table on Linux and a pf anchor on macOS, and a command for the wrong
operating system is worse than none to somebody at a console with no network. Either way it
is meshp's own and nothing else's, so it can be found and removed on its own — by `meshp
down`, by the agent finding it on start-up, or by a person with a console and no idea what
meshp is.

### Recovering a fleet

If the decision was wrong for the whole network rather than for one machine, turn it off
centrally and let the agents pick it up:

```bash
curl -fsS -X PUT -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enforced":false}' \
  "https://control.example.com/api/v1/networks/$NETWORK/egress-fail-closed"
```

Connected agents are nudged immediately rather than waiting for their next heartbeat. This
reaches a locked machine because the control plane is one of the things the lock keeps
reachable.

## A device joined but has no tunnel

```bash
sudo meshp status
```

`interface meshp0 (not up)` on a mobile platform is correct for now: there is no data plane
there yet, so a device enrols, holds an address, and reports honestly that it has no tunnel
rather than pretending.

On Windows the tunnel is a WinTun adapter, reported as `userspace` (ADR-0028). It needs
`wintun.dll` beside `meshpd.exe`; without it the tunnel fails with a message naming the file
and where to put it. What this platform can and cannot do is in
[what each platform can do](platforms.md), and anything it cannot is reported unhonoured
rather than half-applied.

Failing closed works differently here than anywhere else, and the difference shows up exactly
once: **there is no command that takes the lock off.** On Linux it is an nftables table and on
macOS a pf anchor, and both can be removed by hand from a console. Windows' filtering platform
has no command-line interface that changes anything — netsh shows its state and PowerShell has
no cmdlet for a provider — so `meshp doctor` offers a restart instead. That is a real undo
rather than a shrug: meshp's filters are deliberately not persistent (ADR-0030), so a reboot
clears them exactly as it clears the other two. Starting meshpd is still the first answer and
costs nobody their open windows.

To see what meshp installed:

```powershell
netsh wfp show state
```

Its filters are under a provider named `meshp`, and nothing else in that table is meshp's.

Names work differently here than anywhere else, in one way worth knowing before it surprises
somebody. **meshp's resolver listens on port 53 on Windows**, where on Linux and macOS it
takes whatever port the kernel has spare. Windows names a DNS server by address alone: a rule
naming a port is accepted, stores no server, and silently answers nothing for that domain — so
53 is the only thing expressible (ADR-0029). If something else on the machine already holds
`127.0.0.1:53`, and WSL and Docker Desktop both can, meshpd says so at start-up and carries on
without names rather than configuring something that does not work.

To see the rules meshp installed:

```powershell
Get-DnsClientNrptRule | Where-Object { $_.NameServers -contains "127.0.0.1" }
```

They are removed when a membership leaves. Nothing else in that table is meshp's, and meshp
does not touch it: a rule it did not create carries no marker of its own and is left alone.

On macOS `meshp status` reports the tunnel's kind as `userspace` — macOS has no WireGuard in
the kernel, so wireguard-go moves the packets. Expect lower throughput and higher CPU than
the same host would manage on Linux; that is the platform, not a fault. The same is true of
Windows, and [what each platform can do](platforms.md) is where the capability question is
answered.
Names resolve on macOS too: the agent writes a supplemental match domain into the
SystemConfiguration store, so only this network's suffix comes to meshp and everything else
keeps going wherever it was already going. `scutil --dns` shows it as a resolver with a
`domain` and a high `order`, which is the thing to look at when a mesh name does not answer.

A full tunnel on macOS is made without policy routing, which the platform does not have, so
the claim is made
the way wg-quick(8) makes it on this platform: `0.0.0.0/1` and `128.0.0.0/1`, which beat any
default route without replacing it, plus explicit routes keeping the control plane and the
relays off the tunnel they carry.

macOS fails closed too, through `pf` rather than nftables. The rules go in an anchor called
`com.apple/meshp`, which looks impolite and is deliberate: the `/etc/pf.conf` macOS ships
references exactly one anchor point, and an anchor of meshp's own would be loaded and never
evaluated (ADR-0026). meshp never writes that file. It also does not turn the packet filter
on and off outright — pf is enabled with a reference count, so meshp taking a reference
cannot switch it off underneath the application firewall or another VPN.

Before it trusts the lock, the agent checks that the main ruleset still evaluates what is
nested under Apple's anchor. If a macOS release ever changes that arrangement, the device
reports that it cannot fail closed rather than reporting a lock that is loaded and being
ignored. So a macOS upgrade that turns fail-closed networks into unhonoured route groups is
worth reporting; a silent leak is what the check is there to make impossible.

To see the lock:

```bash
sudo pfctl -a com.apple/meshp -s rules -v
```

If a macOS machine has lost its network and you suspect meshp, `sudo meshp doctor` prints
the exact commands to give it back: `sudo pfctl -a com.apple/meshp -F rules` for the lock,
and the `route -n delete` commands for the routing. Those two routes are what a claim is.

On Linux, check that the kernel can make WireGuard interfaces at all:

```bash
sudo ip link add dev wgcheck type wireguard && sudo ip link del dev wgcheck
```

## Devices know about each other but cannot reach each other

Almost always no relay. Nothing discovers direct paths yet, so every peer is relayed
(ADR-0002) — a control plane with no `MESHP_RELAYS` gives agents peers with no way to reach
them, and says so at startup:

```
no relays configured: peers will know about each other and be unable to reach each other
```

See [self-hosting](self-hosting.md#relays).

## An agent will not connect to the control plane

- **Plaintext to a non-loopback address is refused.** Agents will not send an enrolment
  token or a session signature in the clear. Use TLS.
- **`/readyz` is the right thing to check**, not `/healthz`: it reports the database and the
  schema, so it answers "can this serve agents" rather than "is the process alive".

## A route group is not being carried

`meshp status` names the components that did not converge. Common causes:

- **No advertiser**, or every advertiser withdrawn. A group with nobody to carry it is
  withdrawn rather than sent with an empty candidate list, because the latter would have
  every device install a route to nowhere and blackhole the prefix.
- **Two networks claiming the same prefix.** A device in several networks (ADR-0004) where
  two of them carry an identical prefix — `192.168.1.0/24` in both — carries neither, and
  logs the collision naming both interfaces. There is no right answer to pick between them,
  and quietly reaching the wrong customer is much worse than reaching neither
  ([route groups](route-groups.md#two-networks-that-use-the-same-addresses)).
- **The host cannot do it.** Claiming a default route needs policy routing; enforcing a
  policy needs nftables. A host that cannot reports the group unhonoured rather than
  half-claiming it.

## Traffic is going through the wrong exit, or moving when it should not

Read the group's failover policy back:

```bash
curl -fsS -H "Authorization: Bearer $MESHP_TOKEN" \
  "https://control.example.com/api/v1/networks/$NETWORK/route-groups"
```

- **Moving too eagerly**: `fail_threshold` is too low, or a probe target is unreliable.
  Remember a single target measures that target's path rather than the advertiser's health —
  use three and let the quorum absorb one having a bad afternoon.
- **Not moving at all**: `enabled` may be false, which means the device does not move itself
  in either direction. It still reports what it sees, so the control plane can tell you the
  advertiser is dead even while the device stays on it.
- **Moving and not coming back**: that is `recover_threshold` and `min_hold_seconds` doing
  their job. Returning is expensive — every connection through the tunnel drops again — so
  the policy is deliberately slower in that direction.

## A name does not resolve

Device names come from the peer list and need nothing written down. Names for anything else
— a machine that is not a meshp device, or a second name for one that is — are records an
administrator writes:

```bash
curl -fsS -X POST -H "Authorization: Bearer $MESHP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "git", "type": "A", "value": "10.80.0.30"}' \
  "https://control.example.com/api/v1/networks/$NETWORK/dns-records"
```

The response carries the `fqdn` the record will answer to. Records reach devices as desired
state, so a device applies one on its next state delta rather than immediately — `meshp
status` on the device shows the version it has applied.

- **`is not a DNS label`**: the name is one label, without the suffix. Write `git`, not
  `git.acme.internal` — the suffix is the network's and is added for you.
- **`is not a record type this serves`**: A and AAAA work. CNAME is in the schema and is not
  served yet, and is refused rather than stored so it cannot sit there doing nothing.
- **`a device in this network already answers to that name`**: pick another, or rename the
  device. Both names live in one namespace and one resolver answers for both.
- **Resolves to the wrong thing**: if a device was enrolled with that name *after* the
  record was written, the record wins on the device and the device keeps its address. Rename
  one of them.

## Why did my outbound IP change?

Ask the audit trail. A device that moves itself between candidates says why, and the control
plane records it (ADR-0003):

```bash
curl -fsS -H "Authorization: Bearer $MESHP_TOKEN" \
  "https://control.example.com/api/v1/networks/$NETWORK/audit?limit=20"
```

Look for `route.switched`. The `metadata` carries the agent's own words in `reason`, the
candidate it left in `switched_from`, and the one it moved to. `actor_label` is the device
that decided — the choice is the agent's, not the control plane's, so the trail names the
machine that made it.

The same endpoint holds enrolments, revocations and policy publications. It pages newest
first: pass the `next_before` from one response as `?before=` to get the next page. There is
no page number on purpose — events are only ever appended, so an offset would shift under
you while you read.

## An API call is refused and I do not know why

Refusals caused by what you sent carry the reason:

```json
{"error":"invalid","message":"an egress group carries the default route and takes no prefixes of its own"}
```

A bare `{"error":"internal"}` means something the server did not expect, and the detail is in
its log rather than the response — deliberately, because an error whose text nobody has
reviewed could name a table, a path or a peer.

`401` with `unauthorized` means the request carried no credential this control plane
recognises: no session cookie, no API token, and not the bootstrap secret. On a deployment
with no accounts yet and no `MESHP_ADMIN_TOKEN` set, everything answers this — see the
[quickstart](quickstart.md) for making the first account.

`403` with `forbidden` means the opposite: you are who you say you are and may not do this.
The message names the permission you would need, so it is something to hand to whoever
administers your organisation rather than something to retry.

`403` with `cross_origin` means a request that changes something arrived with a session
cookie and no `Origin` header naming this site. Browsers always send one; `curl` does not,
so add `-H "Origin: https://your-control-plane"` — or use an API token, which needs no such
header.

`403` with `person_required` means an API token tried to do something only a person may:
mint another token, or change its owner's password. A token that could mint a token would
survive its own revocation.

## Reporting a bug

`sudo meshp doctor` output is the useful thing to include, plus `meshp status` and the
control plane's log around the time it happened. Issues for every meshp repository live in
[meshpnet/meshp](https://github.com/meshpnet/meshp/issues).
