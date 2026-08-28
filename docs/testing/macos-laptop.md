# What a macOS laptop does: sleep, wake, and changing networks

CI proves that a Mac can bring a tunnel up, resolve names, claim a default route and refuse
egress that does not go through it. It proves all of that on an idle hosted runner, in under
a minute, on a machine that never sleeps and never changes networks.

That is a real proof and it is not the case anybody will actually run. A macOS device is a
laptop: it closes, it moves between wifi and a phone hotspot, it joins a corporate VPN that
claims the default route. Hosted runners do none of those things, which is why this is a
document somebody follows rather than a job that runs (#160).

**Run this before tagging a release, and before merging anything that touches
`internal/wglink`, `internal/pf` or `internal/resolved` on macOS.** Record the results in the
table at the bottom. An empty row is not a pass.

## What you need

- A control plane the laptop can reach **over the internet** — not a loopback one. Half of
  what is being tested is what happens when the laptop's route to that address changes, and
  a control plane on `127.0.0.1` cannot exercise it.
- The Mac enrolled in a network, with `meshp status` reporting a tunnel whose kind is
  `userspace`.
- A network with a route group carrying `0.0.0.0/0` assigned to this device, and
  `fail_closed` enforced. Without that, none of the egress behaviour is reachable.
- Two networks you can move between. Wifi and a phone hotspot is the easiest pair, and a
  hotspot is also the more honest test: a different gateway, a different address family
  situation, and often carrier-grade NAT.

## What to look at

Keep these in three terminals. Everything here works on a machine with no internet, which is
the state some of these steps produce.

```bash
meshp status
```

```bash
sudo meshp doctor
```

```bash
netstat -rn -f inet | head -20
sudo pfctl -a com.apple/meshp -s rules -v
```

The daemon's own log is the fourth thing worth having, and where it goes depends on how
meshpd was started. Run it in a terminal for these checks rather than under launchd, so the
log is in front of you.

## The checks

### 1. Sleep and wake

The tunnel lives inside the agent's process, so it survives a sleep only if the process and
its sockets do. macOS suspends processes and tears down sockets aggressively.

1. Confirm `meshp status` shows the tunnel up and a live session.
2. Close the lid. Wait at least five minutes — a short sleep does not reach the same code
   paths as one long enough for the control channel to time out server-side.
3. Open it.
4. Watch `meshp status` **without touching anything else**. That is the whole test: recovery
   has to need nothing from the person carrying the laptop.

**Pass:** within one reconcile interval (a minute by default), the tunnel is up, the session
is connected, and peers handshake again. `meshp doctor` reports nothing stranded.

**Record:** how long recovery took, and whether anything needed a nudge.

### 2. Changing networks

A new address means the tunnel's outer endpoint has moved. Because meshp is relay-first
(ADR-0002), the relay connection has to be re-established rather than a direct path
renegotiated — which should make this easier than it is for other implementations. "Should"
is doing the work in that sentence, which is why this check exists.

1. On wifi, with a full tunnel claimed, note the default gateway:
   `route -n get default | grep gateway`.
2. Note the carve-out routes meshp installed: `netstat -rn -f inet | grep -E '^(0\.0\.0\.0/1|128\.0\.0\.0/1)'`
   and the host routes to your relay and control plane.
3. Turn wifi off and tether to a phone.
4. Watch `meshp status` and the routing table.

**Pass:** the carve-out routes point at the **new** gateway, the relay reconnects, and the
tunnel comes back — again with nothing done by hand.

**Watch for:** a host route to the relay or the control plane still pointing at the old
gateway. That address is not reachable on the new network, and with fail-closed egress in
force the laptop has no way out at all until it is corrected. This is the specific thing that
makes the reconcile interval matter more on macOS than on Linux: the carve-out is routed
rather than marked, so it is pinned to whatever gateway was current when it was made.

That correction was broken until #160 and is worth checking rather than assuming.
`route add` reports an existing destination as "File exists" without touching it, so every
re-claim was told the route it wanted was already there and the stale one survived. It is
corrected in place now. **The remaining exposure is the interval itself**: nothing watches
for a network change, so the gap between moving and recovering is however long it is until
the next pass, up to a minute by default. Time it. If it is much longer than that, the
correction is not happening and this check has found the same class of bug again.

### 3. An ungraceful death while a full tunnel is claimed

ADR-0011 keeps the lock installed across a crash on purpose, and Invariant 20 says the agent
must never leave a host without networking. Those two pull against each other exactly here.

1. With a full tunnel claimed and failing closed, `sudo kill -9` the daemon.
2. Before restarting anything, run `sudo meshp doctor`. It should say the machine is refusing
   traffic and that meshpd is not running, and print the commands to undo both halves.
3. Check what is actually left: `sudo pfctl -a com.apple/meshp -s rules` and
   `netstat -rn -f inet`.
4. Start meshpd again and watch its first few log lines.

**Pass:** the daemon reports what it found and removes it — both the pf anchor and the
routes — and the machine has ordinary networking within a reconcile interval.

**Watch for:** the daemon logging that it found a claimed default route and leaving routes
behind anyway. Releasing the routing is the half with no equivalent of the firewall mark
Linux uses to find its own work again: a restarted daemon reads
`/var/run/meshp/egress-routes`, which the claim wrote, and takes off exactly what is named
there. Check that the file is gone afterwards. If it is still present, the release did not
complete and the next start will try to delete routes that may no longer be meshp's.

### 4. A VPN that claims the default route

Now that macOS fails closed (ADR-0026), this interaction is worth knowing rather than
guessing at. Another VPN and meshp both want the default route, and both may be enabling pf.

1. With meshp holding a full tunnel, connect a corporate or commercial VPN.
2. Check `netstat -rn -f inet` for whose routes won.
3. Check `sudo pfctl -s info` for the enable reference count, and `sudo pfctl -s rules` for
   whether the `com.apple/*` anchor point is still there.
4. Disconnect the other VPN and check that meshp's lock and routes are intact.

**Pass:** whatever happens to routing, meshp's anchor is still nested where it can be
evaluated, the pf reference count is not left at zero with meshp still expecting it, and
disconnecting the other VPN does not leave this machine locked with nothing to carry
traffic.

**Record what happens even if it is bad.** This is the one check whose purpose is to find
out rather than to confirm.

### 5. `connected_since` after the laptop sleeps

Server-side, and the reason it is here: a laptop that sleeps without closing its session
leaves `membership_state.connected_since` set, so the device reads as connected on every
replica until the session times out.

1. Note the device as connected in the API.
2. Sleep the laptop for longer than the session timeout.
3. Poll the device's state and record how long it goes on claiming to be connected.

**Pass:** it stops reading as connected within the timeout, and the bound is what the code
says it is.

## Results

One row per build actually exercised. A release without a row for its build has not had this
run.

| Date | Build | macOS | 1 Sleep | 2 Networks | 3 kill -9 | 4 Other VPN | 5 connected_since | Notes |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |
