# meshp documentation

Start here.

## Guides

| | |
|---|---|
| [Quickstart](quickstart.md) | A control plane and a device, on one machine, in ten minutes. |
| [Self-hosting](self-hosting.md) | The version you would put in front of real devices: TLS, systemd, relays, backups. |
| [Route groups](route-groups.md) | Office LANs, exit nodes, failover and probes — the thing meshp is for. |
| [Troubleshooting](troubleshooting.md) | When something refuses to connect, starting with `meshp doctor`. |

## Reference

| | |
|---|---|
| [What each platform can do](platforms.md) | Capability by capability, derived from the code rather than written from memory. |
| [Invariants](INVARIANTS.md) | The claims this system makes, written so they can be checked by machines. |
| [Decision records](adr/) | Why things are the way they are. |
| [macOS laptop checks](testing/macos-laptop.md) | The things CI cannot prove, because a hosted runner never sleeps and never changes networks. |
| [Web page checks](testing/the-page.md) | The other thing CI cannot prove: `web/app.js` is the one file here that runs in a browser and no job runs it. |

## If you are evaluating meshp

Read [the ADRs](adr/) rather than these guides. The design decisions are the interesting
part, and if you disagree with one, that disagreement is worth more to us than a patch.

Two worth starting with:

- [ADR-0001](adr/0001-route-groups-not-exit-pools.md) — why internet egress, a LAN gateway
  and a service gateway are one primitive rather than three features.
- [ADR-0011](adr/0011-fail-closed.md) — why a full-tunnel device refuses traffic when its
  tunnel drops, and why that is worth the support tickets.

And the honest one: the [status section of the README](../README.md#status) says what does
not work, and [what each platform can do](platforms.md) says it capability by capability —
derived from the code, so it cannot quietly go out of date. Nothing discovers direct paths
anywhere.
If you need something that works this afternoon, the README names three projects that will
serve you better today.

## A note on what these pages claim

Commands in these guides have been run against a live control plane rather than written from
the source. That is the same rule the code holds itself to: a mechanism nobody has executed
is one that fails on the first person who tries it (ADR-0018).

Two things in the quickstart were wrong the first time it was run end to end, and both are
the sort of thing reading the code would never have caught — one produced a malformed HTTP
header from a shell snippet, the other returned a 500 where the explanation had already been
written and was being thrown away. If something here does not work, it is a bug, and it is
worth an issue.
