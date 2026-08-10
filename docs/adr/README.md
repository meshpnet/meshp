# Architecture decision records

These record decisions that are expensive to reverse, together with what we gave
up to make them. If you are new to the codebase, read them in order — they
explain more about meshp than the code does.

A decision here is not permanent. It is *recorded*, so that changing it is a
deliberate act with a written reason rather than a drift nobody noticed.

| ADR | Decision |
|---|---|
| [0001](0001-route-groups-not-exit-pools.md) | Route groups, not exit pools |
| [0002](0002-relay-first.md) | Relay-first, with opportunistic direct upgrade |
| [0003](0003-candidate-lists.md) | Desired state carries candidate lists, not single assignments |
| [0004](0004-multi-network-membership.md) | A device may hold memberships in several networks at once |
| [0005](0005-address-space.md) | IPv6 ULA primary, configurable IPv4, never a hardcoded 100.64/10 |
| [0006](0006-identity-key-separate-from-wireguard-key.md) | Device identity key is separate from rotatable WireGuard keys |
| [0007](0007-acl-enforced-at-destination.md) | ACLs are enforced at the destination, in the agent |
| [0008](0008-incremental-lazily-scoped-state.md) | Desired state is delivered as incremental, lazily scoped deltas |
| [0009](0009-licensing-and-commercial-boundary.md) | Apache 2.0 core; the commercial layer is API-separated, not a fork |
| [0010](0010-mobile-clients.md) | Mobile clients wrap the official WireGuard tunnel libraries and are relay-only |
| [0011](0011-fail-closed.md) | Full-tunnel devices fail closed |
| [0012](0012-presence-and-bus-interface.md) | Presence and pub/sub sit behind an interface with in-memory and Redis implementations |
| [0013](0013-commit-generated-code.md) | Generated protobuf and database code is committed |

## Format

Copy [`0000-template.md`](0000-template.md). Keep them short. The
**Consequences** section is the one that earns its keep — write down what this
makes harder, not only what it makes possible.
