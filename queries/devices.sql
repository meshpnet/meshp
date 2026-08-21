-- name: CreateDevice :one
INSERT INTO devices (
    organization_id, user_id, name, hostname, os, os_version,
    agent_version, identity_public_key, capabilities
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetDevice :one
-- One device by id, for the places that hold an id and need a name.
--
-- Unscoped like GetDeviceByIdentityKey, and for the same reason: the caller has already
-- established which network it is acting in, and the id it holds came from a row it read
-- under that scope. A tenant parameter here would suggest a check this cannot perform.
SELECT * FROM devices WHERE id = $1;

-- name: GetDeviceByIdentityKey :one
SELECT * FROM devices
WHERE identity_public_key = $1;

-- name: CreateMembership :one
INSERT INTO device_network_memberships (
    device_id, network_id, interface_name, address_v4, address_v6, tags, dns_label
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: TakenDNSLabels :many
-- The labels already used in a network, among those a candidate might collide with.
--
-- Prefix-matched rather than fetching every label in the network: a network with ten
-- thousand devices has ten thousand labels and one of them is being enrolled, so the
-- interesting set is the handful that start with the same base.
SELECT dns_label FROM device_network_memberships
WHERE network_id = $1 AND dns_label LIKE sqlc.arg(prefix) || '%';

-- name: CountMembershipsForDevice :one
SELECT count(*) FROM device_network_memberships
WHERE device_id = $1;

-- name: CreateWireGuardKey :one
INSERT INTO wireguard_keys (membership_id, public_key)
VALUES ($1, $2)
RETURNING *;

-- name: CreateMembershipState :one
INSERT INTO membership_state (membership_id, network_id, applied_version)
VALUES ($1, $2, 0)
RETURNING *;

-- name: ListDeviceAddressPools :many
-- Locked so that address selection inside a redemption cannot race another
-- redemption in the same network. Enrolments are rare, so serialising per network
-- costs nothing worth optimising.
SELECT * FROM address_pools
WHERE network_id = $1 AND purpose = 'device'
ORDER BY family
FOR UPDATE;

-- name: ListAllocationsForPool :many
SELECT address, state, released_at FROM address_allocations
WHERE pool_id = $1;

-- name: CreateAddressAllocation :one
INSERT INTO address_allocations (
    pool_id, network_id, address, holder_kind, holder_id
) VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: CreateAuditEvent :one
INSERT INTO audit_events (
    organization_id, network_id, actor_kind, actor_id, actor_label,
    action, resource_kind, resource_id, source_ip, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id;

-- name: ListAuditEventsForNetwork :many
SELECT * FROM audit_events
WHERE network_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2;

-- name: PageAuditEventsForNetwork :many
-- One page of a network's audit trail, newest first.
--
-- Keyed on the id rather than on a timestamp. created_at has no uniqueness and two events
-- written in the same transaction share it exactly, so a timestamp cursor would either
-- repeat them on the next page or skip them — and this is the one table where a reader
-- silently missing a row defeats the purpose of having it.
--
-- The id is a bigserial, so ordering by it descending is the same order as by time for
-- everything a caller can observe. A cursor of zero starts at the newest.
SELECT * FROM audit_events
WHERE network_id = $1
  AND (sqlc.arg(before)::bigint = 0 OR id < sqlc.arg(before)::bigint)
ORDER BY id DESC
LIMIT sqlc.arg(page_size);

-- name: RevokeMembership :one
-- Take a device out of a network, and say which key stopped being a peer.
--
-- The key comes back because a removal is recorded by key rather than by membership: by
-- the time a delta is built this row may be long gone, and an agent that is never told to
-- drop a peer keeps a tunnel configured to a device that is no longer entitled to one.
--
-- Scoped by network as well as by id so an administrator holding one network cannot revoke
-- a membership in another, and matched on state so revoking twice affects nothing — the
-- second call returns no row, which the caller reports rather than treating as success.
UPDATE device_network_memberships m
SET state = 'revoked', revoked_at = now()
FROM wireguard_keys k
WHERE m.id = $1
  AND m.network_id = $2
  AND m.state <> 'revoked'
  AND k.membership_id = m.id
  AND k.state = 'current'
RETURNING m.id AS membership_id, m.device_id, k.public_key AS wireguard_public_key;

-- name: ListMembershipsForNetwork :many
-- Who is in a network, for an administrator deciding what to revoke.
--
-- Revoked memberships are included rather than filtered out: an administrator checking
-- that a device really is out needs to see that it is out, and one that had silently
-- vanished would be indistinguishable from one that was never there.
SELECT
    m.id            AS membership_id,
    m.device_id,
    d.name          AS device_name,
    m.address_v4,
    m.address_v6,
    m.state,
    m.joined_at,
    m.revoked_at,
    k.public_key    AS wireguard_public_key
FROM device_network_memberships m
JOIN devices d ON d.id = m.device_id
LEFT JOIN wireguard_keys k ON k.membership_id = m.id AND k.state = 'current'
WHERE m.network_id = $1
ORDER BY m.joined_at;
