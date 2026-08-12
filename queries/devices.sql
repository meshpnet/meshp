-- name: CreateDevice :one
INSERT INTO devices (
    organization_id, user_id, name, hostname, os, os_version,
    agent_version, identity_public_key, capabilities
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetDeviceByIdentityKey :one
SELECT * FROM devices
WHERE identity_public_key = $1;

-- name: CreateMembership :one
INSERT INTO device_network_memberships (
    device_id, network_id, interface_name, address_v4, address_v6, tags
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

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
