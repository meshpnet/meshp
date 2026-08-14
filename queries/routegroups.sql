-- name: CreateNetwork :one
-- A network, without anyone reaching for psql.
--
-- Address pools come separately: a network is a thing you name, and the addressing is a
-- decision about the estate it will sit in.
INSERT INTO networks (organization_id, slug, name)
VALUES ($1, $2, $3)
RETURNING id, organization_id, slug, name, state_version, created_at;

-- name: CreateAddressPool :one
INSERT INTO address_pools (network_id, prefix, family, purpose)
VALUES ($1, $2, $3, $4)
RETURNING id, network_id, prefix, family, purpose;

-- name: ListNetworks :many
SELECT id, organization_id, slug, name, state_version, created_at
FROM networks
WHERE organization_id = $1
ORDER BY created_at;

-- name: CreateRouteGroup :one
INSERT INTO route_groups (
    network_id, slug, name, kind, selection_mode,
    auto_failback, failback_delay_seconds, stable_egress_ip
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, network_id, slug, name, kind, selection_mode,
          auto_failback, failback_delay_seconds, stable_egress_ip, created_at;

-- name: AddRouteGroupPrefix :exec
-- Idempotent, because publishing the same group twice must not be an error.
INSERT INTO route_group_prefixes (route_group_id, prefix)
VALUES ($1, $2)
ON CONFLICT (route_group_id, prefix) DO NOTHING;

-- name: GetRouteGroupBySlug :one
SELECT id, network_id, slug, name, kind, selection_mode,
       auto_failback, failback_delay_seconds, stable_egress_ip, created_at
FROM route_groups
WHERE network_id = $1 AND slug = $2;

-- name: ListRouteGroups :many
SELECT id, network_id, slug, name, kind, selection_mode,
       auto_failback, failback_delay_seconds, stable_egress_ip, created_at
FROM route_groups
WHERE network_id = $1
ORDER BY slug;

-- name: ListRouteGroupPrefixes :many
SELECT route_group_id, prefix
FROM route_group_prefixes
WHERE route_group_id = ANY($1::uuid[])
ORDER BY route_group_id, prefix;

-- name: DeleteRouteGroup :execrows
DELETE FROM route_groups WHERE network_id = $1 AND slug = $2;

-- name: UpsertRouteAdvertiser :one
-- A device offering to carry a group's prefixes.
--
-- Upserted rather than inserted, so re-advertising with a new priority is an edit and not
-- a conflict — an operator adjusting a failover order should not have to remove first.
INSERT INTO route_advertisers (
    route_group_id, membership_id, priority, weight, admin_state, region, city, provider
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (route_group_id, membership_id) DO UPDATE SET
    priority = EXCLUDED.priority,
    weight = EXCLUDED.weight,
    admin_state = EXCLUDED.admin_state,
    region = EXCLUDED.region,
    city = EXCLUDED.city,
    provider = EXCLUDED.provider,
    updated_at = now()
RETURNING id, route_group_id, membership_id, priority, weight, admin_state, region, city, provider;

-- name: ListRouteAdvertisers :many
-- Everything the selector needs, joined to the device that plays the role.
--
-- Scoped like every other peer query: active memberships of unrevoked devices. An
-- advertiser that has been revoked must stop being offered, or traffic would be steered at
-- a device that is no longer in the network.
SELECT
    a.id,
    a.route_group_id,
    a.membership_id,
    a.priority,
    a.weight,
    a.admin_state,
    a.region,
    a.city,
    k.public_key AS wireguard_public_key,
    d.name       AS device_name,
    h.state      AS health_state
FROM route_advertisers a
JOIN device_network_memberships m ON m.id = a.membership_id
JOIN wireguard_keys k ON k.membership_id = m.id AND k.state = 'current'
JOIN devices d        ON d.id = m.device_id
LEFT JOIN advertiser_health h ON h.advertiser_id = a.id
WHERE a.route_group_id = ANY($1::uuid[])
  AND m.state = 'active'
  AND d.revoked_at IS NULL
ORDER BY a.route_group_id, a.priority, a.id;

-- name: DeleteRouteAdvertiser :execrows
DELETE FROM route_advertisers
WHERE route_group_id = $1 AND membership_id = $2;
