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

-- name: GetAdvertiserHealth :one
-- What the control plane last concluded about an advertiser, if anything.
SELECT advertiser_id, state, consecutive_ok, consecutive_fail, consecutive_partial,
       last_improved_at, last_checked_at
FROM advertiser_health
WHERE advertiser_id = $1;

-- name: UpsertAdvertiserHealth :exec
-- Store what the monitor concluded.
--
-- The whole snapshot rather than the state alone: the counters are what make the next
-- observation mean anything, and a state persisted without them would restart every
-- hysteresis window on each control-plane restart — turning a policy designed to resist
-- flapping into one that flaps on deploys.
INSERT INTO advertiser_health (
    advertiser_id, state, consecutive_ok, consecutive_fail, consecutive_partial,
    last_improved_at, last_checked_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (advertiser_id) DO UPDATE SET
    state = EXCLUDED.state,
    consecutive_ok = EXCLUDED.consecutive_ok,
    consecutive_fail = EXCLUDED.consecutive_fail,
    consecutive_partial = EXCLUDED.consecutive_partial,
    last_improved_at = EXCLUDED.last_improved_at,
    last_checked_at = EXCLUDED.last_checked_at;

-- name: GetAdvertiserForReport :one
-- The advertiser a device claims to be using, scoped to the network the session belongs to.
--
-- Scoped, because the id arrives from a device: without this a device in one network could
-- report health for an advertiser in another, and steer a network it cannot see.
SELECT a.id, a.route_group_id, g.network_id
FROM route_advertisers a
JOIN route_groups g ON g.id = a.route_group_id
WHERE a.id = $1 AND g.network_id = $2;
