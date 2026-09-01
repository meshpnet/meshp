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
    auto_failback, failback_delay_seconds, stable_egress_ip, local_failover
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, network_id, slug, name, kind, selection_mode,
          auto_failback, failback_delay_seconds, stable_egress_ip, local_failover,
          created_at;

-- name: AddRouteGroupPrefix :exec
-- Idempotent, because publishing the same group twice must not be an error.
INSERT INTO route_group_prefixes (route_group_id, prefix)
VALUES ($1, $2)
ON CONFLICT (route_group_id, prefix) DO NOTHING;

-- name: GetRouteGroupBySlug :one
SELECT id, network_id, slug, name, kind, selection_mode,
       auto_failback, failback_delay_seconds, stable_egress_ip, local_failover,
       created_at
FROM route_groups
WHERE network_id = $1 AND slug = $2;

-- name: ListRouteGroups :many
SELECT id, network_id, slug, name, kind, selection_mode,
       auto_failback, failback_delay_seconds, stable_egress_ip, local_failover,
       created_at
FROM route_groups
WHERE network_id = $1
ORDER BY slug;

-- name: SetRouteGroupFailover :one
-- Replaces a group's local failover policy.
--
-- Replaced whole rather than merged field by field. The policy is a set of numbers that
-- only make sense together — a fail threshold of one alongside a recover threshold left
-- from a previous edit is a device that moves on the first lost packet and takes ten
-- successes to come back — and a partial update is how an operator ends up with a
-- combination nobody chose.
--
-- Returns the row so the caller can report what is now in force, and no row at all when
-- the group is not in this network, which is how a typo is told from a change.
UPDATE route_groups
SET local_failover = sqlc.arg(local_failover),
    updated_at = now()
WHERE network_id = $1 AND slug = $2
RETURNING id, network_id, slug, name, kind, selection_mode,
          auto_failback, failback_delay_seconds, stable_egress_ip, local_failover,
          created_at;

-- name: ListRouteGroupPrefixes :many
SELECT route_group_id, prefix
FROM route_group_prefixes
WHERE route_group_id = ANY($1::uuid[])
ORDER BY route_group_id, prefix;

-- name: DeleteRouteGroup :many
-- Returns the ids it removed, because a delta withdraws a group by naming it and by the time
-- one is built the row is gone (#205). :many rather than :one so that deleting nothing is an
-- empty result rather than an error the caller has to tell apart from a real failure.
DELETE FROM route_groups WHERE network_id = $1 AND slug = $2 RETURNING id;

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

-- name: UpsertRouteAssignment :one
-- Record which candidate a device says it is currently using.
--
-- An observation, never an instruction. ADR-0003 gives the server authorisation and order
-- and the agent the choice, so this is the control plane writing down what it was told —
-- which is the half of that ADR ("the server records it") that was never built. It is what
-- answers "why did my outbound IP change?", and it is where the page finds which advertiser
-- is actually carrying, a question nothing could answer before.
--
-- decided_locally is always true. The column was written when the control plane was
-- expected to decide sometimes; ADR-0003 settled that it never does, so the flag records a
-- design that no longer exists. Kept rather than dropped because a migration to remove one
-- boolean is not worth the churn, and set honestly rather than left at its default.
--
-- The WHERE on the conflict is load-bearing. Reachability reports arrive from every device
-- on every heartbeat, and an UPDATE that ran each time would write a row per device per
-- group every twenty-five seconds — the write rate ADR-0012 exists to keep away from the
-- tables holding desired state. Unchanged reports now cost a conflict check and nothing
-- else, and no row comes back at all when nothing moved.
--
-- The version is returned because it says which kind of change this was without a second
-- query: 1 is a device recording a choice for the first time, and anything higher is a
-- device that moved. Only the second is worth an audit event — the first happens on every
-- enrolment and describes nothing going wrong.
INSERT INTO route_assignments (
    membership_id, route_group_id, advertiser_id, reason, decided_locally
) VALUES ($1, $2, $3, $4, true)
ON CONFLICT (membership_id, route_group_id) DO UPDATE
SET advertiser_id   = EXCLUDED.advertiser_id,
    reason          = EXCLUDED.reason,
    decided_locally = true,
    version         = route_assignments.version + 1,
    assigned_at     = now()
WHERE route_assignments.advertiser_id IS DISTINCT FROM EXCLUDED.advertiser_id
RETURNING version;

-- name: CountRouteAssignments :many
-- How many devices report currently using each candidate, per group.
--
-- Counts rather than rows. A subnet group in a fifty-device network has fifty assignments
-- and one useful fact — which candidate is carrying — so returning the rows would make the
-- overview grow with the network to say the same thing.
SELECT
    r.route_group_id,
    r.advertiser_id,
    count(*)::bigint AS devices
FROM route_assignments r
JOIN device_network_memberships m ON m.id = r.membership_id
JOIN devices d ON d.id = m.device_id
WHERE r.route_group_id = ANY($1::uuid[])
  AND r.advertiser_id IS NOT NULL
  -- Revoked devices stop counting. An assignment outlives the membership that made it
  -- until the cascade catches up, and a candidate shown as carrying for a device that is
  -- out of the network is worse than no number at all.
  AND m.state = 'active'
  AND d.revoked_at IS NULL
GROUP BY r.route_group_id, r.advertiser_id;
