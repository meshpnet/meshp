-- Queries behind the one read endpoint a person looks at (ADR-0022).
--
-- They answer questions rather than fetch rows, and they are read together in one
-- transaction. Everything here is deliberately shaped for a consumer that is not this
-- repository's web page: the commercial layer builds its cross-tenant roll-up on the same
-- endpoint (ADR-0009), so these cannot be reshaped to suit whatever one screen needs.

-- name: ListAllNetworks :many
-- scope: global the only credential that still reaches this is the administrative token,
-- which is a single shared secret granting every route already (ADR-0024 §5), so a tenant
-- parameter here would suggest a constraint that does not exist. A signed-in person gets
-- ListNetworksForOrganizationWithCounts below instead — which is what this comment used to
-- predict would happen the day roles arrived, and this is that day.
--
-- Every network this control plane holds, so a deployment operator can answer "what is on
-- this box" without reading the database.
SELECT
    n.id,
    n.organization_id,
    o.slug          AS organization_slug,
    n.slug,
    n.name,
    n.state_version,
    n.created_at,
    (
        SELECT count(*)
        FROM device_network_memberships m
        WHERE m.network_id = n.id AND m.state = 'active'
    )               AS active_device_count
FROM networks n
JOIN organizations o ON o.id = n.organization_id
WHERE n.deleted_at IS NULL
ORDER BY o.slug, n.slug;

-- name: ListNetworksForOrganizationWithCounts :many
-- What a signed-in person can see: their own organisation's networks.
--
-- The same shape as ListAllNetworks, deliberately — the caller converts one row type to the
-- other, so if these two ever stop matching it is a compile error rather than a page that
-- renders one of them wrongly.
SELECT
    n.id,
    n.organization_id,
    o.slug          AS organization_slug,
    n.slug,
    n.name,
    n.state_version,
    n.created_at,
    (
        SELECT count(*)
        FROM device_network_memberships m
        WHERE m.network_id = n.id AND m.state = 'active'
    )               AS active_device_count
FROM networks n
JOIN organizations o ON o.id = n.organization_id
WHERE n.organization_id = $1 AND n.deleted_at IS NULL
ORDER BY o.slug, n.slug;

-- name: ListNetworkOverviewDevices :many
-- Every membership in a network, with whatever it last told the control plane.
--
-- Left-joined to membership_state rather than inner-joined: a membership that has never
-- opened a session has no state row, and an inner join would hide exactly the devices
-- somebody opening this page is most likely looking for.
--
-- Revoked memberships are included, for the reason ListMembershipsForNetwork gives: a
-- device that silently vanished from a list is indistinguishable from one that was never
-- there, and "is it really out" is a question this page has to answer.
--
-- The limit is the caller's, and the caller asks for one more than it means to show. That
-- is how it can say the list was cut rather than quietly returning a short one.
SELECT
    m.id            AS membership_id,
    m.device_id,
    d.name          AS device_name,
    m.address_v4,
    m.address_v6,
    m.state,
    m.joined_at,
    m.revoked_at,
    s.applied_version,
    s.last_ack_at,
    s.last_error,
    s.unapplied_components,
    -- Whether a control session is open, as recorded by whichever replica is holding it.
    --
    -- The one piece of liveness that is not per-process. ADR-0012 keeps presence out of
    -- PostgreSQL because it is high-frequency, and that is true of what a device *reports* —
    -- an applied version and a path report on every heartbeat. It is not true of whether the
    -- session exists at all, which changes when a device connects and when it goes away.
    --
    -- These two columns have been written on connect and disconnect since the first
    -- migration and read by nothing, so a control plane could only ever report the devices
    -- attached to itself. On one replica that is the same answer; on two it is half of one.
    s.connected_since,
    s.control_session_id
FROM device_network_memberships m
JOIN devices d ON d.id = m.device_id
LEFT JOIN membership_state s ON s.membership_id = m.id
WHERE m.network_id = $1
ORDER BY d.name, m.id
LIMIT $2;
