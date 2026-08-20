-- Queries behind the one read endpoint a person looks at (ADR-0022).
--
-- They answer questions rather than fetch rows, and they are read together in one
-- transaction. Everything here is deliberately shaped for a consumer that is not this
-- repository's web page: the commercial layer builds its cross-tenant roll-up on the same
-- endpoint (ADR-0009), so these cannot be reshaped to suit whatever one screen needs.

-- name: ListAllNetworks :many
-- scope: global the only credential that reaches this is the administrative token, which is
-- a single shared secret granting every route already (ADR-0022 §5), so a tenant parameter
-- here would suggest a constraint that does not exist. The day roles arrive, this is the
-- first query that has to grow a caller, and that is a change to this line as much as to
-- the SQL.
--
-- Every network this control plane holds, so a view can offer a choice rather than
-- requiring somebody to paste a UUID.
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
    s.unapplied_components
FROM device_network_memberships m
JOIN devices d ON d.id = m.device_id
LEFT JOIN membership_state s ON s.membership_id = m.id
WHERE m.network_id = $1
ORDER BY d.name, m.id
LIMIT $2;
