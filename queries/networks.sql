-- Queries are hand-written SQL; sqlc generates the Go. No ORM.
--
-- Every query that reads tenant-scoped data takes the scope as a parameter.
-- There is no unscoped "select all devices" query in this file or any other,
-- and adding one is a review failure.

-- name: GetNetwork :one
SELECT * FROM networks
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListNetworksForOrganization :many
SELECT * FROM networks
WHERE organization_id = $1 AND deleted_at IS NULL
ORDER BY name;

-- name: SetNetworkEgressFailClosed :one
-- Records whether devices in this network must refuse egress outside the tunnel
-- while they claim a default route (ADR-0011).
--
-- Returns whether this actually changed anything, so the caller can decide
-- whether the network needs telling. Writing the same value again and bumping the
-- version regardless would send every agent in the network a delta describing a
-- change that did not happen, which is churn that looks exactly like a real
-- reconfiguration in the logs.
--
-- Written as a CTE because RETURNING sees the row after the write, so an UPDATE
-- alone cannot say what the value used to be. The old row is read and locked
-- first, which also settles two administrators flipping this at once: the second
-- waits, re-reads, and reports honestly that it changed nothing.
--
-- No row comes back for a network that does not exist or has been deleted, which
-- is how the caller tells that apart from a no-op write.
WITH locked AS (
    SELECT before.id, before.egress_fail_closed
    FROM networks before
    WHERE before.id = $1 AND before.deleted_at IS NULL
    FOR UPDATE
), updated AS (
    UPDATE networks after
    SET egress_fail_closed = sqlc.arg(egress_fail_closed)::boolean,
        updated_at = now()
    FROM locked
    WHERE after.id = locked.id
    RETURNING after.egress_fail_closed
)
SELECT
    updated.egress_fail_closed,
    (updated.egress_fail_closed IS DISTINCT FROM locked.egress_fail_closed)::boolean AS changed
FROM updated, locked;

-- name: BumpNetworkStateVersion :one
-- Called exactly once per mutation that changes what any agent should do.
-- Returns the new version so the caller can hand it to the delta computation.
UPDATE networks
SET state_version = state_version + 1,
    updated_at = now()
WHERE id = $1
RETURNING state_version;

-- name: ListActiveMemberships :many
SELECT m.*
FROM device_network_memberships m
JOIN devices d ON d.id = m.device_id
WHERE m.network_id = $1
  AND m.state = 'active'
  AND d.revoked_at IS NULL
ORDER BY m.joined_at;

-- name: GetConvergenceLag :many
-- The gap between desired and applied state, per membership. This is the
-- primary health signal for a reconciliation system: a membership that never
-- closes the gap is a broken agent, and a network where the gap is widening is
-- a broken control plane.
SELECT
    ms.membership_id,
    d.name AS device_name,
    n.state_version AS desired_version,
    ms.applied_version,
    n.state_version - ms.applied_version AS lag,
    ms.last_ack_at,
    ms.last_error
FROM membership_state ms
JOIN networks n ON n.id = ms.network_id
JOIN device_network_memberships m ON m.id = ms.membership_id
JOIN devices d ON d.id = m.device_id
WHERE ms.network_id = $1
ORDER BY lag DESC, ms.last_ack_at NULLS FIRST;
