-- name: RecordStateChange :one
-- Written in the same transaction as the version bump it describes. A change recorded
-- without its bump, or a bump without its change, would leave agents converging on a
-- version whose contents nobody can reconstruct.
INSERT INTO state_changes (network_id, version, kind, membership_id, peer_public_key)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: ListStateChangesSince :many
-- The rows a delta is built from.
--
-- Ordered by version then id so that two changes at the same version are applied in the
-- order they were recorded: a removal followed by an upsert of the same key means
-- something different from the reverse.
SELECT id, version, kind, membership_id, peer_public_key
FROM state_changes
WHERE network_id = $1
  AND version > sqlc.arg(from_version)
  AND version <= sqlc.arg(to_version)
ORDER BY version, id;

-- name: CountStateChangesSince :one
-- Used to decide between a delta and a snapshot before doing the work of either.
SELECT count(*) FROM state_changes
WHERE network_id = $1 AND version > sqlc.arg(from_version) AND version <= sqlc.arg(to_version);

-- name: GetPeerForMembership :one
-- One peer's current state, for a delta that names it.
SELECT
    m.id            AS membership_id,
    m.address_v4,
    m.address_v6,
    m.tags,
    k.public_key    AS wireguard_public_key,
    d.name          AS device_name
FROM device_network_memberships m
JOIN wireguard_keys k ON k.membership_id = m.id AND k.state = 'current'
JOIN devices d        ON d.id = m.device_id
WHERE m.id = $1
  AND m.state = 'active'
  AND d.revoked_at IS NULL;

-- name: GetDeltaWindow :one
-- What the server can currently reconstruct for a network.
SELECT state_version, oldest_delta_version
FROM networks
WHERE id = $1;

-- name: PruneStateChanges :one
-- Drops changes older than a cutoff, reporting how many rows went and the highest version
-- among them.
--
-- Both, because they answer different questions: the row count is how much the table grew
-- since the last sweep, and the highest version is where the delta floor now has to sit.
-- Reporting one as the other would make either operational reasoning or correctness wrong.
--
-- Split from the floor update rather than expressed as one statement with a CTE: keeping
-- them separate reads clearly, and the atomicity comes from the transaction that calls
-- both, which is where it belongs.
WITH pruned AS (
    DELETE FROM state_changes
    WHERE network_id = $1 AND created_at < sqlc.arg(older_than)
    RETURNING version
)
SELECT count(*)::bigint AS rows_pruned,
       coalesce(max(version), 0)::bigint AS highest_pruned
FROM pruned;

-- name: RaiseDeltaFloor :execrows
-- Records that deltas below a version can no longer be built.
--
-- An agent below the floor is sent a snapshot rather than a delta with holes in it.
-- greatest() so a concurrent prune cannot lower it.
UPDATE networks
SET oldest_delta_version = greatest(oldest_delta_version, sqlc.arg(version))
WHERE id = $1;

-- name: ListNetworksWithPrunableChanges :many
-- scope: global the retention sweep runs for the deployment, not for a caller's tenant; it
-- returns network ids only, and every row it leads to is then deleted under a network_id
-- predicate.
-- Networks holding change-log rows older than a cutoff.
--
-- So a deployment with ten thousand quiet networks does no work for them: pruning opens a
-- transaction per network, and a sweep that touched every network regardless would cost
-- more than the rows it removes.
SELECT DISTINCT network_id
FROM state_changes
WHERE created_at < sqlc.arg(older_than);
