-- name: GetActivePolicy :one
-- The policy in force for a network, if there is one.
--
-- No row is a normal condition and means this network has no policy: every device may
-- reach every other, which is what a network does before anyone writes one. It must stay
-- distinguishable from an empty policy, which permits nothing.
SELECT id, network_id, version, document, created_at
FROM acl_policies
WHERE network_id = $1 AND is_active;

-- name: GetPolicyVersion :one
-- One stored version, for reading back what was published.
SELECT id, network_id, version, document, is_active, created_at
FROM acl_policies
WHERE network_id = $1 AND version = $2;

-- name: ListPolicyVersions :many
-- Every version ever published for a network, newest first.
--
-- The documents come too: a policy is meant to be diffed and rolled back (ADR-0007), and
-- a list of version numbers with no contents supports neither.
SELECT id, network_id, version, document, is_active, created_at
FROM acl_policies
WHERE network_id = $1
ORDER BY version DESC;

-- name: NextPolicyVersion :one
-- The version a new policy should take.
--
-- Derived from what is stored rather than from what is active, so a rollback that
-- re-publishes an older document still moves forward: versions name publications, not
-- contents, and reusing a number would make the history ambiguous.
SELECT COALESCE(MAX(version), 0) + 1 FROM acl_policies WHERE network_id = $1;

-- name: DeactivatePolicies :execrows
-- Stand every policy down, so exactly one can then be raised.
--
-- Separate from the insert because acl_policies carries a unique index over active
-- policies per network: activating a new one while the old is still active is refused by
-- the database rather than producing two.
UPDATE acl_policies SET is_active = false
WHERE network_id = $1 AND is_active;

-- name: InsertPolicy :one
INSERT INTO acl_policies (network_id, version, document, is_active, created_by_user_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, network_id, version, document, is_active, created_at;

-- name: ListPolicyDevices :many
-- Every device a policy may resolve a tag or a prefix to.
--
-- The same scoping as the peer list: active memberships of unrevoked devices only. A
-- policy that resolved a tag to a revoked device would put its address in every other
-- device's filter, granting access to something that is no longer in the network.
SELECT
    m.id            AS membership_id,
    m.address_v4,
    m.address_v6,
    m.tags,
    k.public_key    AS wireguard_public_key
FROM device_network_memberships m
JOIN wireguard_keys k ON k.membership_id = m.id AND k.state = 'current'
JOIN devices d        ON d.id = m.device_id
WHERE m.network_id = $1
  AND m.state = 'active'
  AND d.revoked_at IS NULL
ORDER BY m.id;
