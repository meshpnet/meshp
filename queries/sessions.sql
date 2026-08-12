-- name: GetMembershipForSession :one
-- Everything needed to authenticate a control-channel session, in one round trip.
--
-- The device's identity key is returned so the caller can check it against the key
-- presented on the wire. Binding the challenge to a membership id is not enough on
-- its own: the client chooses which membership it asks a challenge for, so without
-- comparing keys, any enrolled device could open a session as any other.
SELECT
    m.id              AS membership_id,
    m.device_id,
    m.network_id,
    m.interface_name,
    m.address_v4,
    m.address_v6,
    m.state           AS membership_state,
    m.tags,
    d.identity_public_key,
    d.name            AS device_name,
    d.revoked_at      AS device_revoked_at,
    n.state_version,
    n.organization_id
FROM device_network_memberships m
JOIN devices d  ON d.id = m.device_id
JOIN networks n ON n.id = m.network_id
WHERE m.id = $1;

-- name: ListPeersForMembership :many
-- The other devices this one may reach.
--
-- Ordered by id so two computations of the same network produce the same list. Map
-- iteration order reaching the wire would look like configuration churn to every
-- agent, and would make deltas that change nothing.
--
-- Scoping is by network only, for now: ACL-aware scoping is what makes this lazy
-- (ADR-0008), and it arrives with the policy engine. Until then a device is told
-- about everything in its network, which is the coarse behaviour the ACL work will
-- narrow.
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
WHERE m.network_id = $1
  AND m.id <> $2
  AND m.state = 'active'
  AND d.revoked_at IS NULL
ORDER BY m.id;

-- name: RecordSessionConnected :execrows
UPDATE membership_state
SET connected_since = sqlc.arg(now),
    control_session_id = sqlc.arg(session_id),
    last_error = ''
WHERE membership_id = $1;

-- name: RecordSessionDisconnected :execrows
-- Cleared only if the row still names this session. A device that reconnects before
-- the old session finishes tearing down would otherwise have its live session marked
-- disconnected by the dying one.
UPDATE membership_state
SET connected_since = NULL,
    control_session_id = NULL
WHERE membership_id = $1 AND control_session_id = sqlc.arg(session_id);

-- name: RecordAppliedVersion :execrows
-- Written only when the version actually changes; presence and liveness live in
-- memory (ADR-0012), so a heartbeat that reports no progress costs no write.
UPDATE membership_state
SET applied_version = sqlc.arg(applied_version),
    last_ack_at = sqlc.arg(now),
    last_error = sqlc.arg(last_error),
    unapplied_components = sqlc.arg(unapplied_components)
WHERE membership_id = $1;

-- name: TouchMembershipSeen :execrows
UPDATE device_network_memberships
SET last_seen_at = sqlc.arg(now)
WHERE id = $1;
