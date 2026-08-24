-- People, and the sessions they hold (ADR-0024).
--
-- What a person may do is not here. Permissions live in roles.sql, read per request against
-- the scope a route names, and nothing in this file grants or checks one — an account and
-- what it may do are separate questions, and answering them in one place is how a suspended
-- user ends up still holding a permission somewhere.

-- name: CreateUser :one
INSERT INTO users (organization_id, email, name, password_hash)
VALUES ($1, $2, $3, $4)
RETURNING id, organization_id, email, name, created_at, suspended_at;

-- name: ListUsersForOrganization :many
SELECT id, organization_id, email, name, created_at, suspended_at
FROM users
WHERE organization_id = $1 AND deleted_at IS NULL
ORDER BY email;

-- name: FindUsersByEmail :many
-- scope: global signing in starts with an email and nothing else, so there is no tenant to
-- scope by until this has found one. Email is unique per organisation rather than globally,
-- so this may return several — the caller refuses an ambiguous sign-in rather than picking,
-- which is the same answer ADR-0021 gives for an ambiguous name.
--
-- Suspended and deleted users are returned rather than filtered, so the caller can tell
-- "wrong password" from "that account is suspended" internally while telling the person at
-- the keyboard neither.
SELECT id, organization_id, email, name, password_hash, suspended_at, deleted_at
FROM users
WHERE lower(email) = lower(sqlc.arg(email)::text);

-- name: GetUserForOrganizationByEmail :one
SELECT id, organization_id, email, name, password_hash, suspended_at, deleted_at
FROM users
WHERE organization_id = $1 AND lower(email) = lower(sqlc.arg(email)::text);

-- name: SetUserPasswordHash :execrows
UPDATE users SET password_hash = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: SetUserSuspended :execrows
UPDATE users
SET suspended_at = CASE WHEN sqlc.arg(suspended)::boolean THEN now() ELSE NULL END,
    updated_at = now()
WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL;

-- name: SoftDeleteUser :execrows
-- Soft, because audit events name a user id and a row that vanished would leave a trail
-- pointing at nothing. The unique constraint is on (organization_id, email), so a deleted
-- address cannot be reused — which is deliberate: reusing one would attach an old trail to
-- a new person.
UPDATE users SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL;

-- name: CreateUserSession :one
INSERT INTO user_sessions (token_hash, user_id, idle_expires_at, expires_at, last_seen_at, user_agent, source_ip)
VALUES ($1, $2, $3, $4, now(), $5, $6)
RETURNING token_hash, user_id, expires_at;

-- name: GetUserSession :one
-- One round trip for "is this session live, and whose is it".
--
-- Joined to the user rather than checked separately, because a suspended or deleted account
-- must stop working immediately rather than at the end of a session it already holds.
SELECT s.token_hash, s.user_id, s.idle_expires_at, s.expires_at,
       u.organization_id, u.email, u.name
FROM user_sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.idle_expires_at > now()
  AND s.expires_at > now()
  AND u.suspended_at IS NULL
  AND u.deleted_at IS NULL;

-- name: TouchUserSession :execrows
-- Moves the idle window, clamped to the fixed deadline so a busy page cannot walk past it
-- one request at a time.
--
-- Called only when the window has actually drifted, not on every request: the view behind
-- this polls every few seconds, and a write per poll per viewer is a cost with nothing to
-- show for it.
UPDATE user_sessions
SET idle_expires_at = least(sqlc.arg(idle_expires_at)::timestamptz, expires_at),
    last_seen_at = now()
WHERE token_hash = $1;

-- name: DeleteUserSession :execrows
DELETE FROM user_sessions WHERE token_hash = $1;

-- name: DeleteUserSessionsForUser :execrows
-- Every session this person holds. What a password change and a suspension both need.
DELETE FROM user_sessions WHERE user_id = $1;

-- name: SweepExpiredUserSessions :execrows
-- scope: global expiry is not a tenant's property. A session that has run out belongs to
-- nobody and is removed on everybody's behalf, so scoping this to one organisation would
-- leave every other organisation's dead rows behind and make the sweep a per-tenant chore.
DELETE FROM user_sessions WHERE expires_at < now() OR idle_expires_at < now();

-- name: CountUsers :one
-- scope: global whether this deployment has any accounts at all is a property of the
-- deployment, not of a tenant. It is asked so the control plane can say, when somebody uses
-- the bootstrap secret, that there is now an account they could be using instead — a
-- question no organisation owns.
SELECT count(*)::bigint FROM users WHERE deleted_at IS NULL;
