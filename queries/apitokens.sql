-- Credentials for machines (ADR-0024 §2).
--
-- A token carries the permissions of the user who minted it, intersected with a scope chosen
-- at creation. The intersection is evaluated at use rather than stored: what is in this table
-- can only narrow, never grant, so a token cannot outlive its owner's demotion.
--
-- Nothing here resolves permissions. That is roles.sql's job, asked about the token's owner,
-- and keeping it there is what stops there being a second answer to "what may this caller do".

-- name: CreateAPIToken :one
INSERT INTO api_tokens (
    token_hash, user_id, organization_id, name, permissions, network_id, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, organization_id, name, permissions, network_id, expires_at, created_at;

-- name: GetAPITokenByHash :one
-- The lookup in front of every request a machine makes.
--
-- Joined to the user rather than checked separately, for the reason GetUserSession gives: a
-- suspended or deleted owner must stop the token working immediately rather than at its
-- expiry. The owner's email comes back because the audit trail names the person at the end
-- of the machine, and a second query to find out who they are would be a second query per
-- request.
--
-- Expiry and revocation are in the WHERE clause rather than returned for the caller to
-- check: a token that has run out is not a token, and there is no code path that could
-- accidentally use one.
SELECT t.id, t.user_id, t.organization_id, t.name, t.permissions, t.network_id,
       t.last_used_at, t.expires_at, t.created_at,
       u.email AS owner_email
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = $1
  AND t.revoked_at IS NULL
  AND t.expires_at > now()
  AND u.suspended_at IS NULL
  AND u.deleted_at IS NULL;

-- name: TouchAPIToken :execrows
-- Records that a token was used, at most about once a minute.
--
-- The interval is in the WHERE clause as well as being decided by the caller, so two
-- concurrent requests cannot both decide to write. The caller skips the round trip entirely
-- in the common case; this is what makes the rare one safe.
UPDATE api_tokens
SET last_used_at = now()
WHERE id = $1
  AND (last_used_at IS NULL OR last_used_at < now() - sqlc.arg(stale)::interval);

-- name: ListAPITokensForUser :many
-- Somebody's own tokens, including expired and revoked ones.
--
-- Returned rather than filtered, because "I revoked that, didn't I?" is the question this
-- list is opened to answer, and a row that vanished answers it the same way a row that was
-- never there does.
SELECT id, user_id, organization_id, name, permissions, network_id,
       last_used_at, expires_at, created_at, revoked_at
FROM api_tokens
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: ListAPITokensForOrganization :many
-- Every token in an organisation, with whose it is. What somebody opens when a person leaves.
SELECT t.id, t.user_id, t.organization_id, t.name, t.permissions, t.network_id,
       t.last_used_at, t.expires_at, t.created_at, t.revoked_at,
       u.email AS owner_email
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.organization_id = $1
ORDER BY t.created_at DESC;

-- name: RevokeAPIToken :execrows
-- Scoped by organisation as well as by id, so a token id learned in one tenant cannot be
-- used to revoke a credential in another.
UPDATE api_tokens
SET revoked_at = now()
WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL;

-- name: GetAPITokenForOrganization :one
-- One token, for the audit event that revoking it writes: the trail should say which
-- credential was withdrawn and whose it was, not only that something was.
SELECT t.id, t.user_id, t.organization_id, t.name, t.network_id, t.revoked_at,
       u.email AS owner_email
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.id = $1 AND t.organization_id = $2;
