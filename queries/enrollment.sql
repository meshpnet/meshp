-- name: CreateEnrollmentToken :one
INSERT INTO enrollment_tokens (
    network_id, organization_id, token_hash, created_by_user_id,
    scoped_user_id, preassigned_tags, max_uses, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetEnrollmentTokenByHash :one
-- Locked for the duration of the redemption transaction. Two devices presenting
-- the same token at once must serialise here rather than both proceeding to check
-- a use count that is about to change underneath them.
SELECT * FROM enrollment_tokens
WHERE token_hash = $1
FOR UPDATE;

-- name: ConsumeEnrollmentToken :one
-- The authoritative check, expressed as a guarded increment so it cannot be
-- separated from the decision it is guarding. The classifying SELECT above only
-- produces a good error message; this is what actually stops a replay.
--
-- "Now" is a parameter rather than now(). Using the database clock here while the
-- service decides expiry with its own would put two clocks in charge of one
-- decision: in tests they disagree by months, and in production they disagree by
-- whatever the skew between the application host and the database happens to be.
-- One time source, passed in.
UPDATE enrollment_tokens
SET uses = uses + 1
WHERE id = $1
  AND uses < max_uses
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
RETURNING uses, max_uses;

-- name: RevokeEnrollmentToken :execrows
UPDATE enrollment_tokens
SET revoked_at = now()
WHERE id = $1 AND network_id = $2 AND revoked_at IS NULL;

-- name: ListEnrollmentTokensForNetwork :many
SELECT id, network_id, organization_id, created_by_user_id, scoped_user_id,
       preassigned_tags, max_uses, uses, expires_at, created_at, revoked_at
FROM enrollment_tokens
WHERE network_id = $1
ORDER BY created_at DESC;
