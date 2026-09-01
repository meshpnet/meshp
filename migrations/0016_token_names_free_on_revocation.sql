-- +goose Up

-- A revoked token holds its name forever, and it should not.
--
-- api_tokens is unique on (user_id, name), and revocation is a soft delete: the row stays
-- with a revoked_at. So a name is consumed permanently the first time it is used, and
-- `meshp login` from a machine can never be run twice — the CLI names a token after the
-- host, revokes the old one when it signs in again, and is then told the name is taken by
-- something that no longer exists.
--
-- The error was false as well as inconvenient: "you already have a token with that name"
-- names a token the owner does not have, cannot see in their list, and cannot revoke again.
--
-- Made partial rather than dropped. What the constraint is for is still right — two live
-- credentials called 'ci' are indistinguishable in the list somebody prunes from — and it
-- stays exactly that strong for tokens that exist.

ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_user_id_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS api_tokens_live_name_per_user
    ON api_tokens (user_id, name)
    WHERE revoked_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS api_tokens_live_name_per_user;

-- Restoring the total constraint can fail, and that is honest rather than a flaw in this
-- migration: rolling back is only possible if no two tokens now share a name, and the whole
-- point of the change above is to allow exactly that. A deployment that has used the freedom
-- cannot give it back without deciding which rows to rename, which is not a decision a
-- migration should take on somebody's behalf.
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_user_id_name_key UNIQUE (user_id, name);
