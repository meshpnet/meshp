-- +goose Up

-- Credentials for machines (ADR-0024 §2).
--
-- `audit_events.actor_kind` has allowed 'api_token' since the first migration and there has
-- never been a table behind it. This is that table.
--
-- Separate from user_sessions on purpose. A machine cannot answer an MFA prompt, cannot
-- rotate a password, and must not be logged out because a person closed a laptop — and the
-- commercial layer (ADR-0009) is a machine, so the API it builds on has to be reachable by
-- one.
CREATE TABLE api_tokens (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The SHA-256 of what the holder was shown, never the value itself. Same treatment as
    -- enrolment tokens and user sessions: a backup does not hand somebody a live credential.
    token_hash      bytea NOT NULL UNIQUE,

    -- Who this token acts as. A token is a person acting through a machine, which is what
    -- makes the audit trail able to name somebody at the end of it.
    --
    -- ON DELETE CASCADE: an account that is gone cannot leave a working credential behind.
    -- Users are soft-deleted (see SoftDeleteUser), so this fires only when a row is really
    -- removed — the soft delete is handled by the lookup, which joins to the user.
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,

    -- What a person calls it. Required, because a list of tokens nobody can tell apart is a
    -- list nobody will ever prune.
    name            text NOT NULL CHECK (name <> ''),

    -- The scope chosen at creation. Intersected with the owner's *current* permissions at
    -- every use, never snapshotted: a token that kept working after its owner was demoted
    -- is the exact failure the intersection exists to prevent.
    --
    -- So this can only ever narrow. It is not a grant.
    permissions     text[] NOT NULL DEFAULT '{}',

    -- Optionally narrowed to one network, the same shape a role binding uses. NULL reaches
    -- every network the owner does.
    network_id      uuid REFERENCES networks (id) ON DELETE CASCADE,

    -- Coarse on purpose: updated when it has drifted by more than a minute, not per request.
    -- A machine polling once a second would otherwise turn a read into a write per second on
    -- a table nothing else needs to be hot.
    last_used_at    timestamptz,

    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,

    -- Unique per owner rather than per organisation: two people may each have a token called
    -- 'ci', and telling somebody their name is taken because a colleague used it would be
    -- surprising.
    UNIQUE (user_id, name)
);

-- Listing an organisation's tokens is how somebody finds what to revoke when a person
-- leaves, and listing your own is how you prune.
CREATE INDEX api_tokens_organization_idx ON api_tokens (organization_id, created_at DESC);
CREATE INDEX api_tokens_user_idx ON api_tokens (user_id, created_at DESC);

-- +goose Down

DROP TABLE IF EXISTS api_tokens;
