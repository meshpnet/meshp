-- +goose Up

-- Where a signed-in person's session lives (ADR-0024 §3).
--
-- In PostgreSQL, unlike the presence and pub/sub state ADR-0012 deliberately keeps out of
-- it. That record's argument is about high-frequency ephemeral data whose loss costs a
-- reconnect; a login is neither frequent nor free to lose. Every deployment restart logging
-- out every operator is a bad property to build in on purpose, and multi-replica has no
-- other answer.
--
-- One row per login, not per request. The row is what makes a session revocable, which is
-- the whole reason not to put the session in a signed token instead.
CREATE TABLE user_sessions (
    -- The SHA-256 of the value the browser presents, never the value itself. A heap dump or
    -- a database backup then does not hand somebody a live session.
    token_hash      bytea PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Sliding, so a page somebody is watching does not expire under them.
    idle_expires_at timestamptz NOT NULL,
    -- Fixed, so no amount of use keeps a session alive forever.
    expires_at      timestamptz NOT NULL,
    -- What the session was last seen doing, for the sign-in list a person reads to answer
    -- "is that me?". Coarse on purpose: updated when the idle window moves, not per request.
    last_seen_at    timestamptz,
    user_agent      text NOT NULL DEFAULT '',
    source_ip       inet
);

-- Ending every session a user holds is a thing that happens on a password change and on a
-- suspension, so it is worth an index rather than a scan of everyone's sessions.
CREATE INDEX user_sessions_user_idx ON user_sessions (user_id);

-- Sweeping expired rows is the other access path.
CREATE INDEX user_sessions_expiry_idx ON user_sessions (expires_at);

-- +goose Down

DROP TABLE IF EXISTS user_sessions;
