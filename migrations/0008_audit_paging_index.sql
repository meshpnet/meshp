-- +goose Up

-- The audit trail is paged by id, and nothing indexed that.
--
-- The existing index is on (network_id, created_at DESC), which was right while the only
-- reader was a `LIMIT` on the newest few. Paging keys on the id instead, because created_at
-- has no uniqueness and events written in one transaction share it exactly — so a timestamp
-- cursor repeats or skips rows. That left `ORDER BY id DESC` filtering by network through
-- one index and then sorting, which is fine on a young deployment and is the wrong shape to
-- leave behind: this table only grows, and the page now reads it on every poll.
CREATE INDEX audit_events_network_id_idx ON audit_events (network_id, id DESC);

-- +goose Down

DROP INDEX IF EXISTS audit_events_network_id_idx;
