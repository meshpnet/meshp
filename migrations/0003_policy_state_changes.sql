-- A policy change is a state change, and the delta log has to be able to say so.
--
-- Everything in state_changes so far names one peer: a membership that changed, or a key
-- that is gone. An ACL policy is different in kind — it changes what every device in the
-- network may do, all at once — and the alternatives to recording it as itself are both
-- bad. Logging a peer_upsert per membership makes one policy edit write a row per device
-- and turns a small change into a large delta. Not logging it at all means agents learn
-- about a policy only when something else happens to bump the version, which for a
-- security control is the wrong direction to be wrong in.
--
-- So: a third kind, carrying no identifier, meaning "recompute this device's filter".
-- The delta builder reads it as "the filter changed since the version you hold" and
-- includes a freshly compiled one.

-- +goose Up

-- Dropped by lookup rather than by name. The two existing CHECKs were created inline, so
-- their names are whatever PostgreSQL chose, and a migration that guessed wrong would fail
-- on somebody's database and not on ours.
DO $$
DECLARE c record;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'state_changes'::regclass AND contype = 'c'
    LOOP
        EXECUTE format('ALTER TABLE state_changes DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_kind_check
    CHECK (kind IN ('peer_upsert', 'peer_remove', 'policy'));

-- Each kind needs its own identifier, and a policy change must carry neither: one that
-- named a membership would look like a change to that device alone, which is precisely
-- what a policy change is not.
ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL) OR
        (kind = 'policy' AND membership_id IS NULL AND peer_public_key IS NULL)
    );

-- +goose Down

DO $$
DECLARE c record;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'state_changes'::regclass AND contype = 'c'
    LOOP
        EXECUTE format('ALTER TABLE state_changes DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;

DELETE FROM state_changes WHERE kind = 'policy';

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_kind_check
    CHECK (kind IN ('peer_upsert', 'peer_remove'));

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL)
    );
