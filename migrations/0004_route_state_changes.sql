-- A route change is a state change, like a policy change and for the same reason.
--
-- Who carries a prefix is desired state for every device in the network, not only for the
-- advertiser: everyone else has to be told where to send that traffic. So it is one row
-- naming nothing, rather than a peer change per membership.

-- +goose Up

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
    CHECK (kind IN ('peer_upsert', 'peer_remove', 'policy', 'routes'));

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL) OR
        (kind IN ('policy', 'routes') AND membership_id IS NULL AND peer_public_key IS NULL)
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

DELETE FROM state_changes WHERE kind = 'routes';

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_kind_check
    CHECK (kind IN ('peer_upsert', 'peer_remove', 'policy'));

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL) OR
        (kind = 'policy' AND membership_id IS NULL AND peer_public_key IS NULL)
    );
