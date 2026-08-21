-- +goose Up

-- A DNS record is a fifth kind of change.
--
-- Like a policy or a tunnel change and unlike a peer, it names nothing: an
-- administrator-entered record is desired state for every device in the network, because
-- every one of them has to be able to resolve it. One row rather than one per membership,
-- for the reason the policy kind gives — a record added in a 500-device network would
-- otherwise write 500 rows describing peers that did not move.
--
-- Constraints are dropped and rebuilt wholesale rather than altered, following 0005: a
-- CHECK cannot be extended in place, and naming them individually has already gone wrong
-- once in this table's history.

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
    CHECK (kind IN ('peer_upsert', 'peer_remove', 'policy', 'routes', 'tunnel', 'dns'));

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL) OR
        (kind IN ('policy', 'routes', 'tunnel', 'dns')
            AND membership_id IS NULL AND peer_public_key IS NULL)
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

DELETE FROM state_changes WHERE kind = 'dns';

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_kind_check
    CHECK (kind IN ('peer_upsert', 'peer_remove', 'policy', 'routes', 'tunnel'));

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL) OR
        (kind IN ('policy', 'routes', 'tunnel')
            AND membership_id IS NULL AND peer_public_key IS NULL)
    );
