-- +goose Up

-- A deleted route group is a sixth kind of change.
--
-- The bug this closes: deleting a route group bumped the version and told nobody. Deltas
-- withdraw a group by naming it, and the builder worked out which to name by listing the
-- groups that still exist and seeing which produced no assignment for a device. A group that
-- has been deleted is in no such list, so it appeared in neither the assignments nor the
-- withdrawals, and every connected device went on carrying it — indefinitely, since only a
-- reconnect replaces the set wholesale. On an egress group that means a laptop sending all
-- of its traffic through an exit node the control plane no longer knows about (#205).
--
-- It names the group, for the reason 'peer_remove' names a public key: by the time a delta
-- is built the row is gone, so the identifier has to be in the log rather than looked up.
-- That is the whole shape of this change — the mechanism already existed for peers and was
-- missing here.
--
-- Constraints are dropped and rebuilt wholesale rather than altered, following 0005 and
-- 0009: a CHECK cannot be extended in place, and naming them individually has gone wrong
-- once in this table's history.

ALTER TABLE state_changes ADD COLUMN route_group_id uuid;

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
    CHECK (kind IN ('peer_upsert', 'peer_remove', 'policy', 'routes', 'tunnel', 'dns',
                    'route_group_remove'));

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL) OR
        (kind = 'route_group_remove' AND route_group_id IS NOT NULL) OR
        (kind IN ('policy', 'routes', 'tunnel', 'dns')
            AND membership_id IS NULL AND peer_public_key IS NULL
            AND route_group_id IS NULL)
    );

-- +goose Down

DELETE FROM state_changes WHERE kind = 'route_group_remove';

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

ALTER TABLE state_changes DROP COLUMN route_group_id;
