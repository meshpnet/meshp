-- +goose Up

-- Make a device removable at all.
--
-- Until now nothing could delete one. `DELETE /networks/{id}/devices/{id}` revokes, the
-- listing deliberately keeps revoked memberships so an administrator can see a device is
-- out, and no query anywhere issued `DELETE FROM devices`. So "take my laptop off this
-- system" had no answer beyond "mark it revoked and look at it forever" — which for a
-- product whose argument is that you run your own private network is the wrong answer.
--
-- The obstacle was this table. `state_changes.membership_id` was ON DELETE SET NULL, and
-- the table also carries
--
--     CHECK ((kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
--            (kind = 'peer_remove' AND peer_public_key IS NOT NULL))
--
-- A referential SET NULL is an UPDATE, and CHECK constraints are evaluated on UPDATE, so
-- deleting a device cascaded to its memberships, tried to null out every `peer_upsert` row
-- naming them, and failed:
--
--     ERROR:  new row for relation "state_changes" violates check constraint
--     CONTEXT: SQL statement "UPDATE ONLY state_changes SET membership_id = NULL ..."
--
-- CASCADE rather than a looser CHECK, because the row genuinely has nothing left to say. A
-- `peer_upsert` is "this membership's peer state changed, go and read it"; once the
-- membership is gone there is nothing to read and an agent replaying it would be told to
-- look up a row that does not exist.
--
-- What must not be cascaded away is the removal itself, and it is not: PeerRemoved carries
-- the public key and leaves membership_id NULL (internal/store/statelog.go), precisely so a
-- removal outlives the thing it removes — the same reason RouteGroupRemoved names its own
-- id on the way out (#205). Deltas therefore still tell every other agent to drop the key.
ALTER TABLE state_changes
    DROP CONSTRAINT state_changes_membership_id_fkey;

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_membership_id_fkey
    FOREIGN KEY (membership_id) REFERENCES device_network_memberships (id) ON DELETE CASCADE;

-- +goose Down

ALTER TABLE state_changes
    DROP CONSTRAINT state_changes_membership_id_fkey;

-- Deliberately restores the constraint that made the delete impossible. Going back means
-- going back: a deployment that rolls this off should not keep the behaviour it enables.
-- Rows whose membership is already gone will fail this, and that is the honest outcome —
-- there is no membership to point them at any more.
ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_membership_id_fkey
    FOREIGN KEY (membership_id) REFERENCES device_network_memberships (id) ON DELETE SET NULL;
