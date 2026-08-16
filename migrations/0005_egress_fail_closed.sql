-- Somewhere for an administrator to say a network's devices may fail open.
--
-- ADR-0011 makes fail-closed the default for a device claiming a default route,
-- and the agent already honours TunnelConfig.fail_closed_policy. What has been
-- missing is anywhere for the decision to live, so the control plane has been
-- sending UNSPECIFIED to everyone — which the agent reads as closed. A policy
-- with no way to change it is a hard-coded behaviour wearing a policy's clothes
-- (ADR-0018).
--
-- On the network rather than on the egress route group, which is the choice worth
-- explaining, because ADR-0011 phrases the default in terms of groups.
--
-- TunnelConfig is sent with every delta, while route group assignments are only
-- recomputed when routes changed — that is the whole point of the delta log. A
-- setting on the group would have to be looked up on every delta anyway to be
-- correct, and getting it wrong has a specific shape: an unrelated peer update
-- would compute "no egress group, so nothing to enforce" and tear the lock off a
-- machine that is still carrying a default route, in the one direction ADR-0011
-- says must never happen by omission. Here it rides on the membership row the
-- session already loads, so every delta and every snapshot carries the same
-- answer without a second query to forget.
--
-- The other half is that a device claims at most one default route, so a
-- per-group setting would need a rule for what happens when a device is assigned
-- to two egress groups that disagree — a conflict with no honest resolution, for
-- a distinction nobody has asked for.
--
-- Rescuing one bricked laptop is deliberately not what this is for: that is
-- `meshp doctor` and a local teardown, which work on a machine with no network.
-- This is the fleet-wide decision ADR-0011 describes.

-- +goose Up

ALTER TABLE networks
    ADD COLUMN egress_fail_closed boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN networks.egress_fail_closed IS
    'False means devices claiming a default route in this network may let traffic leave outside the tunnel if it drops. True is the default and is sent as unspecified, because the column defaulting to true is not the same as an administrator choosing it.';

-- A change to the tunnel configuration is a state change, like a policy change
-- and a route change before it, and the delta log has to be able to say so.
--
-- Without a row here, flipping this column would bump the version and send every
-- agent a delta with a new number and no contents: the builder short-circuits
-- when nothing in the window changed, and the short-circuit does not carry a
-- TunnelConfig. Agents would acknowledge the new version, the convergence metric
-- would say they are current, and every one of them would still be enforcing the
-- old answer. That is the failure BumpVersion's doc comment warns about, and it
-- is silent.
--
-- It names no membership, for the reason 'policy' and 'routes' name none: it is
-- about every device in the network at once.

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
    CHECK (kind IN ('peer_upsert', 'peer_remove', 'policy', 'routes', 'tunnel'));

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL) OR
        (kind IN ('policy', 'routes', 'tunnel')
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

DELETE FROM state_changes WHERE kind = 'tunnel';

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_kind_check
    CHECK (kind IN ('peer_upsert', 'peer_remove', 'policy', 'routes'));

ALTER TABLE state_changes
    ADD CONSTRAINT state_changes_identifier_check CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL) OR
        (kind IN ('policy', 'routes') AND membership_id IS NULL AND peer_public_key IS NULL)
    );

ALTER TABLE networks DROP COLUMN IF EXISTS egress_fail_closed;
