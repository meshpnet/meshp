-- A log of what changed at each version of a network's desired state.
--
-- Without it, every push is a full snapshot: a 500-device network sends every agent a
-- 500-peer document whenever anything happens, which is quadratic in the size of the
-- network and the dominant cost of running a control plane at scale (ADR-0008).
--
-- The design decision worth stating: for something that changed, this records *that it
-- changed*, not what it changed to. A delta looks up the current state of the
-- memberships named here. Storing the new value in the log as well would mean two
-- records of the same fact, and the copy in the log would be the one that goes stale.
--
-- Removals are the exception and have to carry the WireGuard key, because by the time a
-- delta is computed the row that held it may be gone — and an agent that is never told
-- to remove a peer keeps a tunnel configured to a device that no longer exists.

-- +goose Up

CREATE TABLE state_changes (
    id          bigserial PRIMARY KEY,
    network_id  uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,

    -- The network's state_version *after* this change. A delta for an agent at version F
    -- is every row with version > F.
    version     bigint NOT NULL,

    kind        text NOT NULL CHECK (kind IN ('peer_upsert', 'peer_remove')),

    -- Set for peer_upsert. The current row is read when the delta is computed, so this is
    -- a pointer rather than a copy.
    membership_id uuid REFERENCES device_network_memberships (id) ON DELETE SET NULL,

    -- Set for peer_remove. Not a foreign key on purpose: the whole point is that it
    -- outlives the membership it names.
    peer_public_key text,

    created_at  timestamptz NOT NULL DEFAULT now(),

    -- Each kind needs its own identifier, and neither is optional for it.
    CHECK (
        (kind = 'peer_upsert' AND membership_id IS NOT NULL) OR
        (kind = 'peer_remove' AND peer_public_key IS NOT NULL)
    )
);

-- The read path: everything for one network above a version, in order.
CREATE INDEX state_changes_network_version_idx ON state_changes (network_id, version, id);

-- The prune path.
CREATE INDEX state_changes_created_idx ON state_changes (created_at);

-- The oldest version still reconstructible for each network.
--
-- An agent further behind than this cannot be sent a delta and gets a snapshot instead.
-- Tracked per network rather than derived with min(version), because after pruning
-- removes the old rows there is nothing left to take a minimum of — and an empty log
-- would otherwise read as "everything is available".
ALTER TABLE networks
    ADD COLUMN oldest_delta_version bigint NOT NULL DEFAULT 0;

COMMENT ON COLUMN networks.oldest_delta_version IS
    'Deltas can be computed from this version onward; below it, agents are sent a snapshot.';

-- +goose Down

ALTER TABLE networks DROP COLUMN IF EXISTS oldest_delta_version;
DROP TABLE IF EXISTS state_changes;
