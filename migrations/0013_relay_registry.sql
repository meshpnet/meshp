-- +goose Up

-- Relays become rows, so one can be taken out of service without a restart (#128).
--
-- The table has been here since the first migration and nothing read it. What kept it that
-- way is recorded in ParseRelays: "a deployment with one relay should not need a migration
-- to name it." That is still true — MESHP_RELAYS still works and now seeds this table at
-- startup — but it stopped being the whole story once a deployment ran more than one, at
-- which point taking one out meant editing an environment variable and restarting the
-- control plane, dropping every session on every relay to retire one.

-- A relay named by configuration has no public key.
--
-- The column anticipates ADR-0017's relays-whose-keys-a-deployment-trusts, and nothing
-- issues, stores or verifies one: the trust runs the other way, with the control plane
-- signing a capability the relay checks (ADR-0016). NOT NULL on a column nothing writes
-- meant this table could not hold the relays a deployment actually has.
ALTER TABLE relays ALTER COLUMN public_key DROP NOT NULL;

-- Reading the active relays happens on every state build, which is per agent per change.
-- Few rows either way, but this is the access path and it should say so.
CREATE INDEX relays_state_idx ON relays (state) WHERE state = 'active';

-- +goose Down

DROP INDEX IF EXISTS relays_state_idx;
-- Left nullable on the way down. Restoring NOT NULL would fail against exactly the rows
-- this migration exists to allow, and a Down that cannot run is worse than one that leaves a
-- column more permissive than it found it.
