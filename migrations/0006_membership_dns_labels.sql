-- A name a device can be reached by, unique in the network it is reached from.
--
-- ADR-0021 makes names resolvable as <label>.<network>.<suffix>, which requires the label
-- to be unique within a network and to be a thing DNS can carry. Neither is true today:
-- devices.name is free text with no constraint at all.
--
-- On the membership rather than on the device, and that is the decision worth explaining.
-- The scope of uniqueness is the network, because the network is the next part of the name
-- — and a device belongs to many networks (ADR-0004), so a constraint on devices.name would
-- either be too strict (unique per organisation, forbidding two customers from both having
-- a `fileserver`) or unenforceable (unique per network, which is not a column on that
-- table). `UNIQUE (network_id, dns_label)` is exactly the rule, and it is a real constraint
-- rather than something the application promises to remember.
--
-- It also costs less than ADR-0021 assumed. That ADR said names would stop being free text
-- and `Dave's laptop (spare)` would not survive. It does: devices.name stays exactly as it
-- is, display-only and unconstrained, and this is a second, machine-shaped name beside it.
--
-- The backfill renames rather than refuses. An earlier draft of ADR-0021 had the migration
-- refuse on duplicates and make an operator choose, which blocks an upgrade to protect a
-- name nothing yet depends on: no route, no policy and no lookup uses devices.name today.
-- That window closes when the resolver is wired to the system, which is why this goes
-- first.

-- +goose Up

ALTER TABLE device_network_memberships ADD COLUMN dns_label text;

-- Backfill, in one pass per network, oldest membership first.
--
-- Ordering by joined_at rather than by id so the result is explicable: the device that has
-- been in the network longest keeps the unsuffixed name, and a newcomer is the one that
-- becomes `fileserver-2`. Ordered by id as a tiebreak, so two memberships created in the
-- same transaction do not depend on which row the planner reaches first.
DO $$
DECLARE
    m record;
    base text;
    candidate text;
    n integer;
    renamed integer := 0;
    total integer := 0;
BEGIN
    FOR m IN
        SELECT mem.id, mem.network_id, d.name AS device_name, d.id AS device_id
        FROM device_network_memberships mem
        JOIN devices d ON d.id = mem.device_id
        ORDER BY mem.network_id, mem.joined_at, mem.id
    LOOP
        -- Lowercase, anything that is not a letter, digit or hyphen becomes a hyphen,
        -- runs of hyphens collapse, and leading and trailing hyphens go. `Dave's laptop`
        -- becomes `dave-s-laptop`, which is guessable, which is the point.
        base := regexp_replace(lower(m.device_name), '[^a-z0-9]+', '-', 'g');
        base := regexp_replace(base, '(^-+)|(-+$)', '', 'g');
        base := left(base, 63);
        base := regexp_replace(base, '-+$', '', 'g');

        -- A name with nothing usable in it at all — empty, or only punctuation — gets one
        -- derived from the device's id. Opaque, and better than a device that cannot be
        -- named at all: every membership needs a label for the constraint below.
        IF base = '' THEN
            base := 'device-' || left(replace(m.device_id::text, '-', ''), 8);
        END IF;

        candidate := base;
        n := 1;
        WHILE EXISTS (
            SELECT 1 FROM device_network_memberships
            WHERE network_id = m.network_id AND dns_label = candidate
        ) LOOP
            n := n + 1;
            -- Truncated so the suffix always fits inside the 63-byte label limit, rather
            -- than producing a label the CHECK below would reject.
            candidate := left(base, 63 - length('-' || n::text)) || '-' || n::text;
        END LOOP;

        IF candidate <> base THEN
            renamed := renamed + 1;
        END IF;
        total := total + 1;

        UPDATE device_network_memberships SET dns_label = candidate WHERE id = m.id;
    END LOOP;

    -- Said out loud. An operator whose device was renamed has to be able to find out, and
    -- this is the only moment anything knows it happened.
    RAISE NOTICE 'meshp: assigned DNS labels to % membership(s); % renamed to avoid a collision within their network', total, renamed;
END $$;

ALTER TABLE device_network_memberships ALTER COLUMN dns_label SET NOT NULL;

-- The syntax, enforced rather than assumed. A label that is not one of these cannot be
-- carried by DNS, and finding that out at query time means a device that silently does not
-- resolve.
ALTER TABLE device_network_memberships
    ADD CONSTRAINT device_network_memberships_dns_label_check
    CHECK (dns_label ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');

-- The rule this table exists to hold.
ALTER TABLE device_network_memberships
    ADD CONSTRAINT device_network_memberships_dns_label_key
    UNIQUE (network_id, dns_label);

COMMENT ON COLUMN device_network_memberships.dns_label IS
    'The name this device answers to inside this network, as <dns_label>.<network slug>.<suffix>. Unique per network because that is the scope of the name. devices.name stays free text for display.';

-- +goose Down

ALTER TABLE device_network_memberships
    DROP CONSTRAINT IF EXISTS device_network_memberships_dns_label_key;
ALTER TABLE device_network_memberships
    DROP CONSTRAINT IF EXISTS device_network_memberships_dns_label_check;
ALTER TABLE device_network_memberships DROP COLUMN IF EXISTS dns_label;
