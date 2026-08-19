-- Where a colliding customer prefix is reached, when the real one cannot be routed to.
--
-- ADR-0020. Two customers of one MSP both use 192.168.1.0/24 -- the most common customer
-- network there is -- and a technician's routing table cannot hold that prefix twice. Today
-- both route groups are refused (PR #70), so the technician reaches neither. Each colliding
-- prefix gets a distinct range to be reached by, and the device rewrites the destination on
-- the way into the tunnel.
--
-- Keyed by (network_id, prefix) rather than by membership, and that is the decision worth
-- explaining. ADR-0020 allocates "for each colliding membership", which would allow the same
-- customer to be 100.71.5.0/24 on one technician's laptop and 100.71.9.0/24 on another's.
-- The ADR's own consequences rule that out: the mapped ranges have to be quotable in a
-- support ticket and "correlated across the devices of one deployment", and an address that
-- means something different on every laptop is a diagnostic that costs more than it gives.
-- One customer prefix therefore has one mapped range for the whole deployment, and every
-- device that needs it gets the same one.
--
-- Rows are allocated lazily, only when some device actually holds two memberships that
-- collide. A deployment where nobody is in two networks at once never has a row here, and
-- the addresses stay unspent.

-- +goose Up

CREATE TABLE prefix_mappings (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The organisation, because that is the scope a device sees. devices.organization_id is
    -- NOT NULL, so every membership a device holds is in one organisation's networks, and
    -- two mapped ranges only need to differ if they can land in one routing table.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,

    -- The customer's own prefix, as their router has it.
    prefix          cidr NOT NULL,
    -- What a device reaches it by, and what its routing table holds.
    mapped_prefix   cidr NOT NULL,

    created_at      timestamptz NOT NULL DEFAULT now(),

    -- One mapped range per customer prefix, for the whole deployment. This is the constraint
    -- that makes a mapped address mean one thing.
    UNIQUE (network_id, prefix),
    -- And no two customer prefixes reached by the same range, or the collision is back one
    -- level up with nothing left to resolve it.
    UNIQUE (organization_id, mapped_prefix),

    -- The host part is carried across unchanged, so the two halves must hold the same number
    -- of hosts. Mapping a /24 onto a /25 would silently drop half the customer's network,
    -- and the device's rules cannot express it -- internal/nftables refuses the same thing.
    CONSTRAINT prefix_mappings_same_size CHECK (masklen(prefix) = masklen(mapped_prefix)),
    -- Both halves are networks rather than addresses inside one, which needs no constraint:
    -- the cidr type refuses bits set below the netmask outright, so '10.1.2.3/24' cannot be
    -- stored here at all. Said rather than checked, because a CHECK that can never fire
    -- implies the type does not already guarantee it.
    --
    -- A default route has nothing to be mapped into: every address is inside it, so there is
    -- no distinct range to reach it by. Two full tunnels on one device stay refused, which is
    -- the honest answer rather than a mapping that cannot work.
    CONSTRAINT prefix_mappings_not_default CHECK (masklen(prefix) > 0)
);

-- The lookup the session path makes: everything mapped in the networks a device belongs to.
CREATE INDEX prefix_mappings_network_idx ON prefix_mappings (network_id);

COMMENT ON TABLE prefix_mappings IS
    'Distinct ranges for customer prefixes that collide on some device (ADR-0020). One row per (network, prefix) so a mapped address means the same thing across the deployment.';

-- +goose Down

DROP TABLE IF EXISTS prefix_mappings;
