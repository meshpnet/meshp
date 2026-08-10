-- meshp initial schema.
--
-- Design notes that are expensive to change later, so they are here from the
-- first migration:
--
--   * Addresses are allocated by IPAM, not chosen ad hoc, and are quarantined
--     after release so a revoked device's address is not immediately reissued
--     while DNS and ACL caches are still warm (ADR-0005).
--   * A device may hold memberships in several networks at once, each with its
--     own WireGuard key and interface. An MSP technician needs this on day one
--     (ADR-0004).
--   * Device identity is an Ed25519 key that outlives any WireGuard key, so
--     WireGuard keys rotate without re-enrolment (ADR-0006).
--   * Internet egress and subnet routing are the same object: a route group is
--     a set of prefixes with an ordered set of advertisers (ADR-0001).
--
-- Every tenant-scoped table carries organization_id or network_id. Nothing is
-- filtered client-side.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Tenancy
-- ---------------------------------------------------------------------------

CREATE TABLE organizations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            text NOT NULL UNIQUE,
    name            text NOT NULL,
    -- 'direct' is a self-serve or self-hosted org. 'agency' and 'customer'
    -- exist here so the proprietary MSP layer can build a hierarchy over this
    -- table without forking the schema; the OSS control plane treats all orgs
    -- as flat and ignores parent_organization_id.
    kind            text NOT NULL DEFAULT 'direct'
                    CHECK (kind IN ('direct', 'agency', 'customer')),
    parent_organization_id uuid REFERENCES organizations (id) ON DELETE RESTRICT,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    CHECK (parent_organization_id IS NULL OR parent_organization_id <> id)
);

CREATE INDEX organizations_parent_idx ON organizations (parent_organization_id)
    WHERE parent_organization_id IS NOT NULL;

CREATE TABLE networks (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    slug            text NOT NULL,
    name            text NOT NULL,
    -- Monotonic desired-state version for this network. Every mutation that
    -- changes what any agent should do bumps this exactly once.
    state_version   bigint NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    UNIQUE (organization_id, slug)
);

-- ---------------------------------------------------------------------------
-- IPAM
-- ---------------------------------------------------------------------------

CREATE TABLE address_pools (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    prefix          cidr NOT NULL,
    family          smallint NOT NULL CHECK (family IN (4, 6)),
    purpose         text NOT NULL DEFAULT 'device'
                    CHECK (purpose IN ('device', 'service')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (network_id, prefix)
);

CREATE INDEX address_pools_network_idx ON address_pools (network_id, family, purpose);

CREATE TABLE address_allocations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id         uuid NOT NULL REFERENCES address_pools (id) ON DELETE CASCADE,
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    address         inet NOT NULL,
    -- Held while in use, then quarantined for a cooldown before returning to
    -- the free pool.
    state           text NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'quarantined')),
    -- What holds it. Deliberately not a foreign key: an allocation outlives
    -- the membership that released it, which is the point of quarantine.
    holder_kind     text NOT NULL CHECK (holder_kind IN ('membership', 'service', 'reserved')),
    holder_id       uuid,
    allocated_at    timestamptz NOT NULL DEFAULT now(),
    released_at     timestamptz,
    quarantine_until timestamptz,
    UNIQUE (network_id, address)
);

CREATE INDEX address_allocations_holder_idx ON address_allocations (holder_kind, holder_id);
CREATE INDEX address_allocations_reclaim_idx ON address_allocations (state, quarantine_until)
    WHERE state = 'quarantined';

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    email           text NOT NULL,
    name            text NOT NULL DEFAULT '',
    -- Argon2id encoded hash. NULL when the user authenticates via OIDC only.
    password_hash   text,
    mfa_enrolled_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    suspended_at    timestamptz,
    deleted_at      timestamptz,
    UNIQUE (organization_id, email)
);

CREATE TABLE roles (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    slug            text NOT NULL,
    name            text NOT NULL,
    -- Roles are bags of permission strings such as
    -- 'network.devices.revoke'. Behaviour is never keyed off the role name.
    permissions     text[] NOT NULL DEFAULT '{}',
    is_builtin      boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug)
);

CREATE TABLE role_bindings (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id         uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Scope the grant. A binding with network_id NULL applies org-wide.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    network_id      uuid REFERENCES networks (id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_id, user_id, organization_id, network_id)
);

CREATE INDEX role_bindings_user_idx ON role_bindings (user_id);

CREATE TABLE groups (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    slug            text NOT NULL,
    name            text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (network_id, slug)
);

CREATE TABLE group_members (
    group_id        uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    added_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Devices
-- ---------------------------------------------------------------------------

CREATE TABLE devices (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    user_id             uuid REFERENCES users (id) ON DELETE SET NULL,
    name                text NOT NULL,
    hostname            text NOT NULL DEFAULT '',
    os                  text NOT NULL DEFAULT '',
    os_version          text NOT NULL DEFAULT '',
    agent_version        text NOT NULL DEFAULT '',
    -- Ed25519 public key. Survives WireGuard key rotation (ADR-0006).
    identity_public_key bytea NOT NULL UNIQUE,
    capabilities        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz,
    revoked_at          timestamptz,
    revoked_reason      text
);

CREATE INDEX devices_org_idx ON devices (organization_id) WHERE revoked_at IS NULL;
CREATE INDEX devices_user_idx ON devices (user_id);

-- A device joins a network once per membership. Several concurrent memberships
-- are expected: an MSP technician's laptop belongs to their own network and to
-- every customer network they support (ADR-0004).
CREATE TABLE device_network_memberships (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    -- Interface name the agent uses locally. Distinct per membership because
    -- customer networks may use overlapping private space.
    interface_name  text NOT NULL,
    address_v4      inet,
    address_v6      inet,
    state           text NOT NULL DEFAULT 'active'
                    CHECK (state IN ('pending', 'active', 'suspended', 'revoked')),
    tags            text[] NOT NULL DEFAULT '{}',
    joined_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz,
    revoked_at      timestamptz,
    UNIQUE (device_id, network_id)
);

CREATE INDEX memberships_network_idx ON device_network_memberships (network_id)
    WHERE state = 'active';

-- One WireGuard key per membership, not per device: reusing a public key
-- across customer networks would let those networks correlate the device.
CREATE TABLE wireguard_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_id   uuid NOT NULL REFERENCES device_network_memberships (id) ON DELETE CASCADE,
    public_key      text NOT NULL UNIQUE,
    state           text NOT NULL DEFAULT 'current'
                    CHECK (state IN ('current', 'retiring', 'retired')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    retire_after    timestamptz,
    retired_at      timestamptz
);

-- At most one current key per membership; 'retiring' keys overlap during
-- rotation so peers accept both for a short window.
CREATE UNIQUE INDEX wireguard_keys_one_current
    ON wireguard_keys (membership_id) WHERE state = 'current';

-- ---------------------------------------------------------------------------
-- Enrolment
-- ---------------------------------------------------------------------------

CREATE TABLE enrollment_tokens (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- Only a hash is stored; the plaintext is shown once at creation.
    token_hash      bytea NOT NULL UNIQUE,
    created_by_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Optional scoping.
    scoped_user_id  uuid REFERENCES users (id) ON DELETE CASCADE,
    preassigned_tags text[] NOT NULL DEFAULT '{}',
    max_uses        integer NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    uses            integer NOT NULL DEFAULT 0,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    CHECK (uses <= max_uses)
);

CREATE INDEX enrollment_tokens_network_idx ON enrollment_tokens (network_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Route groups
--
-- An exit pool is a route group over 0.0.0.0/0 and ::/0. A subnet router is a
-- route group over a LAN prefix. A service gateway is a route group over a
-- /32. Health, priority, draining and failover are written once (ADR-0001).
-- ---------------------------------------------------------------------------

CREATE TABLE route_groups (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    slug            text NOT NULL,
    name            text NOT NULL,
    kind            text NOT NULL
                    CHECK (kind IN ('egress', 'subnet', 'service')),
    selection_mode  text NOT NULL DEFAULT 'failover'
                    CHECK (selection_mode IN ('failover', 'pinned')),
    auto_failback   boolean NOT NULL DEFAULT true,
    failback_delay_seconds integer NOT NULL DEFAULT 300 CHECK (failback_delay_seconds >= 0),
    -- Floating address that survives failover. Set for customers who allowlist
    -- an outbound IP with a bank or vendor; NULL when egress IP may change.
    stable_egress_ip inet,
    -- Local failover policy handed to agents verbatim.
    local_failover  jsonb NOT NULL DEFAULT '{"enabled": true}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (network_id, slug)
);

CREATE TABLE route_group_prefixes (
    route_group_id  uuid NOT NULL REFERENCES route_groups (id) ON DELETE CASCADE,
    prefix          cidr NOT NULL,
    PRIMARY KEY (route_group_id, prefix)
);

CREATE TABLE route_advertisers (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    route_group_id  uuid NOT NULL REFERENCES route_groups (id) ON DELETE CASCADE,
    -- The membership doing the advertising. An advertiser is a role a device
    -- plays, never a separate kind of machine.
    membership_id   uuid NOT NULL REFERENCES device_network_memberships (id) ON DELETE CASCADE,
    priority        integer NOT NULL DEFAULT 1,
    weight          integer NOT NULL DEFAULT 100 CHECK (weight > 0),
    -- 'draining' keeps existing users and refuses new assignments, which is
    -- how maintenance happens without downtime.
    admin_state     text NOT NULL DEFAULT 'enabled'
                    CHECK (admin_state IN ('enabled', 'draining', 'disabled')),
    region          text NOT NULL DEFAULT '',
    city            text NOT NULL DEFAULT '',
    provider        text NOT NULL DEFAULT '',
    public_ip       inet,
    capacity_hint   integer,
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (route_group_id, membership_id)
);

CREATE INDEX route_advertisers_group_idx ON route_advertisers (route_group_id, priority);

CREATE TABLE advertiser_health (
    advertiser_id   uuid PRIMARY KEY REFERENCES route_advertisers (id) ON DELETE CASCADE,
    state           text NOT NULL DEFAULT 'unknown'
                    CHECK (state IN ('unknown', 'healthy', 'degraded', 'unhealthy', 'draining', 'offline')),
    consecutive_ok  integer NOT NULL DEFAULT 0,
    consecutive_fail integer NOT NULL DEFAULT 0,
    -- Health is a fusion of the node's self-report, the control plane's probe
    -- and what client agents actually observe through it. The last of these is
    -- the only one that measures what users experience.
    self_report     jsonb NOT NULL DEFAULT '{}'::jsonb,
    control_probe   jsonb NOT NULL DEFAULT '{}'::jsonb,
    client_observed jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_checked_at timestamptz,
    last_transition_at timestamptz,
    -- Floor on how often this advertiser may be reconsidered, to stop flapping.
    cooldown_until  timestamptz
);

CREATE INDEX advertiser_health_state_idx ON advertiser_health (state);

CREATE TABLE route_assignments (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_id   uuid NOT NULL REFERENCES device_network_memberships (id) ON DELETE CASCADE,
    route_group_id  uuid NOT NULL REFERENCES route_groups (id) ON DELETE CASCADE,
    advertiser_id   uuid REFERENCES route_advertisers (id) ON DELETE SET NULL,
    version         bigint NOT NULL DEFAULT 1,
    -- Free text explaining the current choice, surfaced verbatim in the UI and
    -- the audit log. This is what answers "why did my outbound IP change?".
    reason          text NOT NULL DEFAULT '',
    -- True when the agent moved itself before the control plane could decide.
    decided_locally boolean NOT NULL DEFAULT false,
    assigned_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (membership_id, route_group_id)
);

-- ---------------------------------------------------------------------------
-- Policy
-- ---------------------------------------------------------------------------

-- The whole ACL is one versioned document rather than a table of rows. Review,
-- diff, test and rollback all become trivial, and there is exactly one thing
-- to compile into per-agent filters.
CREATE TABLE acl_policies (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    version         integer NOT NULL,
    document        jsonb NOT NULL,
    is_active       boolean NOT NULL DEFAULT false,
    created_by_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (network_id, version)
);

CREATE UNIQUE INDEX acl_policies_one_active
    ON acl_policies (network_id) WHERE is_active;

-- ---------------------------------------------------------------------------
-- DNS
-- ---------------------------------------------------------------------------

CREATE TABLE dns_zones (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    name            text NOT NULL,
    -- Split DNS: queries for this zone go to meshp, everything else falls
    -- through to the system resolver.
    is_split        boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (network_id, name)
);

CREATE TABLE dns_records (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    zone_id         uuid NOT NULL REFERENCES dns_zones (id) ON DELETE CASCADE,
    network_id      uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    name            text NOT NULL,
    type            text NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME')),
    value           text NOT NULL,
    ttl             integer NOT NULL DEFAULT 60 CHECK (ttl > 0),
    -- Set when the record is derived from a device or service rather than
    -- entered by an admin, so reconciliation can rewrite it safely.
    managed_by      text NOT NULL DEFAULT 'admin'
                    CHECK (managed_by IN ('admin', 'device', 'service')),
    managed_ref_id  uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (zone_id, name, type, value)
);

CREATE INDEX dns_records_network_idx ON dns_records (network_id);

-- ---------------------------------------------------------------------------
-- Relays
-- ---------------------------------------------------------------------------

CREATE TABLE relays (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL means a relay offered to every network by this deployment.
    network_id      uuid REFERENCES networks (id) ON DELETE CASCADE,
    slug            text NOT NULL,
    region          text NOT NULL DEFAULT '',
    endpoints       text[] NOT NULL DEFAULT '{}',
    public_key      bytea NOT NULL,
    state           text NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'draining', 'disabled')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz,
    UNIQUE (slug)
);

-- ---------------------------------------------------------------------------
-- Convergence tracking
--
-- The gap between the network's state_version and what each membership has
-- applied is the single best health signal in a reconciliation system.
-- ---------------------------------------------------------------------------

CREATE TABLE membership_state (
    membership_id       uuid PRIMARY KEY REFERENCES device_network_memberships (id) ON DELETE CASCADE,
    network_id          uuid NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    applied_version     bigint NOT NULL DEFAULT 0,
    last_ack_at         timestamptz,
    last_error          text NOT NULL DEFAULT '',
    unapplied_components text[] NOT NULL DEFAULT '{}',
    discovered_mtu      integer,
    connected_since     timestamptz,
    control_session_id  text
);

CREATE INDEX membership_state_lag_idx ON membership_state (network_id, applied_version);

-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------

CREATE TABLE audit_events (
    id              bigserial PRIMARY KEY,
    organization_id uuid REFERENCES organizations (id) ON DELETE SET NULL,
    network_id      uuid REFERENCES networks (id) ON DELETE SET NULL,
    -- 'system' covers automatic actions such as failover, which must be as
    -- auditable as anything an admin does.
    actor_kind      text NOT NULL CHECK (actor_kind IN ('user', 'device', 'system', 'api_token')),
    actor_id        uuid,
    actor_label     text NOT NULL DEFAULT '',
    action          text NOT NULL,
    resource_kind   text NOT NULL DEFAULT '',
    resource_id     uuid,
    source_ip       inet,
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_org_time_idx ON audit_events (organization_id, created_at DESC);
CREATE INDEX audit_events_network_time_idx ON audit_events (network_id, created_at DESC);
CREATE INDEX audit_events_action_idx ON audit_events (action, created_at DESC);

-- +goose Down

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS membership_state;
DROP TABLE IF EXISTS relays;
DROP TABLE IF EXISTS dns_records;
DROP TABLE IF EXISTS dns_zones;
DROP TABLE IF EXISTS acl_policies;
DROP TABLE IF EXISTS route_assignments;
DROP TABLE IF EXISTS advertiser_health;
DROP TABLE IF EXISTS route_advertisers;
DROP TABLE IF EXISTS route_group_prefixes;
DROP TABLE IF EXISTS route_groups;
DROP TABLE IF EXISTS enrollment_tokens;
DROP TABLE IF EXISTS wireguard_keys;
DROP TABLE IF EXISTS device_network_memberships;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS role_bindings;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS address_allocations;
DROP TABLE IF EXISTS address_pools;
DROP TABLE IF EXISTS networks;
DROP TABLE IF EXISTS organizations;
