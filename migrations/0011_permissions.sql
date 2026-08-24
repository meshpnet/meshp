-- +goose Up

-- Permissions become real (ADR-0024 §4).
--
-- `roles` and `role_bindings` have been in the schema since the first migration and unread
-- for as long. Everything they need is already there; what this migration adds is what makes
-- them usable, and one backfill without which upgrading would lock every existing account
-- out of a control plane it could previously do anything to.

-- The four built-in roles are shared by every organisation rather than copied into each, so
-- `organization_id` is NULL on them. The table's UNIQUE (organization_id, slug) does not
-- constrain those rows at all — in PostgreSQL two NULLs are distinct, so it would happily
-- hold four roles called 'owner' — which is what this index is for.
CREATE UNIQUE INDEX roles_builtin_slug_idx ON roles (slug) WHERE organization_id IS NULL;

-- The same NULL-is-distinct problem, and here it is worse. An organisation-wide binding has
-- network_id NULL, so without this a role could be granted to the same person twice, three
-- times, any number of times, and each grant would look like a separate thing to revoke.
-- Removing one would appear to do nothing.
CREATE UNIQUE INDEX role_bindings_org_wide_idx
    ON role_bindings (role_id, user_id, organization_id)
    WHERE network_id IS NULL;

-- The lookup this puts in front of every authenticated request: which roles does this person
-- hold in this organisation. role_bindings_user_idx covers the user alone; the organisation
-- is always known alongside it, and a composite index is what stops the check from reading
-- bindings belonging to other tenants only to discard them.
CREATE INDEX role_bindings_user_org_idx ON role_bindings (user_id, organization_id);
DROP INDEX role_bindings_user_idx;

-- The built-in roles themselves, with no permissions.
--
-- Deliberately empty here. The permission list has exactly one home — internal/authz — and
-- the control plane reconciles these rows against it at startup, so adding a route tomorrow
-- does not mean writing a migration to tell the owner role about it. A permission array
-- written into SQL is a second copy of a list, and two copies of a list drift the first time
-- somebody updates one.
--
-- A deployment that runs this migration and never starts a control plane has four roles that
-- grant nothing, which is the safe direction to be wrong in.
INSERT INTO roles (organization_id, slug, name, permissions, is_builtin) VALUES
    (NULL, 'reader',        'Reader',        '{}', true),
    (NULL, 'operator',      'Operator',      '{}', true),
    (NULL, 'administrator', 'Administrator', '{}', true),
    (NULL, 'owner',         'Owner',         '{}', true);

-- Everybody who already has an account becomes an owner of their organisation.
--
-- Until this migration every authenticated user was equivalent and could do everything, which
-- adminOnly said out loud in a comment. Making permissions real without this line would turn
-- that into every authenticated user being able to do nothing — an upgrade that silently
-- locks a deployment's people out of their own control plane, and the administrative token
-- would be the only way back.
--
-- Owner rather than administrator because somebody has to be able to grant a role, and on a
-- deployment being upgraded there is nobody yet who can.
INSERT INTO role_bindings (role_id, user_id, organization_id, network_id)
SELECT r.id, u.id, u.organization_id, NULL
FROM users u
CROSS JOIN roles r
WHERE r.organization_id IS NULL
  AND r.slug = 'owner'
  AND u.deleted_at IS NULL;

-- +goose Down

DELETE FROM role_bindings
WHERE role_id IN (SELECT id FROM roles WHERE organization_id IS NULL AND is_builtin);
DELETE FROM roles WHERE organization_id IS NULL AND is_builtin;
DROP INDEX IF EXISTS role_bindings_user_org_idx;
CREATE INDEX role_bindings_user_idx ON role_bindings (user_id);
DROP INDEX IF EXISTS role_bindings_org_wide_idx;
DROP INDEX IF EXISTS roles_builtin_slug_idx;
