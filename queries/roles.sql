-- Roles and the bindings that grant them (ADR-0024 §4).
--
-- A permission is a string and a role is a bag of them. Nothing in this file, and nothing
-- that calls it, decides anything from a role's *name* — the schema has said so since the
-- first migration, and it is the difference between a role system and a hardcoded list of
-- names with a table in front of it.
--
-- Two shapes of question are asked here, and the difference between them is the design:
--
--   * what may this person do *in this network* — answered by their organisation-wide
--     bindings and by any binding narrowed to that one network;
--   * what may this person do *across this organisation* — answered only by their
--     organisation-wide bindings.
--
-- A technician given a role on one customer's network holds it there and nowhere else, and
-- in particular does not hold it over the organisation that network belongs to. That
-- asymmetry is what an MSP needs and it is enforced in these two queries rather than by
-- every caller remembering to check.

-- name: UpsertBuiltinRole :one
-- Reconciles one built-in role against the catalogue in internal/authz.
--
-- Run at startup rather than seeded by a migration, so the permission list has exactly one
-- home. A route added tomorrow needs no migration for an owner to be able to reach it, and
-- there is no second copy of the list to drift.
--
-- Built-in roles are shared by every organisation — organization_id IS NULL — so this
-- conflicts on the partial unique index over that case rather than on the table's own
-- constraint, which does not constrain NULLs at all.
INSERT INTO roles (organization_id, slug, name, permissions, is_builtin)
VALUES (NULL, $1, $2, $3, true)
ON CONFLICT (slug) WHERE organization_id IS NULL
DO UPDATE SET name = EXCLUDED.name, permissions = EXCLUDED.permissions, is_builtin = true
RETURNING id, slug, name, permissions, is_builtin;

-- name: ListRolesForOrganization :many
-- The roles this organisation can grant: the built-ins every deployment has, plus any it
-- defined for itself.
SELECT id, organization_id, slug, name, permissions, is_builtin, created_at
FROM roles
WHERE organization_id = $1 OR organization_id IS NULL
ORDER BY is_builtin DESC, slug;

-- name: GetRoleForOrganizationBySlug :one
-- Resolves a slug a caller typed. An organisation's own role wins over a built-in of the
-- same name, which is what lets a deployment redefine 'operator' for itself without the
-- built-in shadowing it — ORDER BY puts the more specific row first.
SELECT id, organization_id, slug, name, permissions, is_builtin
FROM roles
WHERE (organization_id = $1 OR organization_id IS NULL)
  AND slug = sqlc.arg(slug)::text
ORDER BY organization_id NULLS LAST
LIMIT 1;

-- name: ListPermissionsInNetwork :many
-- What this person may do in this network.
--
-- Their organisation-wide bindings, plus any binding narrowed to this network. Joined
-- through `networks` rather than taking the organisation as a parameter, so the caller
-- cannot pass a network from one tenant and an organisation from another: the network's own
-- row decides which organisation's bindings count.
--
-- No rows is the answer for a person with no roles here, for a network that does not exist,
-- and for a network belonging to a different organisation. The caller refuses all three the
-- same way, which is deliberate — telling them apart would answer "does this network exist"
-- for somebody who cannot see it.
--
-- Returned as arrays and merged by the caller rather than unnested here. A person holds a
-- handful of bindings, so the merge is free, and the query stays one a reviewer can read.
SELECT r.permissions
FROM networks n
JOIN role_bindings b
  ON b.organization_id = n.organization_id
 AND (b.network_id IS NULL OR b.network_id = n.id)
JOIN roles r ON r.id = b.role_id
WHERE n.id = $1
  AND n.deleted_at IS NULL
  AND b.user_id = $2;

-- name: ListPermissionsInOrganization :many
-- What this person may do across this organisation.
--
-- Organisation-wide bindings only. A binding narrowed to one network deliberately grants
-- nothing here: somebody who looks after a single customer's network must not be able to
-- create accounts across the organisation that network happens to sit in.
SELECT r.permissions
FROM role_bindings b
JOIN roles r ON r.id = b.role_id
WHERE b.user_id = $1
  AND b.organization_id = $2
  AND b.network_id IS NULL;

-- name: CreateRoleBinding :one
-- Grants a role. ON CONFLICT because granting a role somebody already holds is not an error
-- — it is somebody making sure — and the two unique constraints cover the two shapes: the
-- table's own for a binding narrowed to a network, the partial index for an
-- organisation-wide one, whose NULL network_id the table's constraint does not see.
INSERT INTO role_bindings (role_id, user_id, organization_id, network_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING
RETURNING id, role_id, user_id, organization_id, network_id, created_at;

-- name: ListRoleBindingsForUser :many
-- Who this person is, in role terms. Carries the role and the network by name because the
-- answer is read by a human deciding whether it is right, and a page of UUIDs is not.
SELECT b.id, b.role_id, b.user_id, b.organization_id, b.network_id, b.created_at,
       r.slug AS role_slug, r.name AS role_name, r.permissions,
       n.slug AS network_slug, n.name AS network_name
FROM role_bindings b
JOIN roles r ON r.id = b.role_id
LEFT JOIN networks n ON n.id = b.network_id
WHERE b.user_id = $1 AND b.organization_id = $2
ORDER BY r.slug, n.slug NULLS FIRST;

-- name: DeleteRoleBinding :execrows
-- Scoped by organisation as well as by id, so a binding id learned in one tenant cannot be
-- used to revoke a grant in another.
DELETE FROM role_bindings WHERE id = $1 AND organization_id = $2;

-- name: CountOrganizationWideBindingsOfRole :one
-- How many people hold this role over the whole organisation.
--
-- Asked before a grant is removed, so an organisation cannot be left with nobody who can
-- grant one. The administrative token is still a way back in (ADR-0024 §5), but needing it
-- because somebody removed their own last role is a bad afternoon that a count prevents.
SELECT count(*)::bigint
FROM role_bindings
WHERE organization_id = $1 AND role_id = $2 AND network_id IS NULL;

-- name: GetRoleBindingForOrganization :one
-- One grant, scoped by organisation as well as by id so a binding id learned in one tenant
-- cannot be inspected — or removed, since the caller reads before it deletes — in another.
--
-- Carries the role's slug because removing a grant has one rule that depends on which role
-- it is: an organisation may not be left without an owner.
SELECT b.id, b.role_id, b.user_id, b.organization_id, b.network_id, b.created_at,
       r.slug AS role_slug, r.name AS role_name
FROM role_bindings b
JOIN roles r ON r.id = b.role_id
WHERE b.id = $1 AND b.organization_id = $2;
