-- The tenant an organisation's networks belong to.
--
-- Flat here on purpose. The table carries `kind` and `parent_organization_id` so the
-- proprietary MSP layer can build a hierarchy over it without forking the schema, and the
-- open control plane treats every organisation as unrelated to every other — so neither
-- column is written or read by anything in this repository, and this API does not offer
-- them.

-- name: CreateOrganization :one
-- Always 'direct' and never a child. See above: the open plane does not model hierarchy,
-- and an endpoint that accepted a parent would be offering something nothing here honours.
INSERT INTO organizations (slug, name, kind)
VALUES ($1, $2, 'direct')
RETURNING id, slug, name, created_at;

-- name: ListOrganizations :many
-- scope: global an organisation is the tenant, so there is no tenant above it to be scoped
-- to. The only credential that reaches this is the administrative token, which is a single
-- shared secret granting every route already (ADR-0022 §5), and the browser's cookie is
-- deliberately not among them. The day roles arrive, this is one of the first queries that
-- has to grow a caller.
--
-- Every organisation this control plane holds, with how many networks each has.
--
-- The count because it is the question that follows immediately — an organisation with no
-- networks is one somebody created and did not finish setting up, and telling it apart from
-- a working one should not need a second call.
SELECT
    o.id,
    o.slug,
    o.name,
    o.created_at,
    (
        SELECT count(*)
        FROM networks n
        WHERE n.organization_id = o.id AND n.deleted_at IS NULL
    ) AS network_count
FROM organizations o
WHERE o.deleted_at IS NULL
ORDER BY o.slug;
