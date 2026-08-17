-- name: CarriedPrefixesForDevice :many
-- Every prefix reachable through each network this device belongs to.
--
-- The input to collision detection (ADR-0020). A prefix appearing under two different
-- networks is one this device's routing table cannot hold twice, and the reason a technician
-- in two customers' networks reaches neither of them today.
--
-- Active memberships only, and live devices only. A membership that has been revoked or a
-- device that has been deactivated is not going to route anything, and letting either
-- contribute would spend a mapped range on a collision that does not exist.
--
-- Egress groups are excluded here rather than filtered later. They carry the default route,
-- which contains every address and therefore has no distinct range to be reached by, so two
-- full tunnels are a collision nothing can map. Counting them would report a fault an
-- operator cannot act on.
SELECT m.network_id, rgp.prefix
FROM device_network_memberships m
JOIN route_groups rg ON rg.network_id = m.network_id
JOIN route_group_prefixes rgp ON rgp.route_group_id = rg.id
WHERE m.device_id = $1
  AND m.state = 'active'
  AND rg.kind <> 'egress'
ORDER BY m.network_id, rgp.prefix;

-- name: MappedPrefixesForNetworks :many
-- What has already been allocated for these networks.
SELECT network_id, prefix, mapped_prefix
FROM prefix_mappings
WHERE network_id = ANY($1::uuid[])
ORDER BY network_id, prefix;

-- name: SpokenForRangesInOrganization :many
-- Everything in this organisation a mapped range must not land on.
--
-- Both halves matter. Address pools are the mesh addresses of networks the device is in, and
-- a mapped range on top of one would be the same collision a level up with nothing left to
-- resolve it. Existing mapped ranges are the obvious other half.
--
-- The customers' own prefixes are deliberately absent: they are the thing being mapped away
-- from, they already collide with each other, and refusing to allocate near them would rule
-- out the whole of RFC 1918 for no gain.
SELECT p.prefix
FROM address_pools p
JOIN networks n ON n.id = p.network_id
WHERE n.organization_id = $1 AND n.deleted_at IS NULL
UNION ALL
SELECT mapped_prefix AS prefix
FROM prefix_mappings
WHERE organization_id = $1;

-- name: InsertPrefixMapping :one
-- Records where a colliding prefix is reached.
--
-- ON CONFLICT DO NOTHING on the natural key, because two devices in the same two networks
-- discover the same collision independently and will race to allocate for it. The loser
-- takes the winner's answer rather than failing: one customer prefix has one mapped range
-- for the whole deployment, and which session got there first is not interesting.
INSERT INTO prefix_mappings (organization_id, network_id, prefix, mapped_prefix)
VALUES ($1, $2, $3, $4)
ON CONFLICT (network_id, prefix) DO NOTHING
RETURNING network_id, prefix, mapped_prefix;

-- name: OrganizationForDevice :one
SELECT organization_id FROM devices WHERE id = $1;
