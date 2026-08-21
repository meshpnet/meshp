-- The names an administrator wrote down (ADR-0021 §2).
--
-- Device names are derived from the peer list and never stored here; these are the records
-- nothing can synthesise — a name for something that is not a meshp device, or a second name
-- for something that is.

-- name: EnsureDNSZone :one
-- The zone a network's records hang off, created on first use.
--
-- Lazily, like a prefix mapping, and for the same reason: a zone is not a decision anybody
-- makes, it is a consequence of the network's slug and the suffix that follows from it. A
-- deployment should not have to create one before it can write a record, and an
-- administrative endpoint for a row with no choices in it would be a form nobody can fill
-- in wrongly and nobody wants to fill in at all.
INSERT INTO dns_zones (network_id, name)
VALUES ($1, $2)
ON CONFLICT (network_id, name) DO UPDATE SET name = EXCLUDED.name
RETURNING *;

-- name: CreateDNSRecord :one
-- managed_by defaults to 'admin', which is what this endpoint writes. Device-derived
-- records would carry 'device' and a managed_ref_id, and would be regenerated rather than
-- kept — the column exists so reconciliation can tell the two apart.
INSERT INTO dns_records (zone_id, network_id, name, type, value, ttl)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListDNSRecordsForNetwork :many
-- Every administrator-entered record in a network, for the API and for the state builder.
--
-- Device-derived records are excluded rather than filtered by the caller: they are already
-- in the peer list the agent holds, and sending them twice would let the two disagree about
-- an address while both claiming to be current.
SELECT * FROM dns_records
WHERE network_id = $1 AND managed_by = 'admin'
ORDER BY name, type, value;

-- name: DeleteDNSRecord :execrows
-- Scoped to the network as well as the id, because the id arrives from a caller: without it
-- an administrator holding a token for one network could delete a record in another.
DELETE FROM dns_records
WHERE id = $1 AND network_id = $2;

-- name: CountDevicesWithDNSLabel :one
-- Whether a device in this network already answers to this name.
--
-- Asked before a record is written, so a collision is refused in front of the person typing
-- rather than resolved on every device afterwards. Revoked memberships do not count: their
-- names have stopped resolving, and holding a name against a device that is out of the
-- network would make an administrator undo a revocation to reuse a label.
SELECT count(*)::bigint FROM device_network_memberships
WHERE network_id = $1 AND dns_label = $2 AND state = 'active';
