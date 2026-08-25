-- The relays a deployment offers, and whether each is taking new sessions (#128).
--
-- MESHP_RELAYS still names them; what this table adds is a state that can be changed while
-- the control plane is running. Configuration seeds it at startup, so an existing deployment
-- keeps working and becomes visible, and nobody needs a migration to name their first relay.

-- name: UpsertRelayFromConfig :one
-- Seeds one relay from MESHP_RELAYS.
--
-- The endpoints are refreshed because configuration is still the source of truth for where a
-- relay is; the state deliberately is not, because that is the one thing an operator changes
-- at runtime and a restart must not silently undo a drain.
--
-- Deployment-wide: network_id stays NULL. A relay offered to one network is a capability the
-- column anticipates and nothing sets, so this does not pretend to.
INSERT INTO relays (slug, endpoints, public_key, state)
VALUES ($1, $2, NULL, 'active')
ON CONFLICT (slug) DO UPDATE SET endpoints = EXCLUDED.endpoints
RETURNING id, slug, endpoints, state, region, last_seen_at, created_at;

-- name: ListActiveRelays :many
-- scope: global a relay belongs to the deployment rather than to a tenant. network_id exists
-- so one could be offered to a single network and nothing sets it, so every relay here is
-- offered to everybody — which is what makes this the query the state builder runs.
--
-- Read on every state build, like the DNS records beside it. Ordered so two agents asked at
-- the same moment are told the same thing in the same order: an agent picks the first relay
-- it can reach, and a list whose order wobbled would scatter devices across relays for no
-- reason.
SELECT id, slug, endpoints, state, region, last_seen_at, created_at
FROM relays
WHERE state = 'active'
ORDER BY slug;

-- name: ListRelays :many
-- scope: global as above, and this one is for an operator rather than an agent: draining and
-- disabled relays are included, because "did that drain actually take" is the question this
-- list is opened to answer.
SELECT id, slug, endpoints, state, region, last_seen_at, created_at
FROM relays
ORDER BY slug;

-- name: SetRelayState :one
-- Takes a relay out of service, or puts it back.
--
-- Returns the row so the caller can tell "changed" from "already like that" and report
-- honestly. No row means no such relay.
UPDATE relays
SET state = sqlc.arg(state)::text
WHERE slug = $1
RETURNING id, slug, endpoints, state, region, last_seen_at, created_at;

-- name: DeleteRelaysNotIn :execrows
-- scope: global a relay belongs to the deployment and not to a tenant, so there is no
-- organisation to scope this by. It is also not reachable from the API at all: it runs at
-- startup against what MESHP_RELAYS names, so the only thing that can invoke it is the
-- process reading its own configuration.
--
-- Removes relays configuration no longer names.
--
-- Configuration is the source of truth for which relays exist, so one taken out of
-- MESHP_RELAYS should not linger as a row an operator can re-enable into nothing. Runs at
-- startup beside the upserts, and only ever removes rows this deployment put there.
DELETE FROM relays WHERE slug <> ALL(sqlc.arg(slugs)::text[]);
