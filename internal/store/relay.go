package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// Relay states. A relay is one of exactly these, and the check constraint agrees.
const (
	// RelayActive is a relay agents are told about.
	RelayActive = "active"

	// RelayDraining is a relay that stays reachable and stops being handed out.
	//
	// The state this whole table exists for. New agents are not told about it, so nothing
	// new arrives; sessions already using it keep working, because the relay is still
	// running and the agents holding it have not been asked to move. What that buys an
	// operator is a relay that empties rather than one that drops everybody at once.
	//
	// Worth being honest about the limit: nothing yet reports how many sessions are still
	// on it (relays do not check in — see #128), so the operator judges when it is empty.
	// Draining is the mechanism; knowing it finished is not built.
	RelayDraining = "draining"

	// RelayDisabled is a relay agents are not told about and which is not expected back.
	RelayDisabled = "disabled"
)

// ErrNoSuchRelay means no relay by that name.
var ErrNoSuchRelay = errors.New("store: no such relay")

// ErrBadRelayState means a state this table does not allow.
var ErrBadRelayState = errors.New("store: a relay is active, draining or disabled")

// Relay is one relay this deployment offers.
//
// Deliberately without Region or PublicKey. Both are columns the first migration
// anticipated and nothing reads: the trust between control plane and relay runs the other
// way (the control plane signs, the relay verifies — ADR-0016), and no code chooses a relay
// by region. Surfacing them here would offer a structure nothing honours, which is the
// thing #128 warned against when it said not to add API surface for capabilities nobody has.
type Relay struct {
	ID        uuid.UUID
	Slug      string
	Endpoints []string
	State     string
	CreatedAt time.Time

	// LastSeenAt is when the relay last checked in, and is always nil: relays do not check
	// in yet. Carried so a caller can render "unknown" rather than inventing a health it
	// has no basis for.
	LastSeenAt *time.Time
}

// SyncRelaysFromConfig makes the table match MESHP_RELAYS.
//
// Called at startup. Configuration remains the source of truth for which relays exist and
// where they are; what the table adds is a state that survives being changed at runtime —
// so endpoints are refreshed on every boot and state deliberately is not, because a restart
// silently undoing a drain is the failure this is meant to remove.
//
// A relay dropped from configuration is removed rather than left behind. Otherwise it
// lingers as a row an operator can put back into service, pointing at a relay that is no
// longer part of this deployment.
func (s *Store) SyncRelaysFromConfig(ctx context.Context, relays map[string][]string) error {
	slugs := make([]string, 0, len(relays))
	for slug, endpoints := range relays {
		if _, err := s.Queries().UpsertRelayFromConfig(ctx, dbgen.UpsertRelayFromConfigParams{
			Slug: slug, Endpoints: endpoints,
		}); err != nil {
			return fmt.Errorf("store: recording relay %q: %w", slug, err)
		}
		slugs = append(slugs, slug)
	}
	if _, err := s.Queries().DeleteRelaysNotIn(ctx, slugs); err != nil {
		return fmt.Errorf("store: removing relays no longer configured: %w", err)
	}
	return nil
}

// ActiveRelays is what agents should be told about.
//
// Read on every state build, beside the DNS records. A relay list changes when an operator
// changes it, which is rare, and caching it would mean a drain taking effect at a time
// nobody could predict — the cost of the query is a few rows on an indexed column.
func (s *Store) ActiveRelays(ctx context.Context) ([]Relay, error) {
	rows, err := s.Queries().ListActiveRelays(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: reading the active relays: %w", err)
	}
	out := make([]Relay, 0, len(rows))
	for _, row := range rows {
		out = append(out, Relay{
			ID: row.ID, Slug: row.Slug, Endpoints: row.Endpoints,
			State: row.State, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt,
		})
	}
	return out, nil
}

// ListRelays is every relay, whatever its state — which is what an operator needs, because
// "did that drain take" is the question the list is opened to answer.
func (s *Store) ListRelays(ctx context.Context) ([]Relay, error) {
	rows, err := s.Queries().ListRelays(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: listing relays: %w", err)
	}
	out := make([]Relay, 0, len(rows))
	for _, row := range rows {
		out = append(out, Relay{
			ID: row.ID, Slug: row.Slug, Endpoints: row.Endpoints,
			State: row.State, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt,
		})
	}
	return out, nil
}

// SetRelayStateRequest takes a relay out of service, or puts it back.
type SetRelayStateRequest struct {
	Slug  string
	State string

	Actor    Actor
	SourceIP *netip.Addr
}

// SetRelayState changes whether a relay is handed out, and records who changed it.
//
// Audited because it is an operator deciding that traffic should stop arriving somewhere,
// which is exactly the kind of decision somebody asks about afterwards — and because a relay
// going quiet has several possible causes, only one of which is that a person meant it.
func (s *Store) SetRelayState(ctx context.Context, req SetRelayStateRequest) (Relay, error) {
	switch req.State {
	case RelayActive, RelayDraining, RelayDisabled:
	default:
		return Relay{}, fmt.Errorf("%w: %q", ErrBadRelayState, req.State)
	}

	var out Relay
	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		row, err := q.SetRelayState(ctx, dbgen.SetRelayStateParams{
			Slug: req.Slug, State: req.State,
		})
		if IsNotFound(err) {
			return fmt.Errorf("%w: %q", ErrNoSuchRelay, req.Slug)
		}
		if err != nil {
			return fmt.Errorf("store: setting the state of relay %q: %w", req.Slug, err)
		}

		metadata, _ := json.Marshal(map[string]any{"relay": row.Slug, "state": row.State})
		relayID := row.ID
		if err := WriteAudit(ctx, q, req.Actor, dbgen.CreateAuditEventParams{
			// No organisation and no network: a relay belongs to the deployment, and
			// naming one tenant would put a deployment-wide act in one customer's trail
			// and nobody else's.
			Action:       "relay.state_changed",
			ResourceKind: "relay",
			ResourceID:   &relayID,
			SourceIp:     req.SourceIP,
			Metadata:     metadata,
		}); err != nil {
			return err
		}

		out = Relay{
			ID: row.ID, Slug: row.Slug, Endpoints: row.Endpoints,
			State: row.State, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt,
		}
		return nil
	})
	return out, err
}
