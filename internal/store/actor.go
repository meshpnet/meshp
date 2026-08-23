package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// Actor is who did something, for the audit trail.
//
// A type rather than three loose fields on every request, because the failure this is
// guarding against is quiet: an audited action whose author forgot to say who was acting
// writes a row that looks like every other row and answers nothing. One value is one thing
// to remember, and writeAudit below refuses a zero one — so forgetting is a compile-time
// omission that fails at the first test rather than a blank column somebody notices in six
// months.
type Actor struct {
	// Kind is one of the values audit_events.actor_kind allows: user, device, system or
	// api_token.
	Kind string

	// ID names the row this actor is, where there is one. Nil for the bootstrap secret,
	// which is nobody in particular — that being the whole problem with it.
	ID *uuid.UUID

	// Label is what a person reads. An audit line of bare UUIDs is one nobody reads.
	Label string
}

// ErrNoActor means an audited action did not say who was acting.
//
// Returned rather than defaulted. A default would be a guess written into a record whose
// entire purpose is not guessing.
var ErrNoActor = errors.New("store: an audited action must say who was acting")

// UserActor is a signed-in person.
func UserActor(user User) Actor {
	id := user.ID
	return Actor{Kind: "user", ID: &id, Label: user.Email}
}

// DeviceActor is a machine acting for itself — an agent choosing a candidate, or a device
// completing its own enrolment.
func DeviceActor(deviceID uuid.UUID, name string) Actor {
	id := deviceID
	return Actor{Kind: "device", ID: &id, Label: name}
}

// BootstrapActor is the administrative token.
//
// Named rather than left blank, which is what it was: every administrative action in this
// system has been recorded as `api_token` with no id and no label, so the trail could say
// that something happened and never who. It still cannot say who — a shared secret has no
// identity, which is ADR-0024's whole argument — but it can at least say that the shared
// secret was what did it, so "somebody used the root credential" is visible rather than
// inferred from the absence of anything else.
func BootstrapActor() Actor {
	return Actor{Kind: "api_token", Label: "the bootstrap admin token"}
}

// Valid reports whether this actor says anything.
func (a Actor) Valid() bool {
	switch a.Kind {
	case "user", "device", "system", "api_token":
		return a.Label != "" || a.ID != nil
	default:
		return false
	}
}

// WriteAudit records that something happened, and refuses to record it anonymously.
//
// Every audited action goes through here, including the ones in other packages — which is
// why it is exported rather than kept private to this one. The check is the point: an
// audit_events row with no actor is worse than no row, because it looks like a record and
// answers none of the question a record is for.
func WriteAudit(ctx context.Context, q *dbgen.Queries, actor Actor, params dbgen.CreateAuditEventParams) error {
	if !actor.Valid() {
		return ErrNoActor
	}
	params.ActorKind = actor.Kind
	params.ActorID = actor.ID
	params.ActorLabel = actor.Label

	if _, err := q.CreateAuditEvent(ctx, params); err != nil {
		return fmt.Errorf("store: writing the audit event: %w", err)
	}
	return nil
}
