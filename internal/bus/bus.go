// Package bus carries "network N's state changed" between control-plane replicas.
//
// It exists so that an administrator's change reaches every agent, not only the agents
// attached to the replica that took the request. One replica revokes a device; the agents
// holding sessions on the other two have to be told.
//
// # Nothing here is load-bearing
//
// ADR-0012 is explicit that no correctness property may depend on delivery: a missed
// notification must degrade to the agent's next heartbeat noticing a version gap, never to
// a permanently stale agent. That is what makes a best-effort queue the right shape rather
// than a compromise — and it is a property to preserve, not merely to rely on. Anything
// that starts *needing* a message to arrive has moved a correctness property into a
// channel built to drop them.
//
// So a publish that fails is logged and not retried, and a subscriber that misses a
// reconnect window misses the messages sent during it. Both cost latency and neither costs
// correctness.
package bus

import (
	"context"

	"github.com/google/uuid"
)

// Bus publishes and receives "this network changed".
//
// The message carries a network id and deliberately nothing else. It says *what* changed
// and never *how*, so a listener always reads the committed state from PostgreSQL rather
// than trusting something that arrived over a wire — which means there is no format to
// version, and a replica running older code cannot be confused by a newer one's message.
type Bus interface {
	// Publish says a network's state changed. Best effort: the error is worth logging and
	// not worth failing a request over, because the change is already committed and the
	// heartbeat will carry it.
	Publish(ctx context.Context, networkID uuid.UUID) error

	// Subscribe calls fn for every network id published, until ctx is done. It reconnects
	// on its own; a caller that had to supervise it would be a caller that could get the
	// supervision wrong.
	Subscribe(ctx context.Context, fn func(networkID uuid.UUID))

	// Close releases whatever the implementation holds.
	Close() error
}

// Local is the bus for a deployment running one replica.
//
// It does nothing, and that is the whole implementation: with one replica the publisher and
// every subscriber are the same process, and tellNetwork already nudges the local hub
// directly. A Local that looped messages back would deliver every notification twice for no
// benefit.
//
// Not nil, because a nil Bus would put a nil check at every call site, and one of them would
// eventually be missing.
type Local struct{}

// Publish discards the message. See the type documentation.
func (Local) Publish(context.Context, uuid.UUID) error { return nil }

// Subscribe waits for the context and delivers nothing.
//
// It blocks rather than returning, so the caller's supervision loop behaves the same way
// whichever implementation is configured — a Subscribe that returned immediately would have
// a single-replica deployment spinning through a reconnect loop that has nothing to
// reconnect to.
func (Local) Subscribe(ctx context.Context, _ func(uuid.UUID)) { <-ctx.Done() }

// Close releases nothing.
func (Local) Close() error { return nil }
