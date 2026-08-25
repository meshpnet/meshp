package bus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// channel is the PostgreSQL notification channel every replica listens on.
//
// One channel for every network rather than one per network, because a replica cares about
// whichever networks its agents happen to hold and that set changes as devices connect.
// Issuing a LISTEN per network would mean tracking that set and un-listening as it shrank;
// filtering a handful of ids in the subscriber is free by comparison.
const channel = "meshp_network_changed"

// reconnect bounds how fast a listener retries, and how slow it gets.
//
// A control plane that has lost PostgreSQL has bigger problems than a missed nudge, so this
// backs off rather than hammering — and it caps low enough that recovery is quick, because
// the window while it is disconnected is a window in which changes reach agents only on
// their next heartbeat.
const (
	reconnectMin = 250 * time.Millisecond
	reconnectMax = 5 * time.Second
)

// Postgres carries notifications over LISTEN/NOTIFY (ADR-0025).
//
// Publishing borrows a pooled connection like any other statement. Listening cannot: LISTEN
// registers interest for the session, and a pooled connection is handed back between
// statements, so the subscriber dials a connection of its own and keeps it.
type Postgres struct {
	pool *pgxpool.Pool
	log  *slog.Logger

	mu     sync.Mutex
	closed bool
}

// NewPostgres returns a bus over an existing pool.
func NewPostgres(pool *pgxpool.Pool, log *slog.Logger) *Postgres {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Postgres{pool: pool, log: log}
}

// Publish says a network's state changed.
//
// Called after the change has committed, so this is its own statement rather than part of
// the caller's transaction. Being outside the transaction is what makes the ordering safe
// in the direction that matters: the state is already durable when the message goes out, so
// no listener can be woken to read something that is not there yet.
//
// A caller that ever wants the reverse — notify *with* the commit — should send this inside
// the transaction instead, where PostgreSQL holds it until commit and discards it on
// rollback. That property is why this is PostgreSQL and not Redis, and it is available here
// the day something needs it.
func (p *Postgres) Publish(ctx context.Context, networkID uuid.UUID) error {
	if _, err := p.pool.Exec(ctx, "SELECT pg_notify($1, $2)", channel, networkID.String()); err != nil {
		return fmt.Errorf("bus: publishing that %s changed: %w", networkID, err)
	}
	return nil
}

// Subscribe calls fn for every network id published, until ctx is done.
//
// Reconnects on its own, and deliberately does not report failures to the caller: there is
// nothing a caller could do that this cannot, and a Subscribe that returned an error would
// have every caller writing the same retry loop slightly differently.
//
// What a caller does need to know is that messages sent while this is disconnected are lost
// — LISTEN has no backlog, and a notification with nobody listening is discarded by the
// server. That is by design (see the package documentation): the agents on this replica
// pick the change up on their next heartbeat.
func (p *Postgres) Subscribe(ctx context.Context, fn func(uuid.UUID)) {
	backoff := reconnectMin
	for {
		if ctx.Err() != nil {
			return
		}
		err := p.listen(ctx, fn)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			p.log.Warn("the replica bus is not connected",
				"error", err, "retry_in", backoff,
				"consequence", "changes made on other replicas reach this one's agents "+
					"on their next heartbeat rather than immediately")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// listen holds one connection for as long as it works.
func (p *Postgres) listen(ctx context.Context, fn func(uuid.UUID)) error {
	// A connection of its own rather than one from the pool. Holding a pooled connection
	// for the life of the process would take it out of circulation without the pool
	// knowing why, and the pool would still count it against MaxConns.
	conn, err := pgx.ConnectConfig(ctx, p.pool.Config().ConnConfig)
	if err != nil {
		return fmt.Errorf("bus: connecting to listen: %w", err)
	}
	defer func() {
		// Its own context: the caller's is usually already cancelled by the time this
		// runs, and a close that inherited it would not get the chance to say goodbye.
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()

	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return fmt.Errorf("bus: listening on %s: %w", channel, err)
	}
	p.log.Info("the replica bus is connected", "channel", channel)

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("bus: waiting for a notification: %w", err)
		}
		networkID, err := uuid.Parse(notification.Payload)
		if err != nil {
			// Somebody else on this channel, or a message from a version that carries
			// something other than a network id. Ignored rather than fatal: this
			// connection is still good, and refusing to carry on would turn one bad
			// message into a replica that stops hearing anything.
			p.log.Warn("a bus notification was not a network id", "channel", notification.Channel)
			continue
		}
		fn(networkID)
	}
}

// Close marks the bus closed. The listening connection belongs to Subscribe and ends with
// the context it was given.
func (p *Postgres) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("bus: already closed")
	}
	p.closed = true
	return nil
}
