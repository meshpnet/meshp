package bus

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These need a real PostgreSQL, because what is being tested is PostgreSQL's behaviour
// rather than meshp's arithmetic. A fake would assert that the fake agrees with itself.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("MESHP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set MESHP_TEST_DATABASE_URL to run the bus tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// collector gathers what a subscriber receives.
type collector struct {
	mu   sync.Mutex
	got  []uuid.UUID
	seen chan struct{}
}

func newCollector() *collector { return &collector{seen: make(chan struct{}, 64)} }

func (c *collector) fn(id uuid.UUID) {
	c.mu.Lock()
	c.got = append(c.got, id)
	c.mu.Unlock()
	select {
	case c.seen <- struct{}{}:
	default:
	}
}

func (c *collector) all() []uuid.UUID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uuid.UUID(nil), c.got...)
}

// has reports whether one particular id has arrived.
func (c *collector) has(want uuid.UUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range c.got {
		if id == want {
			return true
		}
	}
	return false
}

// waitForID blocks until one particular id arrives, or fails.
//
// By id rather than by count, which the first version of this got wrong: readiness is
// established by publishing a throwaway id, so a wait for "one message" is satisfied by the
// probe that proved the subscriber was listening, and the test then asserts against a
// message that has not arrived yet.
func (c *collector) waitForID(t *testing.T, want uuid.UUID) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if c.has(want) {
			return
		}
		select {
		case <-c.seen:
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatalf("waited for %s and got %v", want, c.all())
		}
	}
}

// The whole point: a change published by one replica reaches another.
//
// Two pools against one database, which is what two meshp-control processes are.
func TestAChangeOnOneReplicaReachesAnother(t *testing.T) {
	publisher := NewPostgres(testPool(t), nil)
	subscriber := NewPostgres(testPool(t), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := newCollector()
	go subscriber.Subscribe(ctx, got.fn)
	waitUntilListening(t, ctx, publisher, got)

	network := uuid.New()
	if err := publisher.Publish(ctx, network); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	got.waitForID(t, network)
}

// Every replica hears it, not just the first. A bus that delivered to one subscriber would
// leave the other replicas' agents waiting for a heartbeat.
func TestEveryReplicaHearsIt(t *testing.T) {
	publisher := NewPostgres(testPool(t), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var collectors []*collector
	for range 3 {
		sub := NewPostgres(testPool(t), nil)
		got := newCollector()
		go sub.Subscribe(ctx, got.fn)
		collectors = append(collectors, got)
	}
	for _, got := range collectors {
		waitUntilListening(t, ctx, publisher, got)
	}

	network := uuid.New()
	if err := publisher.Publish(ctx, network); err != nil {
		t.Fatal(err)
	}
	for i, got := range collectors {
		if !t.Run("replica "+string(rune('a'+i)), func(t *testing.T) {
			got.waitForID(t, network)
		}) {
			t.Errorf("replica %d never heard about %s", i, network)
		}
	}
}

// A notification in a transaction that rolls back is never delivered.
//
// This is the property that makes PostgreSQL the right carrier rather than merely the
// cheapest one (ADR-0025): a replica cannot be woken to read state that was never
// committed. Asserted here because the ADR claims it, and a claim in a record that nothing
// checks is a claim that quietly stops being true.
func TestARolledBackChangeIsNeverAnnounced(t *testing.T) {
	pool := testPool(t)
	publisher := NewPostgres(pool, nil)
	subscriber := NewPostgres(testPool(t), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := newCollector()
	go subscriber.Subscribe(ctx, got.fn)
	waitUntilListening(t, ctx, publisher, got)

	rolledBack, committed := uuid.New(), uuid.New()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", channel, rolledBack.String()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// A second, committed, so there is something to wait for: proving a message did not
	// arrive needs a message that did, or the test passes by being too quick.
	if err := publisher.Publish(ctx, committed); err != nil {
		t.Fatal(err)
	}
	got.waitForID(t, committed)

	if got.has(rolledBack) {
		t.Error("a notification from a rolled-back transaction was delivered")
	}
}

// A subscriber that is not connected misses what was sent, and carries on.
//
// Stated as a test because it is a design property rather than a defect: LISTEN has no
// backlog, and ADR-0012 requires that a missed notification cost latency rather than
// correctness. Somebody who later makes this durable should have to delete this test and
// think about what they are changing.
func TestMessagesSentWhileDisconnectedAreLost(t *testing.T) {
	publisher := NewPostgres(testPool(t), nil)
	subscriber := NewPostgres(testPool(t), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Nobody listening yet.
	missed := uuid.New()
	if err := publisher.Publish(ctx, missed); err != nil {
		t.Fatal(err)
	}

	got := newCollector()
	go subscriber.Subscribe(ctx, got.fn)
	later := uuid.New()
	waitUntilListeningWith(t, ctx, publisher, got, later)

	if got.has(missed) {
		t.Error("a message published before anybody listened was delivered, " +
			"which means something is buffering and the failure mode has changed")
	}
}

// The local bus does nothing, and blocks in Subscribe rather than returning.
//
// The second half matters: a Subscribe that returned immediately would have a
// single-replica deployment spinning through a reconnect loop with nothing to reconnect to.
func TestTheLocalBusDoesNothingAndWaits(t *testing.T) {
	var b Bus = Local{}
	if err := b.Publish(context.Background(), uuid.New()); err != nil {
		t.Errorf("Publish: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		b.Subscribe(ctx, func(uuid.UUID) { t.Error("the local bus delivered a message") })
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("Subscribe returned before its context was cancelled")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe did not return after its context was cancelled")
	}
}

// waitUntilListening publishes until the subscriber shows signs of life.
//
// LISTEN is asynchronous: Subscribe has to connect and issue it before anything sent will
// arrive, and a test that published once immediately would be racing that. Sending a
// throwaway id until one lands is how the test waits for readiness without reaching into
// the implementation.
func waitUntilListening(t *testing.T, ctx context.Context, publisher *Postgres, got *collector) {
	t.Helper()
	waitUntilListeningWith(t, ctx, publisher, got, uuid.New())
}

func waitUntilListeningWith(t *testing.T, ctx context.Context, publisher *Postgres, got *collector, probe uuid.UUID) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if err := publisher.Publish(ctx, probe); err != nil {
			t.Fatalf("publishing a readiness probe: %v", err)
		}
		select {
		case <-got.seen:
			return
		case <-time.After(100 * time.Millisecond):
		case <-deadline:
			t.Fatal("the subscriber never became ready")
		}
	}
}
