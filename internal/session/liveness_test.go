package session

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// The probe, shortened so a test can watch several rounds of it. The ratio is the production
// one's (15s and 30s), so an answer is never due before the next question would be asked.
const (
	testLivenessInterval = 200 * time.Millisecond
	testLivenessTimeout  = 400 * time.Millisecond
	testLivenessBound    = testLivenessInterval + testLivenessTimeout

	// boundSlack is what scheduling is allowed on top of the bound: a goroutine waking late,
	// the database clearing the row. Less than one timeout, so a server that waited for a
	// second unanswered probe before giving up would overrun it and fail.
	boundSlack = 300 * time.Millisecond
)

func withLiveness(interval, timeout time.Duration) func(*Config) {
	return func(c *Config) {
		c.LivenessInterval = interval
		c.LivenessTimeout = timeout
	}
}

// The failure from docs/testing/macos-laptop.md, check 5, reduced to what the server can see.
//
// The connection stays open throughout, as a sleeping laptop's kernel keeps it, and the agent
// goes on writing heartbeats, as its ticker does in the brief wakes macOS gives it with the lid
// shut. What it stops doing is reading, which is what a frozen process stops doing first and
// for longest. Under the read deadline alone those heartbeats held the session open
// indefinitely — nine and a half minutes on the laptop, and for as long as this test would
// wait. The bound holds only if the server measures liveness itself.
func TestAnAgentThatStopsAnsweringIsDroppedWithinTheBound(t *testing.T) {
	f := newFixture(t, withLiveness(testLivenessInterval, testLivenessTimeout))
	alice := f.enrolDevice("alice")

	conn := f.openRawSession(alice)
	defer func() { _ = conn.CloseNow() }()

	heartbeating, stopHeartbeats := context.WithCancel(f.ctx)
	defer stopHeartbeats()
	go func() {
		for {
			select {
			case <-heartbeating.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			if writeRaw(conn, &meshpv1.ClientMessage{
				Payload: &meshpv1.ClientMessage_Heartbeat{Heartbeat: &meshpv1.Heartbeat{}},
			}) != nil {
				return
			}
		}
	}()

	// Reading is what answers a ping, inside the library's Read. It stops between messages,
	// and the heartbeat acknowledgements arriving every fifty milliseconds are what make sure
	// there is a between.
	var answering atomic.Bool
	answering.Store(true)
	stopped := make(chan time.Time, 1)
	go func() {
		for answering.Load() {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
		stopped <- time.Now()
	}()

	// While it answers, it is held — through several rounds of probing, not one.
	time.Sleep(4 * testLivenessBound)
	if !f.reportsConnected(alice) {
		t.Fatal("a session that was answering every probe was dropped")
	}

	answering.Store(false)
	var since time.Time
	select {
	case since = <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never stopped reading; the test cannot say anything")
	}

	deadline := since.Add(testLivenessBound + boundSlack)
	for f.reportsConnected(alice) {
		if time.Now().After(deadline) {
			t.Fatalf("still connected %s after the agent stopped answering, with heartbeats still arriving; the bound is %s",
				time.Since(since).Round(time.Millisecond), testLivenessBound)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("dropped %s after the agent stopped answering; the bound is %s",
		time.Since(since).Round(time.Millisecond), testLivenessBound)
}

// Every agent deployed before this answers the probe without knowing it exists — its websocket
// library does — and this agent is that code with nothing added to how it reads. Held for many
// bounds with the same session throughout: a probe that a working agent fails would show as a
// reconnect here rather than a drop, which is why the session id is compared and not merely
// the count.
func TestAWorkingAgentIsNotDroppedByTheProbe(t *testing.T) {
	f := newFixture(t, withLiveness(testLivenessInterval, testLivenessTimeout))
	alice := f.enrolDevice("alice")

	applier, cancel := f.connect(alice, 0)
	defer cancel()
	select {
	case <-applier.applied:
	case <-time.After(15 * time.Second):
		t.Fatal("no state was delivered")
	}
	waitFor(t, "the session to register", func() bool { return f.hub.Count() == 1 })
	first, _ := f.hub.Get(alice.membershipID)

	time.Sleep(6 * testLivenessBound)

	now, ok := f.hub.Get(alice.membershipID)
	if !ok {
		t.Fatal("a working agent was dropped by the liveness probe")
	}
	if now.ID != first.ID {
		t.Fatal("a working agent's session was replaced: it was dropped and reconnected")
	}
	if !f.reportsConnected(alice) {
		t.Error("the database stopped recording a working agent as connected")
	}
}

// reportsConnected is what the overview's "connected" is made of: this replica holding the
// session, or the database saying some replica does.
func (f *fixture) reportsConnected(d device) bool {
	f.t.Helper()
	if _, live := f.hub.Get(d.membershipID); live {
		return true
	}
	var recorded bool
	if err := f.store.Pool().QueryRow(f.ctx,
		`SELECT connected_since IS NOT NULL FROM membership_state WHERE membership_id = $1`,
		d.membershipID).Scan(&recorded); err != nil {
		f.t.Fatalf("reading membership_state: %v", err)
	}
	return recorded
}

// openRawSession completes a real handshake by hand and returns the connection after the
// server's hello, so a test decides exactly when the agent reads and writes.
func (f *fixture) openRawSession(d device) *websocket.Conn {
	f.t.Helper()
	ch, err := f.srv.IssueChallenge(d.identity.Public, d.membershipID)
	if err != nil {
		f.t.Fatal(err)
	}

	dialCtx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(dialCtx, strings.Replace(f.http.URL, "http://", "ws://", 1)+"/api/v1/session", nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		f.t.Fatalf("dialling: %v", err)
	}
	conn.SetReadLimit(maxMessageBytes)

	if err := writeRaw(conn, &meshpv1.ClientMessage{Payload: &meshpv1.ClientMessage_Hello{Hello: &meshpv1.ClientHello{
		IdentityPublicKey:  d.identity.Public,
		Challenge:          ch.Bytes,
		ChallengeSignature: d.identity.Sign(ch.Bytes),
		MembershipId:       d.membershipID.String(),
		AgentVersion:       "raw-test",
	}}}); err != nil {
		f.t.Fatalf("sending hello: %v", err)
	}

	// Until the hello, which is not always first: run enqueues it and nudges for the snapshot
	// in the same breath, and its select takes whichever of the two it likes.
	readCtx, cancelRead := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancelRead()
	for {
		msg, err := readClientSide(readCtx, conn)
		if err != nil {
			f.t.Fatalf("waiting for the server's hello: %v", err)
		}
		if msg.GetHello() != nil {
			break
		}
	}
	waitFor(f.t, "the session to be recorded", func() bool { return f.reportsConnected(d) })
	return conn
}

func writeRaw(conn *websocket.Conn, msg *meshpv1.ClientMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return conn.Write(ctx, websocket.MessageBinary, data)
}

func readClientSide(ctx context.Context, conn *websocket.Conn) (*meshpv1.ServerMessage, error) {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	var msg meshpv1.ServerMessage
	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}
