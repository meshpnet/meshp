package sessionclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/peerset"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// fakeControl is enough of a control plane to hold one session.
//
// A real WebSocket rather than a hand-rolled seam, because what is being tested is when
// the client sends a message and what it does with the reply — and a seam that let the
// test call handleRelayToken directly would prove nothing about whether anything calls it.
type fakeControl struct {
	t   *testing.T
	srv *httptest.Server

	// received collects everything the client sent.
	mu       sync.Mutex
	received []*meshpv1.ClientMessage

	// conn is handed to the test once a session is up, so it can push messages.
	conn    chan *websocket.Conn
	oneConn sync.Once
}

func newFakeControl(t *testing.T) *fakeControl {
	t.Helper()
	fc := &fakeControl{t: t, conn: make(chan *websocket.Conn, 1)}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/session/challenge", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challenge": base64.StdEncoding.EncodeToString([]byte("a-challenge-to-sign")),
		})
	})
	mux.HandleFunc("/api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		fc.oneConn.Do(func() { fc.conn <- conn })
		fc.read(conn)
	})

	fc.srv = httptest.NewServer(mux)
	t.Cleanup(fc.srv.Close)
	return fc
}

// read drains the client's messages for as long as the session lasts.
func (fc *fakeControl) read(conn *websocket.Conn) {
	for {
		typ, data, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		var msg meshpv1.ClientMessage
		if proto.Unmarshal(data, &msg) != nil {
			continue
		}
		fc.mu.Lock()
		fc.received = append(fc.received, &msg)
		fc.mu.Unlock()
	}
}

func (fc *fakeControl) send(conn *websocket.Conn, msg *meshpv1.ServerMessage) {
	fc.t.Helper()
	data, err := proto.Marshal(msg)
	if err != nil {
		fc.t.Fatalf("marshalling: %v", err)
	}
	if err := conn.Write(context.Background(), websocket.MessageBinary, data); err != nil {
		fc.t.Fatalf("writing to the agent: %v", err)
	}
}

// awaitRelayTokenRequest waits for the client to ask, and reports whether it did.
func (fc *fakeControl) awaitRelayTokenRequest(within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		fc.mu.Lock()
		for _, msg := range fc.received {
			if _, ok := msg.Payload.(*meshpv1.ClientMessage_RelayTokenRequest); ok {
				fc.mu.Unlock()
				return true
			}
		}
		fc.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func (fc *fakeControl) relayTokenRequests() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	n := 0
	for _, msg := range fc.received {
		if _, ok := msg.Payload.(*meshpv1.ClientMessage_RelayTokenRequest); ok {
			n++
		}
	}
	return n
}

// recordingSink is a RelayCredentials that remembers what it was told.
type recordingSink struct {
	mu       sync.Mutex
	needs    bool
	token    []byte
	expires  time.Time
	refusals []string
}

func (s *recordingSink) NeedsToken() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.needs
}

func (s *recordingSink) SetToken(token []byte, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	s.expires = expiresAt
	s.needs = false
}

func (s *recordingSink) TokenRefused(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusals = append(s.refusals, reason)
	s.needs = false
}

func (s *recordingSink) held() ([]byte, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, s.expires
}

func (s *recordingSink) refusalsSeen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refusals...)
}

type noopApplier struct{}

func (noopApplier) Apply(context.Context, *peerset.Set) ([]string, error) { return nil, nil }

// start runs one session against fc and returns the connection the server holds.
func start(t *testing.T, fc *fakeControl, sink RelayCredentials) *websocket.Conn {
	t.Helper()

	identity, err := keys.NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	client := New(Options{
		ControlURL:   fc.srv.URL,
		Identity:     identity,
		MembershipID: uuid.New(),
		Relay:        sink,
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = client.RunOnce(ctx, noopApplier{}) }()

	select {
	case conn := <-fc.conn:
		t.Cleanup(func() { _ = conn.CloseNow() })
		return conn
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never opened a session")
		return nil
	}
}

func stateWithRelay() *meshpv1.ServerMessage {
	return &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{
			FromVersion: 0,
			ToVersion:   1,
			Relays: &meshpv1.RelayConfig{Relays: []*meshpv1.RelayConfig_Relay{
				{Id: "relay1", Endpoints: []string{"relay1.example:3478"}},
			}},
		},
	}}
}

// The agent asks; the server does not push (ADR-0017). Desired state naming a relay is
// what starts the exchange.
func TestAsksForARelayTokenOnceStateNamesARelay(t *testing.T) {
	fc := newFakeControl(t)
	sink := &recordingSink{needs: true}
	conn := start(t, fc, sink)

	fc.send(conn, stateWithRelay())

	if !fc.awaitRelayTokenRequest(5 * time.Second) {
		t.Fatal("the agent never asked for a relay token")
	}
}

// Asking before a relay is known would get a refusal from a deployment that has simply not
// sent its relays yet, and teach the agent to stop asking.
func TestDoesNotAskBeforeARelayIsKnown(t *testing.T) {
	fc := newFakeControl(t)
	sink := &recordingSink{needs: true}
	conn := start(t, fc, sink)

	// State, but no relays in it.
	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{FromVersion: 0, ToVersion: 1},
	}})

	if fc.awaitRelayTokenRequest(300 * time.Millisecond) {
		t.Fatal("the agent asked for a relay token with no relay to use it on")
	}
}

// A build with no data plane has nowhere to present a token, and minting one for it is
// work the control plane does for nothing.
func TestDoesNotAskWithNoCredentialSink(t *testing.T) {
	fc := newFakeControl(t)
	conn := start(t, fc, nil)

	fc.send(conn, stateWithRelay())

	if fc.awaitRelayTokenRequest(300 * time.Millisecond) {
		t.Fatal("an agent with no relay asked for a token")
	}
}

// The whole point of asking: what comes back has to reach the thing that dials.
func TestIssuedTokenReachesTheSink(t *testing.T) {
	fc := newFakeControl(t)
	sink := &recordingSink{needs: true}
	conn := start(t, fc, sink)

	fc.send(conn, stateWithRelay())
	if !fc.awaitRelayTokenRequest(5 * time.Second) {
		t.Fatal("the agent never asked")
	}

	expires := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_RelayToken{
		RelayToken: &meshpv1.RelayToken{Token: []byte("a-signed-capability"), ExpiresAtUnix: expires.Unix()},
	}})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if token, at := sink.held(); len(token) > 0 {
			if string(token) != "a-signed-capability" {
				t.Fatalf("token = %q", token)
			}
			if !at.Equal(expires) {
				t.Errorf("expiry = %v, want %v", at, expires)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the issued token never reached the sink")
}

// A refusal is a fact the sink needs, so it can stop asking. Dropping it would leave the
// agent retrying a deployment that has told it not to.
func TestRefusalReachesTheSink(t *testing.T) {
	fc := newFakeControl(t)
	sink := &recordingSink{needs: true}
	conn := start(t, fc, sink)

	fc.send(conn, stateWithRelay())
	if !fc.awaitRelayTokenRequest(5 * time.Second) {
		t.Fatal("the agent never asked")
	}
	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_RelayToken{
		RelayToken: &meshpv1.RelayToken{Error: "relaying is not available"},
	}})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if seen := sink.refusalsSeen(); len(seen) > 0 {
			if seen[0] != "relaying is not available" {
				t.Errorf("reason = %q", seen[0])
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the refusal never reached the sink")
}

// An empty token with no error set is a broken server, not a usable credential. Handing it
// on would have the agent dial a relay with nothing to present and read the rejection as a
// network problem.
func TestEmptyTokenIsTreatedAsARefusal(t *testing.T) {
	fc := newFakeControl(t)
	sink := &recordingSink{needs: true}
	conn := start(t, fc, sink)

	fc.send(conn, stateWithRelay())
	if !fc.awaitRelayTokenRequest(5 * time.Second) {
		t.Fatal("the agent never asked")
	}
	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_RelayToken{
		RelayToken: &meshpv1.RelayToken{},
	}})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(sink.refusalsSeen()) > 0 {
			if token, _ := sink.held(); len(token) > 0 {
				t.Fatal("an empty token was handed on as a credential")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("an empty token was neither used nor refused")
}

// The sink is asked every time rather than once. A sink holding a good token says no, and
// an agent that ignored it would ask on every state change for the life of the session.
func TestDoesNotAskWhileTheSinkIsSatisfied(t *testing.T) {
	fc := newFakeControl(t)
	sink := &recordingSink{needs: false}
	conn := start(t, fc, sink)

	fc.send(conn, stateWithRelay())
	fc.send(conn, stateWithRelay())

	if fc.awaitRelayTokenRequest(300 * time.Millisecond) {
		t.Fatalf("asked %d times while already holding a token", fc.relayTokenRequests())
	}
}

// ---------------------------------------------------------------------------
// State handling

// recordingApplier keeps what it was handed, and can be made to fail.
type recordingApplier struct {
	mu      sync.Mutex
	applied []*peerset.Set
	err     error
}

func (a *recordingApplier) Apply(_ context.Context, s *peerset.Set) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.applied = append(a.applied, s)
	if a.err != nil {
		return []string{"peers"}, a.err
	}
	return nil, nil
}

func (a *recordingApplier) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.applied)
}

// startWith is start, with an applier of the caller's choosing.
func startWith(t *testing.T, fc *fakeControl, applier Applier) (*Client, *websocket.Conn) {
	t.Helper()

	identity, err := keys.NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	client := New(Options{
		ControlURL:   fc.srv.URL,
		Identity:     identity,
		MembershipID: uuid.New(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = client.RunOnce(ctx, applier) }()

	select {
	case conn := <-fc.conn:
		t.Cleanup(func() { _ = conn.CloseNow() })
		return client, conn
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never opened a session")
		return nil, nil
	}
}

func (fc *fakeControl) awaitAck(t *testing.T, within time.Duration) *meshpv1.StateAck {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		fc.mu.Lock()
		for i := len(fc.received) - 1; i >= 0; i-- {
			if ack, ok := fc.received[i].Payload.(*meshpv1.ClientMessage_StateAck); ok {
				fc.mu.Unlock()
				return ack.StateAck
			}
		}
		fc.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no state acknowledgement arrived")
	return nil
}

// A delta whose from_version is not what this agent holds would produce a peer set matching
// neither version while claiming to be the newer one — drift nothing downstream can detect,
// because the version numbers would agree.
func TestADeltaAgainstTheWrongVersionIsRefused(t *testing.T) {
	fc := newFakeControl(t)
	applier := &recordingApplier{}
	client, conn := startWith(t, fc, applier)

	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{FromVersion: 0, ToVersion: 4},
	}})
	if ack := fc.awaitAck(t, 5*time.Second); ack.GetAppliedVersion() != 4 {
		t.Fatalf("applied version = %d, want 4", ack.GetAppliedVersion())
	}

	// Now a delta computed against a version this agent never held.
	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{FromVersion: 9, ToVersion: 10},
	}})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ack := fc.awaitAck(t, time.Second); ack.GetError() != "" {
			if ack.GetAppliedVersion() != 4 {
				t.Errorf("refused a delta but reported version %d, want the one still in force (4)",
					ack.GetAppliedVersion())
			}
			if client.AppliedVersion() != 4 {
				t.Errorf("the client moved to %d despite refusing the delta", client.AppliedVersion())
			}
			if applier.count() != 1 {
				t.Errorf("the applier was called %d times; the refused delta reached it", applier.count())
			}
			return
		}
	}
	t.Fatal("a delta against the wrong version was accepted")
}

// Claiming a version we failed to reach would make the one metric that shows a broken agent
// show a healthy one.
func TestAFailedApplyRollsTheVersionBack(t *testing.T) {
	fc := newFakeControl(t)
	applier := &recordingApplier{err: errors.New("the kernel refused")}
	client, conn := startWith(t, fc, applier)

	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{FromVersion: 0, ToVersion: 7},
	}})

	ack := fc.awaitAck(t, 5*time.Second)
	if ack.GetError() == "" {
		t.Fatal("a failed apply was acknowledged as success")
	}
	if ack.GetAppliedVersion() != 0 {
		t.Errorf("acknowledged version %d after failing to apply it", ack.GetAppliedVersion())
	}
	if client.AppliedVersion() != 0 {
		t.Errorf("the client holds version %d after a failed apply", client.AppliedVersion())
	}
}

// Peers folded from desired state are what the agent reports holding.
func TestPeerCountReflectsFoldedState(t *testing.T) {
	fc := newFakeControl(t)
	client, conn := startWith(t, fc, &recordingApplier{})

	fc.send(conn, &meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{FromVersion: 0, ToVersion: 1, UpsertPeers: []*meshpv1.Peer{
			{PublicKey: "one", AllowedIps: []string{"100.90.0.2/32"}},
			{PublicKey: "two", AllowedIps: []string{"100.90.0.3/32"}},
		}},
	}})
	fc.awaitAck(t, 5*time.Second)

	if got := client.PeerCount(); got != 2 {
		t.Errorf("PeerCount = %d, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// Supervision

// Losing the control plane must not be terminal: Run reconnects rather than returning, or a
// restarted control plane would need every agent restarted too.
func TestRunReconnectsAfterASessionDrops(t *testing.T) {
	fc := newFakeControl(t)

	// A fresh connection channel per accept, so the test can count sessions.
	sessions := make(chan struct{}, 4)
	fc.oneConn = sync.Once{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/session/challenge", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challenge": base64.StdEncoding.EncodeToString([]byte("challenge")),
		})
	})
	mux.HandleFunc("/api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		select {
		case sessions <- struct{}{}:
		default:
		}
		// Read one message, then drop the session on the floor.
		_, _, _ = conn.Read(context.Background())
		_ = conn.CloseNow()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	identity, err := keys.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client := New(Options{ControlURL: srv.URL, Identity: identity, MembershipID: uuid.New()})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx, &recordingApplier{}) }()

	// Two sessions means it came back after the first was dropped.
	for i := range 2 {
		select {
		case <-sessions:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d session(s) were established; Run did not reconnect", i)
		}
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run did not return when its context ended")
	}
}

// An invalid control URL is rejected once, at construction, rather than on every dial.
func TestARejectedControlURLFailsEveryRun(t *testing.T) {
	identity, err := keys.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client := New(Options{ControlURL: "not a url", Identity: identity, MembershipID: uuid.New()})
	if err := client.RunOnce(context.Background(), &recordingApplier{}); err == nil {
		t.Error("an unusable control URL was accepted")
	}
}

func TestWebSocketURLDerivation(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://example.test:8080", "ws://example.test:8080"},
		{"https://example.test", "wss://example.test"},
		{"ws://already", "ws://already"},
	} {
		if got := toWebSocketURL(tc.in); got != tc.want {
			t.Errorf("toWebSocketURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Jitter spreads reconnections out. Without it an outage ends with every agent in a fleet
// reconnecting in the same instant, knocking the control plane over as it comes back.
func TestJitterStaysWithinItsInterval(t *testing.T) {
	if got := jitter(0); got != 0 {
		t.Errorf("jitter(0) = %v, want 0", got)
	}
	const d = time.Second
	spread := map[time.Duration]bool{}
	for range 200 {
		got := jitter(d)
		if got < d/2 || got >= d+d/2 {
			t.Fatalf("jitter(%v) = %v, outside [%v, %v)", d, got, d/2, d+d/2)
		}
		spread[got] = true
	}
	if len(spread) < 50 {
		t.Errorf("only %d distinct delays in 200 draws; a fleet would still reconnect together",
			len(spread))
	}
}
