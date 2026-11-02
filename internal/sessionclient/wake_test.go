package sessionclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/peerset"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// sleepyClocks is the system's clocks with a lid that can be shut: sleeping moves the wall
// clock forward and leaves the monotonic one where it was, which is what a laptop's sleep does
// to a process on macOS and Linux.
type sleepyClocks struct{ slept atomic.Int64 }

func (s *sleepyClocks) clocks() clocks {
	sys := systemClocks()
	return clocks{
		wall:    func() time.Time { return sys.wall().Add(time.Duration(s.slept.Load())) },
		running: sys.running,
	}
}

func (s *sleepyClocks) sleep(d time.Duration) { s.slept.Add(int64(d)) }

// welcomingControl accepts every session it is offered and welcomes it, as a control plane
// does, so a test can watch a client come back and be shown as connected again.
type welcomingControl struct {
	srv      *httptest.Server
	sessions chan *websocket.Conn

	// refusing is how many more attempts to turn away before welcoming one, so a test can
	// give the client a backoff to carry.
	refusing atomic.Int32
}

func newWelcomingControl(t *testing.T) *welcomingControl {
	t.Helper()
	wc := &welcomingControl{sessions: make(chan *websocket.Conn, 8)}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/session/challenge", func(w http.ResponseWriter, _ *http.Request) {
		if wc.refusing.Add(-1) >= 0 {
			http.Error(w, "not now", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challenge": base64.StdEncoding.EncodeToString([]byte("a-challenge-to-sign")),
		})
	})
	mux.HandleFunc("/api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		data, _ := proto.Marshal(&meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_Hello{
			Hello: &meshpv1.ServerHello{SessionId: uuid.NewString(), CurrentStateVersion: 1},
		}})
		if conn.Write(context.Background(), websocket.MessageBinary, data) != nil {
			return
		}
		wc.sessions <- conn
		// Reading for as long as the session lasts is what lets a ping from this end see its
		// pong.
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	})
	wc.srv = httptest.NewServer(mux)
	t.Cleanup(wc.srv.Close)
	return wc
}

func (wc *welcomingControl) awaitSession(t *testing.T, what string) *websocket.Conn {
	t.Helper()
	select {
	case conn := <-wc.sessions:
		t.Cleanup(func() { _ = conn.CloseNow() })
		return conn
	case <-time.After(10 * time.Second):
		t.Fatalf("no session: %s", what)
		return nil
	}
}

// sleepyClient is a client that has not started, on clocks the test can put to sleep.
func sleepyClient(t *testing.T, wc *welcomingControl) (*Client, *sleepyClocks) {
	t.Helper()
	identity, err := keys.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client := New(Options{ControlURL: wc.srv.URL, Identity: identity, MembershipID: uuid.New()})
	sleepy := &sleepyClocks{}
	client.clk = sleepy.clocks()
	return client, sleepy
}

func awaitConnected(t *testing.T, client *Client, what string, ok func(since time.Time) bool) time.Time {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if up, since := client.Connected(); up && ok(since) {
			return since
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never reported connected: %s", what)
	return time.Time{}
}

func shortenWakeChecks(t *testing.T, to time.Duration) {
	original := wakeCheckInterval
	wakeCheckInterval = to
	t.Cleanup(func() { wakeCheckInterval = original })
}

// The other half of check 5, and the ninety seconds after waking in which `meshp status` showed
// a session the control plane had already ended. The read deadline that should have noticed
// slept through the sleep along with everything else measured on the monotonic clock; the wall
// clock did not, and the difference is the whole signal.
func TestASessionThatSpannedASleepIsReplaced(t *testing.T) {
	shortenWakeChecks(t, 20*time.Millisecond)
	wc := newWelcomingControl(t)
	client, sleepy := sleepyClient(t, wc)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx, &recordingApplier{}) }()
	defer func() {
		cancel()
		<-done
	}()

	wc.awaitSession(t, "before the sleep")
	before := awaitConnected(t, client, "before the sleep", func(time.Time) bool { return true })

	// The lid shuts for as long as it did on 2026-08-31, and opens again.
	sleepy.sleep(9*time.Minute + 35*time.Second)

	// Status stops showing the old session within a check or two, not once a deadline that
	// slept with everything else expires.
	deadline := time.Now().Add(time.Second)
	for {
		up, since := client.Connected()
		if !up || !since.Equal(before) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("status went on reporting the session from before the sleep")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// And a new one replaces it, promptly.
	wc.awaitSession(t, "after the sleep: the client did not reconnect")
	awaitConnected(t, client, "after the sleep", func(since time.Time) bool { return since.After(before) })
}

// A pong is this device vouching that its session is live. One that has just been thawed —
// for a moment, perhaps, in a dark wake with the lid still shut — cannot, and answering the
// control plane's probe would keep a session open across exactly the sleep the probe exists to
// notice. The wake check is held off here, so the ping is the only thing that can notice.
func TestAPingAfterASleepIsNotAnswered(t *testing.T) {
	shortenWakeChecks(t, time.Hour)
	wc := newWelcomingControl(t)
	client, sleepy := sleepyClient(t, wc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.RunOnce(ctx, &recordingApplier{}) }()
	conn := wc.awaitSession(t, "the session never opened")

	ping := func() error {
		pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return conn.Ping(pingCtx)
	}
	if err := ping(); err != nil {
		t.Fatalf("an awake agent did not answer: %v", err)
	}

	sleepy.sleep(time.Minute)
	if ping() == nil {
		t.Fatal("the agent answered a probe for a session that spanned a sleep")
	}

	select {
	case err := <-done:
		if !errors.Is(err, errSlept) {
			t.Errorf("the session ended with %v, want it to say the machine slept", err)
		}
		if !strings.Contains(err.Error(), "1m0s") {
			t.Errorf("%q does not say how long the machine slept", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not end after the agent declined to vouch for it")
	}
	if up, _ := client.Connected(); up {
		t.Error("still reported connected after declining to vouch for the session")
	}
}

// A wake is not an outage, so it does not inherit one's backoff. Run measures a session's health
// by how long it lasted, on the monotonic clock, and that clock does not count the sleep — so a
// laptop that had to retry a few times before the lid shut would otherwise wait out a backoff
// it earned before it slept, after opening it.
func TestAWakeDoesNotWaitOutAnEarlierBackoff(t *testing.T) {
	shortenWakeChecks(t, 20*time.Millisecond)
	wc := newWelcomingControl(t)
	// Three refusals leave the next wait drawn from two to six seconds.
	wc.refusing.Store(3)
	client, sleepy := sleepyClient(t, wc)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx, &recordingApplier{}) }()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case conn := <-wc.sessions:
		t.Cleanup(func() { _ = conn.CloseNow() })
	case <-time.After(15 * time.Second):
		t.Fatal("never connected after the refusals")
	}
	awaitConnected(t, client, "before the sleep", func(time.Time) bool { return true })

	sleepy.sleep(time.Hour)
	woke := time.Now()
	wc.awaitSession(t, "after the sleep")
	if took := time.Since(woke); took > 1500*time.Millisecond {
		t.Errorf("took %s to come back after waking; the backoff from before the sleep was carried over",
			took.Round(time.Millisecond))
	}
}

// Status is corrected the moment the sleep is noticed, not when the session finishes ending.
// The two are usually a moment apart; they are not when the read loop is busy applying state,
// which it does without looking up — and is also what a freshly woken agent may well be doing.
func TestStatusDropsTheOldSessionWithoutWaitingForTheReadLoop(t *testing.T) {
	shortenWakeChecks(t, 20*time.Millisecond)
	wc := newWelcomingControl(t)
	client, sleepy := sleepyClient(t, wc)

	applying := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	applier := applierFunc(func() {
		close(applying)
		<-release
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.RunOnce(ctx, applier) }()

	conn := wc.awaitSession(t, "the session never opened")
	awaitConnected(t, client, "before the sleep", func(time.Time) bool { return true })

	data, _ := proto.Marshal(&meshpv1.ServerMessage{Payload: &meshpv1.ServerMessage_StateDelta{
		StateDelta: &meshpv1.StateDelta{FromVersion: 0, ToVersion: 1},
	}})
	if err := conn.Write(context.Background(), websocket.MessageBinary, data); err != nil {
		t.Fatal(err)
	}
	select {
	case <-applying:
	case <-time.After(5 * time.Second):
		t.Fatal("the state was never applied")
	}

	sleepy.sleep(time.Hour)
	deadline := time.Now().Add(time.Second)
	for up, _ := client.Connected(); up; up, _ = client.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("status showed the session from before the sleep for as long as the apply ran")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// applierFunc blocks however the test says, once.
type applierFunc func()

func (f applierFunc) Apply(context.Context, *peerset.Set) ([]string, error) {
	f()
	return nil, nil
}

// The threshold exists so that a process the scheduler was slow to run is not mistaken for a
// laptop that slept. A reconnection costs little; a client that made one on every hiccup would
// cost a control plane a snapshot per device per hiccup.
func TestABriefPauseKeepsTheSession(t *testing.T) {
	shortenWakeChecks(t, 20*time.Millisecond)
	wc := newWelcomingControl(t)
	client, sleepy := sleepyClient(t, wc)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx, &recordingApplier{}) }()
	defer func() {
		cancel()
		<-done
	}()

	conn := wc.awaitSession(t, "the session never opened")
	before := awaitConnected(t, client, "before the pause", func(time.Time) bool { return true })

	sleepy.sleep(suspendThreshold / 2)
	time.Sleep(20 * wakeCheckInterval)

	pingCtx, cancelPing := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelPing()
	if err := conn.Ping(pingCtx); err != nil {
		t.Fatalf("the session did not survive a pause shorter than the threshold: %v", err)
	}
	if up, since := client.Connected(); !up || !since.Equal(before) {
		t.Error("a pause shorter than the threshold replaced the session")
	}
	select {
	case <-wc.sessions:
		t.Error("the client reconnected after a pause shorter than the threshold")
	default:
	}
}

// The wall clock has to be read without its monotonic reading, or subtracting two of them
// subtracts monotonically and the two clocks can never disagree. Nothing else would catch that:
// every other test here supplies its own wall clock, and a running machine never sleeps under
// test.
func TestTheSystemWallClockIsNotMonotonic(t *testing.T) {
	sys := systemClocks()
	if s := sys.wall().String(); strings.Contains(s, " m=") {
		t.Fatalf("the wall clock carries a monotonic reading (%s), so it cannot see a sleep", s)
	}

	watch := newSuspendWatch(sys)
	time.Sleep(20 * time.Millisecond)
	if gap := watch.frozen(); gap > time.Second || gap < -time.Second {
		t.Errorf("a process that never stopped measured %s frozen", gap)
	}
}
