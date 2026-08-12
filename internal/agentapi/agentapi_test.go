package agentapi

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeHandler stands in for the daemon.
type fakeHandler struct {
	mu       sync.Mutex
	status   Status
	joinResp JoinResponse
	joinErr  error
	joined   []JoinRequest
}

func (h *fakeHandler) Status(context.Context) (Status, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status, nil
}

func (h *fakeHandler) Join(_ context.Context, req JoinRequest) (JoinResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.joined = append(h.joined, req)
	return h.joinResp, h.joinErr
}

func (h *fakeHandler) joinCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.joined)
}

// socketPath keeps the path short. A unix socket path has a hard limit around 100
// bytes, and t.TempDir() under a long temporary root can exceed it — which fails with
// "invalid argument" and no hint about why.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mpsk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}

func serve(t *testing.T, h Handler, cfg ServerConfig) (*Server, string) {
	t.Helper()
	if cfg.SocketPath == "" {
		cfg.SocketPath = socketPath(t)
	}
	srv := NewServer(h, cfg)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after the context was cancelled")
		}
	})
	return srv, cfg.SocketPath
}

func TestStatusRoundTrip(t *testing.T) {
	membershipID, networkID := uuid.New(), uuid.New()
	h := &fakeHandler{status: Status{
		Version:           "test",
		StartedAt:         time.Now().UTC().Truncate(time.Second),
		Enrolled:          true,
		IdentityPublicKey: "aWRlbnRpdHk=",
		Memberships: []MembershipStatus{{
			MembershipID:        membershipID,
			NetworkID:           networkID,
			ControlURL:          "http://control.test",
			InterfaceName:       "meshp0",
			AddressV4:           "100.90.0.7",
			WireGuardPublicKey:  "d2c=",
			Connected:           true,
			AppliedStateVersion: 42,
		}},
	}}
	_, path := serve(t, h, ServerConfig{})

	got, err := NewClient(path, 5*time.Second).Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !got.Enrolled || len(got.Memberships) != 1 {
		t.Fatalf("status = %+v", got)
	}
	m := got.Memberships[0]
	if m.MembershipID != membershipID || m.NetworkID != networkID {
		t.Errorf("identifiers did not survive: %+v", m)
	}
	if !m.Connected || m.AppliedStateVersion != 42 {
		t.Errorf("live fields did not survive: connected=%v applied=%d", m.Connected, m.AppliedStateVersion)
	}
	// A membership with an address is not a working tunnel, and status must not imply
	// otherwise.
	if m.TunnelUp {
		t.Error("TunnelUp is true in a build with no WireGuard")
	}
}

func TestJoinRoundTrip(t *testing.T) {
	h := &fakeHandler{joinResp: JoinResponse{
		MembershipID:  uuid.New(),
		NetworkID:     uuid.New(),
		InterfaceName: "meshp0",
		AddressV4:     "100.90.0.1",
	}}
	_, path := serve(t, h, ServerConfig{})

	res, err := NewClient(path, 5*time.Second).Join(context.Background(), JoinRequest{
		Token: "meshp_tok_example", ControlURL: "http://control.test", Name: "laptop",
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if res.InterfaceName != "meshp0" || res.AddressV4 != "100.90.0.1" {
		t.Errorf("response = %+v", res)
	}
	if h.joinCount() != 1 {
		t.Fatalf("handler saw %d joins, want 1", h.joinCount())
	}
	if got := h.joined[0].Token; got != "meshp_tok_example" {
		t.Errorf("token reached the handler as %q", got)
	}
}

func TestJoinRefusalReachesTheCaller(t *testing.T) {
	h := &fakeHandler{joinErr: errors.New("that enrolment token has already been used")}
	_, path := serve(t, h, ServerConfig{})

	_, err := NewClient(path, 5*time.Second).Join(context.Background(), JoinRequest{
		Token: "meshp_tok_used", ControlURL: "http://control.test",
	})
	if err == nil {
		t.Fatal("a refused join reported success")
	}
	// The control plane's wording has to survive both hops, or the person at the
	// terminal is told "bad gateway" about an expired token.
	if !strings.Contains(err.Error(), "already been used") {
		t.Errorf("error lost its meaning on the way back: %v", err)
	}
}

func TestJoinRejectsAnEmptyToken(t *testing.T) {
	h := &fakeHandler{}
	_, path := serve(t, h, ServerConfig{})

	_, err := NewClient(path, 5*time.Second).Join(context.Background(), JoinRequest{ControlURL: "http://x"})
	if err == nil {
		t.Fatal("an empty token was accepted")
	}
	if h.joinCount() != 0 {
		t.Error("an empty token reached the handler")
	}
}

func TestJoinRejectsUnknownFields(t *testing.T) {
	h := &fakeHandler{}
	_, path := serve(t, h, ServerConfig{})

	// Reaching past the client, because the point is what the server accepts.
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	body := `{"token":"meshp_tok_x","control_url":"http://x","typo_field":1}`
	req := "POST /v1/join HTTP/1.1\r\nHost: meshpd\r\nContent-Type: application/json\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "400") {
		t.Errorf("an unknown field was not refused: %s", buf[:n])
	}
	if h.joinCount() != 0 {
		t.Error("a request with an unknown field reached the handler")
	}
}

// The socket is a privilege boundary: anything that can reach it can enrol this device
// and, once tunnels exist, decide where its traffic goes.
func TestSocketIsOwnerOnlyByDefault(t *testing.T) {
	_, path := serve(t, &fakeHandler{}, ServerConfig{})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("socket is %04o, want 0600", perm)
	}
	if perm&0o077 != 0 {
		t.Error("the socket is reachable by users other than its owner")
	}
}

func TestListenRefusesAnUnknownGroup(t *testing.T) {
	srv := NewServer(&fakeHandler{}, ServerConfig{
		SocketPath: socketPath(t),
		Group:      "a-group-that-does-not-exist-anywhere",
	})
	err := srv.Listen()
	if err == nil {
		t.Fatal("Listen accepted a group that does not exist")
	}
	// And it must not have left a socket behind at looser permissions than intended.
	if _, statErr := os.Stat(srv.SocketPath()); !errors.Is(statErr, fs.ErrNotExist) {
		t.Error("a failed Listen left a socket behind")
	}
}

// But it must never steal the socket from a daemon that is alive, or two processes end
// up fighting over one state directory and one set of keys.
func TestListenRefusesToStealALiveSocket(t *testing.T) {
	_, path := serve(t, &fakeHandler{}, ServerConfig{})

	second := NewServer(&fakeHandler{}, ServerConfig{SocketPath: path})
	err := second.Listen()
	if err == nil {
		t.Fatal("a second daemon took over a live socket")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("error does not explain the conflict: %v", err)
	}

	// The first is still serving.
	if _, err := NewClient(path, 5*time.Second).Status(context.Background()); err != nil {
		t.Errorf("the original daemon stopped answering: %v", err)
	}
}

func TestListenRefusesANonSocketFile(t *testing.T) {
	path := socketPath(t)
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := NewServer(&fakeHandler{}, ServerConfig{SocketPath: path}).Listen()
	if err == nil {
		t.Fatal("Listen replaced a regular file")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("error does not say what is wrong: %v", err)
	}
}

// "connection refused" is not an answer anyone can act on, so the client names the
// cases separately.
func TestClientDistinguishesNoDaemon(t *testing.T) {
	_, err := NewClient("/tmp/meshp-nothing-here-at-all.sock", time.Second).Status(context.Background())
	if !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("error = %v, want ErrNoDaemon", err)
	}
	if !strings.Contains(err.Error(), "meshp-nothing-here-at-all.sock") {
		t.Errorf("error does not name the socket: %v", err)
	}
}

func TestServeCleansUpTheSocket(t *testing.T) {
	path := socketPath(t)
	srv := NewServer(&fakeHandler{}, ServerConfig{SocketPath: path})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx) }()

	// Wait until it is answering.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := NewClient(path, time.Second).Status(ctx); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}

	// Left behind, the next start would log a stale-socket warning for no reason.
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the socket outlived the server: %v", err)
	}
}

// No private key material has any business crossing this socket (Invariant 1). The types
// are the enforcement; this is the assertion that they stay that way.
func TestNoPrivateKeyFieldsAreExposed(t *testing.T) {
	forbidden := []string{"private", "secret", "PrivateKey"}
	for _, sample := range []any{Status{}, MembershipStatus{}, JoinRequest{}, JoinResponse{}} {
		rendered := structFieldNames(sample)
		for _, word := range forbidden {
			if strings.Contains(strings.ToLower(rendered), strings.ToLower(word)) {
				t.Errorf("%T exposes a field mentioning %q: %s", sample, word, rendered)
			}
		}
	}
}

// --- small helpers ----------------------------------------------------------

func itoa(n int) string { return strconv.Itoa(n) }

// structFieldNames renders a struct's field and JSON tag names for inspection.
func structFieldNames(v any) string {
	t := reflect.TypeOf(v)
	var b strings.Builder
	for i := range t.NumField() {
		f := t.Field(i)
		b.WriteString(f.Name)
		b.WriteString(" ")
		b.WriteString(f.Tag.Get("json"))
		b.WriteString(" ")
	}
	return b.String()
}
