package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// ErrNoDaemon means meshpd is not reachable on the socket.
//
// Distinguished from every other failure so the CLI can say something useful. "Is the
// daemon running?" and "the daemon refused that" need different answers, and a single
// connection error covering both is how a person ends up debugging the wrong thing.
var ErrNoDaemon = errors.New("agentapi: meshpd is not running")

// ErrPermission means the socket exists but this user may not use it.
var ErrPermission = errors.New("agentapi: not permitted to talk to meshpd")

// Client talks to a local meshpd.
type Client struct {
	socketPath string
	http       *http.Client
}

// NewClient returns a client for the socket at path.
func NewClient(socketPath string, timeout time.Duration) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Client{
		socketPath: socketPath,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// SocketPath is the socket this client uses.
func (c *Client) SocketPath() string { return c.socketPath }

// Status asks the daemon what it is doing.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var out Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &out)
	return out, err
}

// Join asks the daemon to enrol this device.
func (c *Client) Join(ctx context.Context, req JoinRequest) (JoinResponse, error) {
	var out JoinResponse
	err := c.do(ctx, http.MethodPost, "/v1/join", req, &out)
	return out, err
}

// SetRunning takes this device off the mesh, or puts it back.
func (c *Client) SetRunning(ctx context.Context, running bool) (Status, error) {
	path := "/v1/down"
	if running {
		path = "/v1/up"
	}
	var out Status
	// No body. The path says which way, and a body saying it again is a second place for
	// the two to disagree.
	err := c.do(ctx, http.MethodPost, path, nil, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("agentapi: encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	// The host in the URL is ignored: the transport dials the socket regardless. It has
	// to be something, so it says what it is.
	req, err := http.NewRequestWithContext(ctx, method, "http://meshpd"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return c.classifyDialError(err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("agentapi: reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr Error
		if json.Unmarshal(payload, &apiErr) == nil && (apiErr.Code != "" || apiErr.Message != "") {
			return &apiErr
		}
		return fmt.Errorf("agentapi: meshpd returned %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("agentapi: decoding response: %w", err)
		}
	}
	return nil
}

// classifyDialError turns a connection failure into something a person can act on.
func (c *Client) classifyDialError(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w: %s", ErrPermission, c.socketPath)
	}
	// A missing socket file and a refused connection both mean no daemon; the first is
	// "never started", the second is "died without cleaning up".
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w (socket %s)", ErrNoDaemon, c.socketPath)
	}
	if _, statErr := os.Stat(c.socketPath); errors.Is(statErr, fs.ErrNotExist) {
		return fmt.Errorf("%w (socket %s)", ErrNoDaemon, c.socketPath)
	}
	return fmt.Errorf("agentapi: reaching meshpd on %s: %w", c.socketPath, err)
}
