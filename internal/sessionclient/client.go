// Package sessionclient is the device half of the control channel.
//
// It holds one connection per network membership, receives desired state, hands it to
// an Applier and acknowledges the version that was applied (Invariant 14).
//
// Losing the control plane must not disturb networking that is already up
// (Invariant 15). Nothing here tears anything down on disconnect: it reconnects, and
// the Applier is only ever asked to move toward a new state, never to abandon the
// current one.
package sessionclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/meshpnet/meshp/internal/keys"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

const (
	// heartbeatInterval is well inside the server's idle timeout, so a healthy
	// connection is never mistaken for a dead one.
	heartbeatInterval = 25 * time.Second

	dialTimeout     = 20 * time.Second
	writeTimeout    = 10 * time.Second
	readIdleTimeout = 90 * time.Second
	maxMessageBytes = 1 << 20

	minBackoff = 500 * time.Millisecond
	maxBackoff = 30 * time.Second
)

// Applier converges the device toward a desired state.
//
// It returns the components it could not apply rather than only an error, so a
// partial failure is reported honestly: the control plane can then show "this device
// has DNS but not routes" instead of deciding the whole thing either worked or did
// not.
type Applier interface {
	Apply(ctx context.Context, delta *meshpv1.StateDelta) (unapplied []string, err error)
}

// Options configures a Client.
type Options struct {
	ControlURL   string
	Identity     keys.Identity
	MembershipID uuid.UUID

	// AppliedVersion is what this device already has, from local state. Sending it in
	// the hello is what lets a reconnecting agent be told it is current rather than
	// being handed a snapshot it already has.
	AppliedVersion int64

	AgentVersion string
	OS           string
	OSVersion    string
	Hostname     string

	HTTPClient *http.Client
	Log        *slog.Logger
}

// Client maintains one control-channel session.
type Client struct {
	opts    Options
	log     *slog.Logger
	httpc   *http.Client
	applied int64
}

// New returns a Client.
func New(opts Options) *Client {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: dialTimeout}
	}
	opts.ControlURL = strings.TrimRight(opts.ControlURL, "/")
	return &Client{opts: opts, log: opts.Log, httpc: opts.HTTPClient, applied: opts.AppliedVersion}
}

// AppliedVersion is the newest version this client has applied.
func (c *Client) AppliedVersion() int64 { return c.applied }

// Run keeps a session up until ctx ends, reconnecting when it drops.
func (c *Client) Run(ctx context.Context, applier Applier) error {
	backoff := minBackoff
	for {
		start := time.Now()
		err := c.RunOnce(ctx, applier)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// A session that lasted a while was healthy, so the next failure should retry
		// promptly rather than inheriting the backoff from an outage that is over.
		if time.Since(start) > time.Minute {
			backoff = minBackoff
		}

		wait := jitter(backoff)
		c.log.Info("control channel lost; reconnecting",
			"membership_id", c.opts.MembershipID, "retry_in", wait.Round(time.Millisecond), "error", err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// jitter spreads reconnections out.
//
// Without it, an outage ends with every agent in the fleet reconnecting in the same
// instant — the control plane comes back, is knocked over by its own clients, and the
// cycle repeats. Full jitter over the interval is the cheapest fix.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d))) + d/2
}

// RunOnce establishes one session and serves it until it ends.
func (c *Client) RunOnce(ctx context.Context, applier Applier) error {
	challenge, err := c.fetchChallenge(ctx)
	if err != nil {
		return fmt.Errorf("sessionclient: challenge: %w", err)
	}

	wsURL := toWebSocketURL(c.opts.ControlURL) + "/api/v1/session"
	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	conn, upgradeResp, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPClient:      c.httpc,
		CompressionMode: websocket.CompressionDisabled,
	})
	cancelDial()
	if upgradeResp != nil && upgradeResp.Body != nil {
		// The handshake has already consumed it; closing releases the reader.
		_ = upgradeResp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("sessionclient: dialling %s: %w", wsURL, err)
	}
	conn.SetReadLimit(maxMessageBytes)
	defer func() { _ = conn.CloseNow() }()

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// One writer. The heartbeat ticker and the acknowledgement path both produce
	// messages, and concurrent writes to a WebSocket are not allowed.
	outbound := make(chan *meshpv1.ClientMessage, 8)

	hello := &meshpv1.ClientMessage{
		Payload: &meshpv1.ClientMessage_Hello{Hello: &meshpv1.ClientHello{
			IdentityPublicKey:   c.opts.Identity.Public,
			Challenge:           challenge,
			ChallengeSignature:  c.opts.Identity.Sign(challenge),
			MembershipId:        c.opts.MembershipID.String(),
			AgentVersion:        c.opts.AgentVersion,
			Os:                  c.opts.OS,
			OsVersion:           c.opts.OSVersion,
			Hostname:            c.opts.Hostname,
			AppliedStateVersion: uint64(c.applied),
			Capabilities: &meshpv1.AgentCapabilities{
				// Reported honestly: this build has no WireGuard, no filter and no
				// traversal, and a control plane told otherwise would make decisions on
				// the strength of things this agent cannot do.
				Ipv6:               true,
				LocalFailover:      false,
				PacketFilter:       false,
				SplitDns:           false,
				CanEgress:          false,
				CanAdvertiseRoutes: false,
			},
		}},
	}
	if err := writeClientMessage(sessionCtx, conn, hello); err != nil {
		return fmt.Errorf("sessionclient: sending hello: %w", err)
	}

	writerDone := make(chan error, 1)
	go func() {
		for {
			select {
			case <-sessionCtx.Done():
				writerDone <- nil
				return
			case msg := <-outbound:
				if err := writeClientMessage(sessionCtx, conn, msg); err != nil {
					writerDone <- err
					return
				}
			}
		}
	}()

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				select {
				case outbound <- &meshpv1.ClientMessage{
					Payload: &meshpv1.ClientMessage_Heartbeat{Heartbeat: &meshpv1.Heartbeat{
						AppliedStateVersion: uint64(c.applied),
						SentAtUnixMs:        time.Now().UnixMilli(),
					}},
				}:
				default:
					// The writer is already behind; another heartbeat will not help.
				}
			}
		}
	}()

	for {
		select {
		case err := <-writerDone:
			if err != nil {
				return fmt.Errorf("sessionclient: writing: %w", err)
			}
			return errors.New("sessionclient: writer stopped")
		default:
		}

		readCtx, cancelRead := context.WithTimeout(sessionCtx, readIdleTimeout)
		msg, err := readServerMessage(readCtx, conn)
		cancelRead()
		if err != nil {
			return err
		}

		switch payload := msg.Payload.(type) {
		case *meshpv1.ServerMessage_Hello:
			h := payload.Hello
			c.log.Info("control channel established",
				"session", h.GetSessionId(),
				"network_id", h.GetNetworkId(),
				"addresses", h.GetAddresses(),
				"server_version", h.GetCurrentStateVersion(),
				"applied_version", c.applied)

		case *meshpv1.ServerMessage_StateDelta:
			c.handleState(sessionCtx, applier, payload.StateDelta, outbound)

		case *meshpv1.ServerMessage_HeartbeatAck:
			if payload.HeartbeatAck.GetStateAvailable() {
				c.log.Debug("server has newer state",
					"server_version", payload.HeartbeatAck.GetCurrentStateVersion(), "applied", c.applied)
			}

		case *meshpv1.ServerMessage_Command:
			c.log.Info("received a command", "command", fmt.Sprintf("%T", payload.Command.Payload))

		default:
			// A newer control plane may send something this agent has never heard of,
			// and that must not end the session (ADR-0008).
			c.log.Debug("ignoring an unhandled server message", "type", fmt.Sprintf("%T", msg.Payload))
		}
	}
}

// handleState applies a delta and acknowledges it.
func (c *Client) handleState(ctx context.Context, applier Applier, delta *meshpv1.StateDelta, outbound chan<- *meshpv1.ClientMessage) {
	ack := &meshpv1.StateAck{AppliedVersion: delta.GetToVersion()}

	unapplied, err := applier.Apply(ctx, delta)
	switch {
	case err != nil:
		// The version is reported as *not* applied, so the control plane's convergence
		// lag stays truthful. Claiming a version we failed to reach would make the one
		// metric that shows a broken agent show a healthy one.
		ack.AppliedVersion = uint64(c.applied)
		ack.Error = err.Error()
		ack.UnappliedComponents = unapplied
		c.log.Error("could not apply desired state",
			"version", delta.GetToVersion(), "error", err, "unapplied", unapplied)
	default:
		c.applied = int64(delta.GetToVersion())
		ack.UnappliedComponents = unapplied
		c.log.Info("applied desired state",
			"version", delta.GetToVersion(), "peers", len(delta.GetUpsertPeers()))
	}

	select {
	case outbound <- &meshpv1.ClientMessage{Payload: &meshpv1.ClientMessage_StateAck{StateAck: ack}}:
	case <-ctx.Done():
	}
}

// fetchChallenge asks the control plane for something to sign.
func (c *Client) fetchChallenge(ctx context.Context) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{
		"identity_public_key": base64.StdEncoding.EncodeToString(c.opts.Identity.Public),
		"membership_id":       c.opts.MembershipID.String(),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.opts.ControlURL+"/api/v1/session/challenge", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("control plane returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	var out struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, fmt.Errorf("decoding challenge: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Challenge)
	if err != nil {
		return nil, fmt.Errorf("challenge is not valid base64: %w", err)
	}
	return raw, nil
}

// toWebSocketURL converts an http(s) control URL to its ws(s) equivalent.
func toWebSocketURL(controlURL string) string {
	switch {
	case strings.HasPrefix(controlURL, "https://"):
		return "wss://" + strings.TrimPrefix(controlURL, "https://")
	case strings.HasPrefix(controlURL, "http://"):
		return "ws://" + strings.TrimPrefix(controlURL, "http://")
	default:
		return controlURL
	}
}

func readServerMessage(ctx context.Context, conn *websocket.Conn) (*meshpv1.ServerMessage, error) {
	typ, data, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, fmt.Errorf("sessionclient: expected a binary frame, got %v", typ)
	}
	var msg meshpv1.ServerMessage
	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("sessionclient: malformed message: %w", err)
	}
	return &msg, nil
}

func writeClientMessage(ctx context.Context, conn *websocket.Conn, msg *meshpv1.ClientMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageBinary, data)
}
