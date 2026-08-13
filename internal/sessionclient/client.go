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
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/meshpnet/meshp/internal/controlurl"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/peerset"
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
// It is handed the complete desired state, not the delta that produced it. Folding deltas
// is this package's job, and the difference matters: an Applier given a target is
// idempotent by construction and can be run twice with the same result (Invariant 18),
// while an Applier given an instruction has to remember what it did last time and is
// wrong in a way nothing detects if it ever forgets.
//
// It also means the reconciler compares desired state against what the host actually has,
// rather than against what it believes it applied — which is the only version of that
// comparison that survives somebody editing a WireGuard interface by hand.
//
// It returns the components it could not apply rather than only an error, so a partial
// failure is reported honestly: the control plane can show "this device has DNS but not
// routes" instead of deciding the whole thing either worked or did not.
type Applier interface {
	Apply(ctx context.Context, state *peerset.Set) (unapplied []string, err error)
}

// RelayCredentials is whatever needs a relay token, if anything does.
//
// The agent asks and the server answers; the server never pushes (ADR-0017). This is the
// asking half, kept behind an interface so the control channel carries the credential
// without owning a relay connection — a session dropping must not take relayed paths with
// it (Invariant 15), which it would if the client held the relay itself.
type RelayCredentials interface {
	// NeedsToken reports whether to ask now. Called on every heartbeat, so it is also
	// where a refusal is throttled: an implementation that kept saying yes after being
	// declined would turn one misconfigured deployment into a request loop.
	NeedsToken() bool

	// SetToken hands over an issued credential.
	SetToken(token []byte, expiresAt time.Time)

	// TokenRefused reports that the server declined, and why.
	TokenRefused(reason string)
}

// Options configures a Client.
type Options struct {
	ControlURL   string
	Identity     keys.Identity
	MembershipID uuid.UUID

	AgentVersion string
	OS           string
	OSVersion    string
	Hostname     string

	// Relay receives relay credentials as they are issued. Nil on a build or a platform
	// with no data plane, and the client then never asks for one — a token nothing can use
	// is a credential minted for no reason.
	Relay RelayCredentials

	HTTPClient *http.Client
	Log        *slog.Logger
}

// Client maintains one control-channel session.
type Client struct {
	opts   Options
	urlErr error
	log    *slog.Logger
	httpc  *http.Client

	// mu guards state. Three goroutines reach it: the read loop folds deltas into it, the
	// heartbeat reports its version, and whatever asks the daemon for status reads both.
	// Nothing here is contended — the lock is held for a map copy at most — but without it
	// the daemon's own status command races the session it is reporting on.
	mu sync.Mutex

	// state is the desired state as folded from everything received so far. It is the
	// only thing that licenses asking for a delta: a delta can be applied to it, and
	// there is nothing else to apply one to.
	state *peerset.Set
}

// New returns a Client.
func New(opts Options) *Client {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: dialTimeout}
	}
	c := &Client{opts: opts, log: opts.Log, httpc: opts.HTTPClient, state: peerset.New()}
	validated, err := controlurl.Validate(opts.ControlURL)
	if err != nil {
		c.urlErr = err
		return c
	}
	c.opts.ControlURL = validated
	return c
}

// AppliedVersion is the newest version this client has applied.
func (c *Client) AppliedVersion() int64 { return int64(c.appliedVersion()) }

// PeerCount is how many peers the desired state currently holds.
func (c *Client) PeerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Len()
}

// appliedVersion is the version the client currently holds.
func (c *Client) appliedVersion() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Version()
}

// knowsARelay reports whether desired state names one.
func (c *Client) knowsARelay() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.state.Relays().GetRelays()) > 0
}

// maybeRequestRelayToken asks for a credential when there is somewhere to use one.
//
// Both conditions matter. Asking before desired state names a relay gets a refusal from a
// deployment that has simply not sent its relays yet, and asking on a build with no data
// plane mints a credential nothing will ever present.
//
// Non-blocking on a full queue: the writer is already behind, and a second request would
// not reach the server any sooner. The heartbeat asks again in 25 seconds.
func (c *Client) maybeRequestRelayToken(outbound chan<- *meshpv1.ClientMessage) {
	if c.opts.Relay == nil || !c.knowsARelay() || !c.opts.Relay.NeedsToken() {
		return
	}
	select {
	case outbound <- &meshpv1.ClientMessage{
		Payload: &meshpv1.ClientMessage_RelayTokenRequest{RelayTokenRequest: &meshpv1.RelayTokenRequest{}},
	}:
	default:
	}
}

// handleRelayToken passes an issued credential on, or records a refusal.
func (c *Client) handleRelayToken(msg *meshpv1.RelayToken) {
	if c.opts.Relay == nil {
		// Nothing asked for this. A server that sent it unprompted is not a reason to end
		// the session (ADR-0008), but it is worth a line: it means the two ends disagree
		// about who starts this exchange.
		c.log.Debug("ignoring a relay token nothing asked for")
		return
	}
	if reason := msg.GetError(); reason != "" {
		// The text crosses a trust boundary from the control plane, which an agent may be
		// pointed at rather than own.
		c.log.Warn("the control plane declined to issue a relay token",
			"reason", logx.Safe(reason))
		c.opts.Relay.TokenRefused(reason)
		return
	}
	if len(msg.GetToken()) == 0 {
		c.opts.Relay.TokenRefused("the control plane sent an empty token")
		return
	}
	expires := time.Unix(msg.GetExpiresAtUnix(), 0)
	c.opts.Relay.SetToken(msg.GetToken(), expires)
	c.log.Info("holding a relay token", "expires_at", expires.UTC().Format(time.RFC3339))
}

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
		// The error can carry text written by the control plane, which an agent may be
		// pointed at rather than own.
		c.log.Info("control channel lost; reconnecting",
			"membership_id", c.opts.MembershipID,
			"retry_in", wait.Round(time.Millisecond),
			"error", logx.SafeError(err))

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
	if c.urlErr != nil {
		return c.urlErr
	}
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
			IdentityPublicKey:  c.opts.Identity.Public,
			Challenge:          challenge,
			ChallengeSignature: c.opts.Identity.Sign(challenge),
			MembershipId:       c.opts.MembershipID.String(),
			AgentVersion:       c.opts.AgentVersion,
			Os:                 c.opts.OS,
			OsVersion:          c.opts.OSVersion,
			Hostname:           c.opts.Hostname,
			// What this process holds in memory, which after a fresh start is nothing.
			//
			// Deliberately not the version persisted on disk. A delta can only be applied to
			// the state it was computed against, and a restarted agent no longer has that
			// state — asking for a delta from a remembered number would fold changes into an
			// empty set and leave the agent quietly missing every peer it knew about, at a
			// version that says it is current.
			AppliedStateVersion: c.appliedVersion(),
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
						AppliedStateVersion: c.appliedVersion(),
						SentAtUnixMs:        time.Now().UnixMilli(),
					}},
				}:
				default:
					// The writer is already behind; another heartbeat will not help.
				}

				// A relay token expires while the session stays up, so something has to
				// notice on a timer rather than only when state changes. The heartbeat is
				// already the agent's "still here" tick and needs no goroutine of its own.
				c.maybeRequestRelayToken(outbound)
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
				"applied_version", c.appliedVersion())

		case *meshpv1.ServerMessage_StateDelta:
			c.handleState(sessionCtx, applier, payload.StateDelta, outbound)
			// State is what first tells this agent a relay exists, so this is the earliest
			// moment worth asking — waiting for the next heartbeat would leave every peer
			// relay-less for up to 25 seconds after a join.
			c.maybeRequestRelayToken(outbound)

		case *meshpv1.ServerMessage_RelayToken:
			c.handleRelayToken(payload.RelayToken)

		case *meshpv1.ServerMessage_HeartbeatAck:
			if payload.HeartbeatAck.GetStateAvailable() {
				c.log.Debug("server has newer state",
					"server_version", payload.HeartbeatAck.GetCurrentStateVersion(),
					"applied", c.appliedVersion())
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

// handleState folds a delta into the desired state, applies it and acknowledges.
func (c *Client) handleState(ctx context.Context, applier Applier, delta *meshpv1.StateDelta, outbound chan<- *meshpv1.ClientMessage) {
	previous := c.appliedVersion()

	// Refusing a delta we cannot apply, rather than applying it to the wrong base. A
	// delta whose from_version is not what this agent holds would produce a peer set that
	// matches neither version while claiming to be the newer one — drift that nothing
	// downstream can detect, because the version numbers would agree.
	if from := delta.GetFromVersion(); from != 0 && from != previous {
		c.log.Warn("refusing a delta computed against a different version",
			"delta_from", from, "have", previous, "delta_to", delta.GetToVersion())
		select {
		case outbound <- &meshpv1.ClientMessage{Payload: &meshpv1.ClientMessage_StateAck{StateAck: &meshpv1.StateAck{
			AppliedVersion:      previous,
			Error:               fmt.Sprintf("delta from version %d cannot be applied to version %d", from, previous),
			UnappliedComponents: []string{"peers"},
		}}}:
		case <-ctx.Done():
		}
		return
	}

	snapshot := delta.GetFromVersion() == 0

	// Folded under the lock; handed over as a copy. The applier may keep what it is given
	// for as long as it likes — the reconciler will, to diff the next state against it —
	// and the next delta must not reach back into it.
	c.mu.Lock()
	c.state.Apply(delta)
	target := c.state.Clone()
	c.mu.Unlock()

	ack := &meshpv1.StateAck{AppliedVersion: target.Version()}
	unapplied, err := applier.Apply(ctx, target)
	if err != nil {
		// Reported as *not* applied, and the folded state is rolled back to the version
		// that was actually in force. Claiming a version we failed to reach would make the
		// one metric that shows a broken agent show a healthy one.
		c.mu.Lock()
		c.state.SetVersion(previous)
		c.mu.Unlock()
		ack.AppliedVersion = previous
		ack.Error = err.Error()
		ack.UnappliedComponents = unapplied
		c.log.Error("could not apply desired state",
			"version", delta.GetToVersion(), "error", err, "unapplied", unapplied)
	} else {
		ack.UnappliedComponents = unapplied
		c.log.Info("applied desired state",
			"version", target.Version(),
			"snapshot", snapshot,
			"upserted", len(delta.GetUpsertPeers()),
			"removed", len(delta.GetRemovePeerKeys()),
			"peers", target.Len())
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
