// Package relaylink is this device's attachment to a relay.
//
// It is the join between three things that do not know about each other: the control
// channel, which is told about relays and issues the credential to use them; relayclient,
// which speaks to a relay; and relayforward, which carries packets between a relay and the
// kernel. Nothing here decides policy — which peers are relayed is desired state, and how
// a packet reaches the kernel is relayforward's problem.
//
// Two properties shape it.
//
// The relay attachment outlives the control channel. Losing the control plane must not
// disturb networking that is already up (Invariant 15), and a relayed path is networking
// that is up: the token in hand stays valid for as long as it says it does, and a
// reconnecting session does not interrupt the relay connection.
//
// A relayed peer's endpoint is stable whether or not a relay is reachable. The socket
// serving it belongs to relayforward and exists as soon as desired state says the peer is
// relayed. Tying it to the connection would mean rewriting every peer on each reconnect,
// and un-relaying a peer with nothing to replace its endpoint is something wgplan refuses
// to do for good reason (ADR-0016).
package relaylink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/relayclient"
	"github.com/meshpnet/meshp/internal/relayforward"
	"github.com/meshpnet/meshp/internal/relayproto"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

const (
	// renewWithin is how close to expiry a token gets before another is asked for.
	//
	// Deliberately inside the control plane's own reissue window, which is five minutes:
	// asking outside it returns the same token, so the agent would ask on every heartbeat
	// for as long as it took to get inside. Four minutes means the first ask mints a fresh
	// one, and it still leaves four minutes of working credential if the control plane is
	// unreachable when the timer comes round.
	renewWithin = 4 * time.Minute

	// refusalBackoff is how long to leave a declining control plane alone.
	//
	// A refusal usually means the deployment has no signing key, which no amount of asking
	// fixes. Long enough that a misconfiguration costs one request every few minutes
	// rather than one per heartbeat; short enough that configuring a relay starts working
	// without restarting every agent.
	refusalBackoff = 5 * time.Minute

	// deadAfter is how long a relay may stay silent before the session is treated as gone.
	//
	// A relay answers every ping, so silence across three keepalives is not a quiet mesh —
	// it is a relay that has forgotten us. UDP will not report that, so nothing else would
	// notice and the agent would sit attached to a dead session reporting itself connected.
	deadAfter = 3 * relayclient.KeepaliveInterval

	minDialBackoff = 1 * time.Second
	maxDialBackoff = 30 * time.Second

	// idlePoll bounds how long the dial loop waits when it has nothing to dial with. It is
	// a backstop: wake() covers every case where something actually changes.
	idlePoll = 30 * time.Second
)

// Options configures a Link.
type Options struct {
	// Key is this device's WireGuard public key for this membership, base64 as the control
	// plane spells it. The relay knows the device by this and nothing else.
	Key string

	// WireGuardPort is the local WireGuard listen port, where inbound relayed packets are
	// delivered. Zero when the interface has not come up yet, which is the state of a
	// device that has just joined; SetWireGuardPort supplies it once the kernel has chosen.
	WireGuardPort int

	Log   *slog.Logger
	Clock clock.Clock
}

// Link is one membership's relay attachment.
type Link struct {
	key       relayproto.Key
	log       *slog.Logger
	clk       clock.Clock
	forwarder *relayforward.Forwarder

	// wake is poked whenever something changes that could let a blocked dial proceed: a
	// token arriving, or relays appearing in desired state. Buffered and non-blocking, so
	// a caller holding the lock never waits on the dial loop.
	wake chan struct{}

	// keepalive and deadAfter are fields rather than constants so a test can watch a
	// session be declared dead without waiting a real minute for it.
	keepalive time.Duration
	deadAfter time.Duration

	mu sync.Mutex

	// relayID and endpoints are the relay this link is responsible for, from desired
	// state. One relay today; when there are several this becomes a set and the peer's
	// relay_id picks between them, which is why Endpoint already takes one.
	relayID   string
	endpoints []string

	token        []byte
	expires      time.Time
	refusedUntil time.Time
	refusal      string

	client         *relayclient.Client
	connectedSince time.Time
	lastErr        string
	closed         bool
}

// New returns a Link, which does nothing until Run is called.
func New(opts Options) (*Link, error) {
	key, err := relayKey(opts.Key)
	if err != nil {
		return nil, err
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	forwarder, err := relayforward.New(opts.WireGuardPort, nil, opts.Log)
	if err != nil {
		return nil, err
	}
	return &Link{
		key:       key,
		log:       opts.Log,
		clk:       opts.Clock,
		forwarder: forwarder,
		wake:      make(chan struct{}, 1),
		keepalive: relayclient.KeepaliveInterval,
		deadAfter: deadAfter,
	}, nil
}

// relayKey turns a base64 WireGuard public key into the raw form a relay session is named by.
func relayKey(encoded string) (relayproto.Key, error) {
	var out relayproto.Key
	if encoded == "" {
		return out, errors.New("relaylink: this membership has no WireGuard public key")
	}
	parsed, err := keys.ParseWireGuardKey(encoded)
	if err != nil {
		return out, fmt.Errorf("relaylink: this membership's WireGuard public key: %w", err)
	}
	copy(out[:], parsed[:])
	return out, nil
}

// SetRelays records the relays desired state names.
//
// Called before the reconciler is asked to converge, so that a peer arriving as relayed in
// the same update already has somewhere to be relayed through.
func (l *Link) SetRelays(cfg *meshpv1.RelayConfig) {
	relay := preferred(cfg)

	l.mu.Lock()
	id, endpoints := "", []string(nil)
	if relay != nil {
		id, endpoints = relay.GetId(), relay.GetEndpoints()
	}
	changed := id != l.relayID || !sameStrings(endpoints, l.endpoints)
	l.relayID, l.endpoints = id, endpoints

	// A relay that has been replaced or withdrawn invalidates the connection to the old
	// one. Dropping it here rather than letting it idle out means an operator moving a
	// fleet between relays sees it happen.
	stale := l.client
	if changed && stale != nil {
		l.client = nil
		l.connectedSince = time.Time{}
	} else {
		stale = nil
	}
	l.mu.Unlock()

	if stale != nil {
		l.log.Info("the relay changed; dropping the old connection", "endpoint", stale.Endpoint())
		_ = stale.Close()
		l.forwarder.SetSender(nil)
	}
	if changed {
		l.wakeDialer()
	}
}

// preferred picks the relay to attach to.
func preferred(cfg *meshpv1.RelayConfig) *meshpv1.RelayConfig_Relay {
	relays := cfg.GetRelays()
	if len(relays) == 0 {
		return nil
	}
	if id := cfg.GetPreferredRelayId(); id != "" {
		for _, relay := range relays {
			if relay.GetId() == id {
				return relay
			}
		}
		// Named a relay it did not describe. Falling through to the first is better than
		// refusing to relay at all, but it is a control-plane bug and says so.
	}
	return relays[0]
}

// NeedsToken implements sessionclient.RelayCredentials.
func (l *Link) NeedsToken() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clk.Now()
	if l.closed || now.Before(l.refusedUntil) {
		return false
	}
	// Renewed before expiry rather than after, so a relayed path is never interrupted
	// waiting for a credential it could have had already.
	return len(l.token) == 0 || !now.Add(renewWithin).Before(l.expires)
}

// SetToken implements sessionclient.RelayCredentials.
func (l *Link) SetToken(token []byte, expiresAt time.Time) {
	l.mu.Lock()
	// Fresh credentials clear a refusal: whatever the control plane was declining for, it
	// is not declining now.
	l.token, l.expires, l.refusedUntil, l.refusal = token, expiresAt, time.Time{}, ""
	connected := l.client != nil
	l.mu.Unlock()

	// Only worth waking the dialler if it is waiting. A live connection keeps its own
	// token until the relay stops accepting it, at which point the loop reconnects and
	// picks this one up — reconnecting now would interrupt working paths to no purpose.
	if !connected {
		l.wakeDialer()
	}
}

// TokenRefused implements sessionclient.RelayCredentials.
func (l *Link) TokenRefused(reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refusedUntil = l.clk.Now().Add(refusalBackoff)
	l.refusal = reason
}

// Endpoint returns the local address to configure for a peer relayed through relayID.
//
// The peer's relay must be the one this link serves. Handing back an endpoint for a relay
// nothing is attached to would give the kernel somewhere to send that goes nowhere, which
// looks exactly like a working relayed peer until traffic is tried.
func (l *Link) Endpoint(publicKey, relayID string) (netip.AddrPort, error) {
	l.mu.Lock()
	serving, closed := l.relayID, l.closed
	l.mu.Unlock()

	if closed {
		return netip.AddrPort{}, errors.New("relaylink: closed")
	}
	if relayID == "" || relayID != serving {
		return netip.AddrPort{}, fmt.Errorf(
			"relaylink: this device is not attached to relay %q", logx.Safe(relayID))
	}
	key, err := relayKey(publicKey)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return l.forwarder.Endpoint(key)
}

// SetWireGuardPort tells the forwarder where inbound packets go.
//
// Called by the reconciler after the interface converges: a device that has just joined
// asks the kernel for any port, so the port it will be reached on is not known until then.
func (l *Link) SetWireGuardPort(port int) { l.forwarder.SetWireGuardPort(port) }

// Retain stops serving any peer not in the list.
//
// Called after the kernel has been pointed somewhere else, never before: closing a socket
// the kernel still sends to produces a peer that looks configured and goes nowhere
// (ADR-0016).
func (l *Link) Retain(publicKeys []string) {
	keep := make(map[relayproto.Key]struct{}, len(publicKeys))
	for _, encoded := range publicKeys {
		if key, err := relayKey(encoded); err == nil {
			keep[key] = struct{}{}
		}
	}
	for _, served := range l.forwarder.Peers() {
		if _, ok := keep[served]; !ok {
			l.forwarder.Forget(served)
		}
	}
}

// Run keeps the relay connection up until ctx ends.
func (l *Link) Run(ctx context.Context) error {
	backoff := minDialBackoff
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		endpoints, token, ready := l.dialInputs()
		if !ready {
			if l.isClosed() {
				// Nothing will ever become ready again. Without this the loop would idle
				// forever on a link something has finished with.
				return nil
			}
			if !l.sleep(ctx, idlePoll) {
				return ctx.Err()
			}
			continue
		}

		client, err := relayclient.Dial(ctx, relayclient.Options{
			Endpoints: endpoints, Key: l.key, Token: token, Log: l.log,
		})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			l.dialFailed(err)
			if !l.sleep(ctx, backoff) {
				return ctx.Err()
			}
			if backoff *= 2; backoff > maxDialBackoff {
				backoff = maxDialBackoff
			}
			continue
		}

		backoff = minDialBackoff
		l.attach(client)
		err = l.serve(ctx, client)

		// A shutdown is not a fault. The watchdog closes the client to unblock the read, so
		// the error on the way out says "closed" — recording that as the last error would
		// leave every stopped agent claiming its relay failed.
		if ctx.Err() != nil {
			l.detach(client, nil)
			return ctx.Err()
		}
		l.detach(client, err)
	}
}

func (l *Link) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// dialInputs reports what a dial needs, and whether it has it.
func (l *Link) dialInputs() (endpoints []string, token []byte, ready bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || len(l.endpoints) == 0 || len(l.token) == 0 {
		return nil, nil, false
	}
	// An expired token will be refused, and presenting one teaches the relay nothing except
	// that this device is misbehaving. Waiting costs one idle poll; the control channel is
	// already asking for a replacement.
	if !l.clk.Now().Before(l.expires) {
		return nil, nil, false
	}
	return append([]string(nil), l.endpoints...), l.token, true
}

// serve runs the receive loop until the connection ends.
//
// One goroutine rather than two. The read deadline doubles as the keepalive timer: a
// deadline that expires means nothing has arrived for a keepalive interval, which is
// exactly when a ping is worth sending, and traffic means the mapping is being held open
// by the traffic itself.
func (l *Link) serve(ctx context.Context, client *relayclient.Client) error {
	// Closing the client is what unblocks a read, since a UDP read cannot take a context.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-stop:
		}
	}()

	buf := make([]byte, relayproto.MaxPayload)
	nonce := make([]byte, 8)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := client.SetReadDeadline(time.Now().Add(l.keepalive)); err != nil {
			return err
		}

		peer, n, err := client.Receive(buf)
		if err != nil {
			var timeout interface{ Timeout() bool }
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				return err
			}
			// Nothing for a keepalive interval. Ping, and give up on the session if the
			// relay has been silent long enough that it can no longer be listening.
			if time.Since(client.LastHeard()) > l.deadAfter {
				return fmt.Errorf("relaylink: %s stopped answering", client.Endpoint())
			}
			if err := client.Ping(nonce); err != nil {
				return err
			}
			continue
		}

		if err := l.forwarder.Deliver(peer, buf[:n]); err != nil {
			// One undeliverable packet is not a reason to drop a working relay connection:
			// a peer that has just moved to a direct path produces exactly this while the
			// relay flushes what it still had. relayforward counts them.
			l.log.Debug("could not deliver a relayed packet", "error", logx.SafeError(err))
		}
	}
}

func (l *Link) attach(client *relayclient.Client) {
	l.mu.Lock()
	l.client = client
	l.connectedSince = l.clk.Now()
	l.lastErr = ""
	l.mu.Unlock()

	// The forwarder can send only once there is something to send through.
	l.forwarder.SetSender(client)
	l.log.Info("attached to a relay",
		"endpoint", client.Endpoint(), "reflexive", client.Reflexive().String())
}

func (l *Link) detach(client *relayclient.Client, cause error) {
	l.mu.Lock()
	if l.client == client {
		l.client = nil
		l.connectedSince = time.Time{}
	}
	// A relay refusing us mid-session means the credential is no longer good — almost
	// always an expired token. Dropping it makes NeedsToken say yes, so the control
	// channel fetches another instead of the dial loop presenting the same bad one.
	if errors.Is(cause, relayclient.ErrRefused) {
		l.token, l.expires = nil, time.Time{}
	}
	if cause != nil {
		l.lastErr = cause.Error()
	}
	l.mu.Unlock()

	// Before closing, so no packet is handed to a socket being torn down.
	l.forwarder.SetSender(nil)
	_ = client.Close()

	if cause != nil && !errors.Is(cause, context.Canceled) {
		l.log.Warn("relay connection ended",
			"endpoint", client.Endpoint(), "error", logx.SafeError(cause))
	}
}

func (l *Link) dialFailed(err error) {
	l.mu.Lock()
	l.lastErr = err.Error()
	// Same reasoning as detach: a refusal means the token is the problem.
	if errors.Is(err, relayclient.ErrRefused) {
		l.token, l.expires = nil, time.Time{}
	}
	l.mu.Unlock()
	l.log.Warn("could not reach a relay", "error", logx.SafeError(err))
}

// sleep waits, and reports whether it finished rather than being cut short.
//
// Woken early by anything that could unblock a dial, so a token arriving does not sit
// behind a backoff that was waiting for exactly that.
func (l *Link) sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-l.wake:
		return true
	case <-timer.C:
		return true
	}
}

func (l *Link) wakeDialer() {
	select {
	case l.wake <- struct{}{}:
	default: // already pending; one wake is enough
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Status is what the daemon reports about this link.
type Status struct {
	// RelayID and Endpoints are what desired state asked for, which is worth reporting
	// even when nothing is connected: "configured for relay1 and cannot reach it" and
	// "never told about a relay" are different problems.
	RelayID   string
	Endpoints []string

	Connected      bool
	ConnectedSince time.Time
	Endpoint       string
	Reflexive      string

	HasToken       bool
	TokenExpiresAt time.Time
	Refusal        string
	LastError      string

	Forwarder relayforward.Stats
}

// Status reports what this link is doing.
func (l *Link) Status() Status {
	l.mu.Lock()
	st := Status{
		RelayID:        l.relayID,
		Endpoints:      append([]string(nil), l.endpoints...),
		ConnectedSince: l.connectedSince,
		HasToken:       len(l.token) > 0,
		TokenExpiresAt: l.expires,
		Refusal:        l.refusal,
		LastError:      l.lastErr,
	}
	client := l.client
	l.mu.Unlock()

	if client != nil {
		st.Connected = true
		st.Endpoint = client.Endpoint()
		if reflexive := client.Reflexive(); reflexive.IsValid() {
			st.Reflexive = reflexive.String()
		}
	}
	st.Forwarder = l.forwarder.Stats()
	return st
}

// Close releases the connection and every socket.
func (l *Link) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	client := l.client
	l.client = nil
	l.mu.Unlock()

	if client != nil {
		_ = client.Close()
	}
	return l.forwarder.Close()
}
