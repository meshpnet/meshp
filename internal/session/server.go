package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/meshpnet/meshp/internal/challenge"
	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// ChallengePurpose separates session challenges from every other use of the
// deployment secret. An enrolment challenge must not open a session: a device whose
// membership has been revoked could otherwise present a leftover enrolment challenge
// and be let back in.
const ChallengePurpose = "meshp session challenge v1"

const (
	// helloDeadline is how long a connection may stay open without identifying
	// itself. An unauthenticated socket holding a goroutine and a database-free slot
	// is cheap, but not free, and there is no reason for a real agent to be slow here.
	helloDeadline = 10 * time.Second

	// writeTimeout bounds a single write. Without it, a peer that stops reading holds
	// the writer goroutine indefinitely.
	writeTimeout = 10 * time.Second

	// readIdleTimeout is how long the server waits to hear anything at all. Agents
	// heartbeat well inside this, so silence means the connection is gone in a way
	// TCP has not noticed — a laptop closed mid-flight, or a NAT that dropped the
	// mapping.
	readIdleTimeout = 90 * time.Second

	// maxMessageBytes caps one protocol message. A snapshot for a large network is
	// the biggest thing that crosses this channel, and it travels the other way.
	maxMessageBytes = 1 << 20
)

// Config wires a Server.
type Config struct {
	// MasterSecret derives the session challenge key.
	MasterSecret []byte

	Clock clock.Clock
	Log   *slog.Logger
}

// Server terminates control-channel sessions.
type Server struct {
	store      *store.Store
	hub        *Hub
	builder    *StateBuilder
	challenger *challenge.Challenger
	clk        clock.Clock
	log        *slog.Logger
}

// NewServer builds a Server.
func NewServer(st *store.Store, hub *Hub, cfg Config) (*Server, error) {
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	challenger, err := challenge.New(cfg.MasterSecret, ChallengePurpose, challenge.DefaultTTL, cfg.Clock)
	if err != nil {
		return nil, err
	}
	return &Server{
		store:      st,
		hub:        hub,
		builder:    NewStateBuilder(st),
		challenger: challenger,
		clk:        cfg.Clock,
		log:        cfg.Log,
	}, nil
}

// Hub exposes the registry so mutations elsewhere can notify connected agents.
func (s *Server) Hub() *Hub { return s.hub }

// IssueChallenge mints a challenge for a membership to sign.
//
// Bound to both the identity key and the membership, so a challenge obtained for one
// cannot be spent on the other. It deliberately does not check that the membership
// exists: doing so would make this an enumeration oracle for membership ids, and the
// signature check at connect time is what actually decides.
func (s *Server) IssueChallenge(identityPublicKey []byte, membershipID uuid.UUID) (challenge.Challenge, error) {
	if len(identityPublicKey) == 0 {
		return challenge.Challenge{}, errors.New("session: an identity public key is required")
	}
	id := membershipID
	return s.challenger.Issue(identityPublicKey, id[:])
}

// Serve upgrades an HTTP request to a control-channel session and runs it until the
// agent goes away or the context ends.
func (s *Server) Serve(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// No compression: the payload is protobuf, which compresses poorly, and
		// compressing attacker-influenced data alongside server data is a class of
		// problem worth not having.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		// Accept has already answered the request.
		s.log.Debug("control channel upgrade failed", "error", err)
		return
	}
	conn.SetReadLimit(maxMessageBytes)

	// Detached from the request context on purpose. A session outlives the HTTP
	// handler's notion of a request, and cancelling on request completion would tear
	// down every connection the moment it was established.
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()

	sess, err := s.handshake(ctx, conn)
	if err != nil {
		s.log.Info("control channel rejected", "error", err, "remote", r.RemoteAddr)
		// The reason goes to the client as a close code and to us as a log line. It is
		// deliberately terse on the wire: an agent needs to know it failed, not which
		// check failed.
		_ = conn.Close(websocket.StatusPolicyViolation, "authentication failed")
		return
	}

	s.run(ctx, conn, sess)
}

// handshake reads and verifies ClientHello, then registers the session.
func (s *Server) handshake(ctx context.Context, conn *websocket.Conn) (*Session, error) {
	helloCtx, cancel := context.WithTimeout(ctx, helloDeadline)
	defer cancel()

	msg, err := readClientMessage(helloCtx, conn)
	if err != nil {
		return nil, fmt.Errorf("reading hello: %w", err)
	}
	hello := msg.GetHello()
	if hello == nil {
		return nil, errors.New("first message was not a hello")
	}

	membershipID, err := uuid.Parse(hello.GetMembershipId())
	if err != nil {
		return nil, fmt.Errorf("membership id: %w", err)
	}

	// Order matters. The challenge is checked before anything touches the database, so
	// an unauthenticated caller cannot make the control plane do queries.
	id := membershipID
	if err := s.challenger.Verify(hello.GetChallenge(), hello.GetIdentityPublicKey(), id[:]); err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	if err := keys.VerifyIdentity(hello.GetIdentityPublicKey(), hello.GetChallenge(), hello.GetChallengeSignature()); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	membership, err := s.store.Queries().GetMembershipForSession(ctx, membershipID)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, errors.New("no such membership")
		}
		return nil, fmt.Errorf("loading membership: %w", err)
	}

	// The signature proves possession of *a* key; this proves it is the key recorded
	// for this membership's device. Without it, any enrolled device could request a
	// challenge for any membership id and open somebody else's session.
	if !constantTimeEqualBytes(membership.IdentityPublicKey, hello.GetIdentityPublicKey()) {
		return nil, errors.New("identity key does not belong to that membership")
	}
	if membership.DeviceRevokedAt != nil {
		return nil, errors.New("device has been revoked")
	}
	if membership.MembershipState != "active" {
		return nil, fmt.Errorf("membership is %s", membership.MembershipState)
	}

	sess := newSession(uuid.NewString(), membershipID, membership.NetworkID, membership.DeviceID, s.clk.Now())
	sess.setApplied(int64(hello.GetAppliedStateVersion()))

	if displaced := s.hub.Add(sess); displaced != nil {
		// The device reconnected without the old connection having been noticed as
		// dead. The newcomer wins.
		s.log.Info("replacing an existing session",
			"membership_id", membershipID, "old_session", displaced.ID, "new_session", sess.ID)
		displaced.Close()
	}

	if _, err := s.store.Queries().RecordSessionConnected(ctx, dbgen.RecordSessionConnectedParams{
		MembershipID: membershipID,
		Now:          ptrTime(s.clk.Now()),
		SessionID:    ptrString(sess.ID),
	}); err != nil {
		// Not fatal. The session works without the bookkeeping, and refusing to serve a
		// device because a presence row could not be written would turn a cosmetic
		// failure into an outage.
		s.log.Warn("could not record session as connected", "membership_id", membershipID, "error", err)
	}

	s.log.Info("control channel established",
		"session", sess.ID,
		"membership_id", membershipID,
		"device", membership.DeviceName,
		"agent_version", hello.GetAgentVersion(),
		"applied_version", hello.GetAppliedStateVersion())

	return sess, nil
}

// run serves a session until it ends.
func (s *Server) run(ctx context.Context, conn *websocket.Conn, sess *Session) {
	defer func() {
		s.hub.Remove(sess)
		sess.Close()

		// A short, independent context: the session's is already cancelled by the time
		// this runs, and the bookkeeping is still worth attempting.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.store.Queries().RecordSessionDisconnected(cleanupCtx, dbgen.RecordSessionDisconnectedParams{
			MembershipID: sess.MembershipID,
			SessionID:    ptrString(sess.ID),
		}); err != nil {
			s.log.Debug("could not clear session presence", "session", sess.ID, "error", err)
		}
		s.log.Info("control channel closed",
			"session", sess.ID, "membership_id", sess.MembershipID, "overran", sess.Overran())
	}()

	// ServerHello, then the first snapshot.
	membership, err := s.store.Queries().GetMembershipForSession(ctx, sess.MembershipID)
	if err != nil {
		s.log.Error("could not load membership after handshake", "session", sess.ID, "error", err)
		_ = conn.Close(websocket.StatusInternalError, "internal error")
		return
	}

	hello := &meshpv1.ServerMessage{
		Payload: &meshpv1.ServerMessage_Hello{Hello: &meshpv1.ServerHello{
			SessionId:           sess.ID,
			MembershipId:        sess.MembershipID.String(),
			NetworkId:           sess.NetworkID.String(),
			Addresses:           addressesOf(membership.AddressV4, membership.AddressV6),
			CurrentStateVersion: uint64(membership.StateVersion),
			SnapshotFollows:     true,
		}},
	}
	if !sess.enqueue(hello) {
		return
	}
	sess.Notify() // the snapshot itself

	readErr := make(chan error, 1)
	go func() { readErr <- s.readLoop(ctx, conn, sess) }()

	for {
		select {
		case <-ctx.Done():
			_ = conn.Close(websocket.StatusGoingAway, "shutting down")
			return

		case <-sess.Closed():
			_ = conn.Close(websocket.StatusNormalClosure, "session replaced or ended")
			return

		case err := <-readErr:
			if err != nil && !isExpectedClose(err) {
				s.log.Info("control channel read ended", "session", sess.ID, "error", err)
			}
			return

		case msg := <-sess.send:
			if err := writeServerMessage(ctx, conn, msg); err != nil {
				s.log.Debug("control channel write failed", "session", sess.ID, "error", err)
				return
			}

		case <-sess.notify:
			if err := s.pushState(ctx, conn, sess); err != nil {
				s.log.Info("could not push state", "session", sess.ID, "error", err)
				return
			}
		}
	}
}

// pushState sends whatever the agent needs to reach the current version.
//
// Relative to what the agent last acknowledged, so a device that is current gets an empty
// delta and a device that is behind gets only the difference. The builder decides between
// a delta and a snapshot; this only has to ask from the right place.
func (s *Server) pushState(ctx context.Context, conn *websocket.Conn, sess *Session) error {
	delta, err := s.builder.For(ctx, sess.MembershipID, uint64(sess.AppliedVersion()))
	if err != nil {
		return err
	}
	return writeServerMessage(ctx, conn, &meshpv1.ServerMessage{
		Payload: &meshpv1.ServerMessage_StateDelta{StateDelta: delta},
	})
}

// readLoop consumes agent messages until the connection ends.
func (s *Server) readLoop(ctx context.Context, conn *websocket.Conn, sess *Session) error {
	for {
		readCtx, cancel := context.WithTimeout(ctx, readIdleTimeout)
		msg, err := readClientMessage(readCtx, conn)
		cancel()
		if err != nil {
			return err
		}

		switch payload := msg.Payload.(type) {
		case *meshpv1.ClientMessage_StateAck:
			s.handleAck(ctx, sess, payload.StateAck)

		case *meshpv1.ClientMessage_Heartbeat:
			s.handleHeartbeat(ctx, sess, payload.Heartbeat)

		case *meshpv1.ClientMessage_Hello:
			// One hello per connection. A second is either a confused agent or somebody
			// trying to change identity mid-session.
			return errors.New("received a second hello on an established session")

		default:
			// Path reports, reachability reports and signalling arrive here once the
			// subsystems that consume them exist. Ignoring an unknown payload rather than
			// closing is deliberate: a newer agent must be able to send something this
			// server has never heard of (ADR-0008).
			s.log.Debug("ignoring an unhandled client message",
				"session", sess.ID, "type", fmt.Sprintf("%T", msg.Payload))
		}
	}
}

// handleAck records that an agent applied a version.
func (s *Server) handleAck(ctx context.Context, sess *Session, ack *meshpv1.StateAck) {
	applied := int64(ack.GetAppliedVersion())
	previous := sess.AppliedVersion()

	if ack.GetError() != "" {
		s.log.Warn("agent could not fully apply state",
			"session", sess.ID, "version", applied,
			"error", ack.GetError(), "unapplied", ack.GetUnappliedComponents())
	}

	// Only a change is worth a write. A fleet acknowledging the same version every
	// thirty seconds would otherwise be a steady stream of no-op updates against the
	// rows that hold desired state (ADR-0012).
	if applied == previous && ack.GetError() == "" {
		return
	}
	sess.setApplied(applied)

	if _, err := s.store.Queries().RecordAppliedVersion(ctx, dbgen.RecordAppliedVersionParams{
		MembershipID:   sess.MembershipID,
		AppliedVersion: applied,
		Now:            ptrTime(s.clk.Now()),
		LastError:      ack.GetError(),
		// A nil Go slice becomes SQL NULL rather than an empty array, and the column is
		// NOT NULL — so an agent reporting nothing unapplied, which is the common case,
		// would fail the write.
		UnappliedComponents: nonNilStrings(ack.GetUnappliedComponents()),
	}); err != nil {
		s.log.Warn("could not record applied version", "session", sess.ID, "error", err)
	}
}

// handleHeartbeat answers a liveness check and tells the agent whether it is behind.
func (s *Server) handleHeartbeat(ctx context.Context, sess *Session, hb *meshpv1.Heartbeat) {
	membership, err := s.store.Queries().GetMembershipForSession(ctx, sess.MembershipID)
	if err != nil {
		s.log.Debug("heartbeat could not read state version", "session", sess.ID, "error", err)
		return
	}
	current := uint64(membership.StateVersion)

	// The safety net for a push that never arrived: if the agent is behind, it learns
	// so from the acknowledgement rather than waiting for a notification that was
	// already lost (ADR-0012 requires that a missed notify degrade to latency, not to
	// a permanently stale agent).
	behind := hb.GetAppliedStateVersion() < current
	sess.enqueue(&meshpv1.ServerMessage{
		Payload: &meshpv1.ServerMessage_HeartbeatAck{HeartbeatAck: &meshpv1.HeartbeatAck{
			CurrentStateVersion: current,
			ServerTimeUnixMs:    s.clk.Now().UnixMilli(),
			StateAvailable:      behind,
		}},
	})
	if behind {
		sess.Notify()
	}
}

// --- wire helpers -----------------------------------------------------------

func readClientMessage(ctx context.Context, conn *websocket.Conn) (*meshpv1.ClientMessage, error) {
	typ, data, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, fmt.Errorf("expected a binary frame, got %v", typ)
	}
	var msg meshpv1.ClientMessage
	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("malformed message: %w", err)
	}
	return &msg, nil
}

func writeServerMessage(ctx context.Context, conn *websocket.Conn, msg *meshpv1.ServerMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageBinary, data)
}

// isExpectedClose reports whether an error is a connection ending normally rather
// than something worth logging at info level.
func isExpectedClose(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return true
	}
	return false
}

func ptrTime(t time.Time) *time.Time { return &t }

// nonNilStrings turns a nil slice into an empty one.
//
// PostgreSQL text[] columns declared NOT NULL reject a nil Go slice, because pgx sends
// it as NULL rather than as '{}'. The distinction does not exist in Go, which is why
// this keeps catching people.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
func ptrString(s string) *string { return &s }

// constantTimeEqualBytes compares two byte slices without leaking their contents
// through timing. The keys here are public, so this is caution rather than necessity —
// but a comparison that becomes security-relevant later should already be correct.
func constantTimeEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
