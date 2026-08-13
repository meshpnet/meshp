// Package session terminates the device control channel.
//
// One long-lived duplex connection per network membership carries configuration,
// signalling and telemetry, and never user traffic (Invariant 2). The control plane
// computes desired state; the agent converges toward it and acknowledges the version
// it applied (Invariant 14).
//
// Liveness lives here in memory rather than in PostgreSQL. Whether a device is
// connected right now is ephemeral by definition and losing it costs a reconnect, so
// writing it to the database on every heartbeat would put hundreds of writes per
// second against the same rows that hold desired state (ADR-0012). What does reach
// the database is the applied version, and only when it changes.
package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// sendQueue is how many messages may be outstanding to one agent.
//
// A queue that fills means an agent is not reading, and the right answer is to close
// the connection rather than to buffer indefinitely: it will reconnect and be sent a
// snapshot, which is cheaper than holding memory for a device that may be gone. The
// alternative — blocking the writer — would let one stalled agent hold up the
// goroutine notifying everybody else.
const sendQueue = 16

// Session is one connected membership.
type Session struct {
	// relayMu guards the relay credential, which the read loop writes and nothing else
	// touches today — but a session is reachable from the hub, so the guarantee should not
	// depend on that staying true.
	relayMu  sync.Mutex
	relayTok []byte
	relayExp time.Time

	ID           string
	MembershipID uuid.UUID
	NetworkID    uuid.UUID
	DeviceID     uuid.UUID
	ConnectedAt  time.Time

	send   chan *meshpv1.ServerMessage
	notify chan struct{}

	closeOnce sync.Once
	closed    chan struct{}

	applied atomic.Int64
	// overrun records that the send queue filled, so the reason a session ended is
	// visible in a log rather than inferred.
	overrun atomic.Bool
}

func newSession(id string, membershipID, networkID, deviceID uuid.UUID, now time.Time) *Session {
	return &Session{
		ID:           id,
		MembershipID: membershipID,
		NetworkID:    networkID,
		DeviceID:     deviceID,
		ConnectedAt:  now,
		send:         make(chan *meshpv1.ServerMessage, sendQueue),
		notify:       make(chan struct{}, 1),
		closed:       make(chan struct{}),
	}
}

// AppliedVersion is the last version this agent said it had applied.
func (s *Session) AppliedVersion() int64 { return s.applied.Load() }

func (s *Session) setApplied(v int64) { s.applied.Store(v) }

// relayToken returns the credential this session was last issued, if it holds one.
//
// Kept on the session rather than in the database: it is derivable from the signing key at any
// time, it expires within the hour, and storing a credential that need not be stored is a
// liability with no benefit.
func (s *Session) relayToken() ([]byte, time.Time, bool) {
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	if len(s.relayTok) == 0 {
		return nil, time.Time{}, false
	}
	return s.relayTok, s.relayExp, true
}

func (s *Session) setRelayToken(token []byte, expires time.Time) {
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	s.relayTok, s.relayExp = token, expires
}

// Closed reports the channel that closes when the session ends.
func (s *Session) Closed() <-chan struct{} { return s.closed }

// Close ends the session. Safe to call repeatedly and from several goroutines, which
// matters because the reader, the writer and the hub can each decide it is over.
func (s *Session) Close() {
	s.closeOnce.Do(func() { close(s.closed) })
}

// Overran reports whether the session ended because the agent stopped reading.
func (s *Session) Overran() bool { return s.overrun.Load() }

// enqueue offers a message to the agent, closing the session if it cannot keep up.
func (s *Session) enqueue(msg *meshpv1.ServerMessage) bool {
	// Closed is checked in its own select, first. Putting it alongside the send in one
	// select is wrong in a way that hides: when the session is closed *and* the queue
	// has room, both cases are ready and Go chooses between them at random, so a closed
	// session accepts messages about half the time.
	select {
	case <-s.closed:
		return false
	default:
	}

	select {
	case s.send <- msg:
		return true
	default:
		s.overrun.Store(true)
		s.Close()
		return false
	}
}

// Notify asks the session to send fresh state.
//
// Coalescing rather than queueing: if a nudge is already pending there is no point
// adding another, because what gets sent is whatever the state is when the writer
// gets to it. Ten changes in a second produce one push, not ten.
func (s *Session) Notify() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Hub tracks connected sessions.
type Hub struct {
	mu           sync.RWMutex
	byMembership map[uuid.UUID]*Session
	byNetwork    map[uuid.UUID]map[uuid.UUID]*Session
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{
		byMembership: make(map[uuid.UUID]*Session),
		byNetwork:    make(map[uuid.UUID]map[uuid.UUID]*Session),
	}
}

// Add registers a session and returns any session it displaced.
//
// One session per membership. A second connection for the same membership means the
// device reconnected — after a network change, or because the old connection died in
// a way neither end noticed — so the newcomer wins and the caller closes the old one.
// Keeping both would mean sending each device's state to two connections and taking
// acknowledgements from either.
func (h *Hub) Add(s *Session) *Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	displaced := h.byMembership[s.MembershipID]
	h.byMembership[s.MembershipID] = s
	if h.byNetwork[s.NetworkID] == nil {
		h.byNetwork[s.NetworkID] = make(map[uuid.UUID]*Session)
	}
	h.byNetwork[s.NetworkID][s.MembershipID] = s
	return displaced
}

// Remove deregisters a session, but only if it is still the registered one. A session
// that has already been displaced must not delete its successor on the way out.
func (h *Hub) Remove(s *Session) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if current, ok := h.byMembership[s.MembershipID]; !ok || current != s {
		return
	}
	delete(h.byMembership, s.MembershipID)
	if inNetwork := h.byNetwork[s.NetworkID]; inNetwork != nil {
		delete(inNetwork, s.MembershipID)
		if len(inNetwork) == 0 {
			delete(h.byNetwork, s.NetworkID)
		}
	}
}

// Get returns the session for a membership.
func (h *Hub) Get(membershipID uuid.UUID) (*Session, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.byMembership[membershipID]
	return s, ok
}

// NotifyNetwork nudges every session in a network and reports how many were reached.
//
// Called after any mutation that changes what agents should do. It notifies rather
// than pushes, so the caller is not holding a transaction open while the state for
// every device is computed.
func (h *Hub) NotifyNetwork(networkID uuid.UUID) int {
	h.mu.RLock()
	sessions := make([]*Session, 0, len(h.byNetwork[networkID]))
	for _, s := range h.byNetwork[networkID] {
		sessions = append(sessions, s)
	}
	h.mu.RUnlock()

	// Outside the lock: a notify is non-blocking, but taking a write lock for the
	// duration of a fan-out would stall every connect and disconnect behind it.
	for _, s := range sessions {
		s.Notify()
	}
	return len(sessions)
}

// NotifyMembership nudges one session.
func (h *Hub) NotifyMembership(membershipID uuid.UUID) bool {
	h.mu.RLock()
	s, ok := h.byMembership[membershipID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	s.Notify()
	return true
}

// Count reports how many sessions are connected.
func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.byMembership)
}

// NetworkCount reports how many sessions are connected for a network.
func (h *Hub) NetworkCount(networkID uuid.UUID) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.byNetwork[networkID])
}
