package session

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func testSession(networkID uuid.UUID) *Session {
	return newSession(uuid.NewString(), uuid.New(), networkID, uuid.New(), time.Now())
}

func TestHubAddAndRemove(t *testing.T) {
	h := NewHub()
	networkID := uuid.New()
	s := testSession(networkID)

	if displaced := h.Add(s); displaced != nil {
		t.Error("adding to an empty hub displaced something")
	}
	if got, ok := h.Get(s.MembershipID); !ok || got != s {
		t.Error("Get did not return the session that was added")
	}
	if h.Count() != 1 || h.NetworkCount(networkID) != 1 {
		t.Errorf("counts = %d/%d, want 1/1", h.Count(), h.NetworkCount(networkID))
	}

	h.Remove(s)
	if _, ok := h.Get(s.MembershipID); ok {
		t.Error("Get returned a removed session")
	}
	if h.Count() != 0 || h.NetworkCount(networkID) != 0 {
		t.Errorf("counts after removal = %d/%d, want 0/0", h.Count(), h.NetworkCount(networkID))
	}
}

// A device that reconnects before its previous connection was noticed as dead must end
// up with exactly one session, and it must be the new one.
func TestHubReplacesASessionForTheSameMembership(t *testing.T) {
	h := NewHub()
	networkID := uuid.New()

	first := testSession(networkID)
	h.Add(first)

	second := newSession(uuid.NewString(), first.MembershipID, networkID, first.DeviceID, time.Now())
	displaced := h.Add(second)

	if displaced != first {
		t.Fatal("Add did not report the displaced session")
	}
	if got, _ := h.Get(first.MembershipID); got != second {
		t.Error("the hub kept the old session")
	}
	if h.Count() != 1 {
		t.Errorf("Count = %d, want 1", h.Count())
	}
}

// The subtle one: a displaced session tearing down must not delete its replacement.
func TestHubRemoveDoesNotEvictASuccessor(t *testing.T) {
	h := NewHub()
	networkID := uuid.New()

	first := testSession(networkID)
	h.Add(first)
	second := newSession(uuid.NewString(), first.MembershipID, networkID, first.DeviceID, time.Now())
	h.Add(second)

	// This is what the old session's deferred cleanup does.
	h.Remove(first)

	if got, ok := h.Get(first.MembershipID); !ok || got != second {
		t.Fatal("the replacement was evicted by the session it replaced")
	}
	if h.Count() != 1 {
		t.Errorf("Count = %d, want 1", h.Count())
	}
}

func TestHubNotifyNetworkReachesEveryoneInIt(t *testing.T) {
	h := NewHub()
	networkA, networkB := uuid.New(), uuid.New()

	inA := []*Session{testSession(networkA), testSession(networkA), testSession(networkA)}
	for _, s := range inA {
		h.Add(s)
	}
	inB := testSession(networkB)
	h.Add(inB)

	if n := h.NotifyNetwork(networkA); n != 3 {
		t.Errorf("NotifyNetwork reached %d sessions, want 3", n)
	}
	for i, s := range inA {
		select {
		case <-s.notify:
		default:
			t.Errorf("session %d in the network was not notified", i)
		}
	}
	// Networks are isolated: a change in one must not wake the other (Invariant 4).
	select {
	case <-inB.notify:
		t.Error("a session in another network was notified")
	default:
	}
}

// Ten changes in a moment should produce one push, not ten.
func TestNotifyCoalesces(t *testing.T) {
	s := testSession(uuid.New())
	for range 10 {
		s.Notify()
	}

	received := 0
	for {
		select {
		case <-s.notify:
			received++
			continue
		default:
		}
		break
	}
	if received != 1 {
		t.Errorf("%d notifications queued, want 1 coalesced", received)
	}
}

// An agent that stops reading gets disconnected rather than buffered indefinitely: it
// will reconnect and be sent a snapshot, which is cheaper than holding memory for a
// device that may be gone.
func TestSessionClosesWhenTheAgentStopsReading(t *testing.T) {
	s := testSession(uuid.New())

	for i := range sendQueue {
		if !s.enqueue(&meshpv1.ServerMessage{}) {
			t.Fatalf("enqueue failed at %d, inside the queue depth", i)
		}
	}
	if s.enqueue(&meshpv1.ServerMessage{}) {
		t.Fatal("enqueue succeeded past the queue depth")
	}
	if !s.Overran() {
		t.Error("the overrun was not recorded, so the reason for the disconnect is invisible")
	}
	select {
	case <-s.Closed():
	default:
		t.Error("the session was not closed after overrunning")
	}
}

func TestSessionCloseIsIdempotent(t *testing.T) {
	s := testSession(uuid.New())
	// The reader, the writer and the hub can each decide it is over.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); s.Close() }()
	}
	wg.Wait()

	select {
	case <-s.Closed():
	default:
		t.Error("Close did not close the session")
	}
}

func TestEnqueueOnAClosedSessionFails(t *testing.T) {
	s := testSession(uuid.New())
	s.Close()
	if s.enqueue(&meshpv1.ServerMessage{}) {
		t.Error("enqueue succeeded on a closed session")
	}
}

func TestNotifyMembership(t *testing.T) {
	h := NewHub()
	s := testSession(uuid.New())
	h.Add(s)

	if !h.NotifyMembership(s.MembershipID) {
		t.Error("NotifyMembership reported no session")
	}
	select {
	case <-s.notify:
	default:
		t.Error("the session was not notified")
	}
	if h.NotifyMembership(uuid.New()) {
		t.Error("NotifyMembership reported success for an unknown membership")
	}
}

// The hub is read by connects, disconnects and fan-outs at once. Meaningful only under
// -race, which CI enforces.
func TestHubIsConcurrencySafe(t *testing.T) {
	h := NewHub()
	networkID := uuid.New()

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			s := testSession(networkID)
			h.Add(s)
			h.Remove(s)
		}()
		go func() { defer wg.Done(); h.NotifyNetwork(networkID) }()
		go func() { defer wg.Done(); _ = h.Count() }()
	}
	wg.Wait()

	if h.Count() != 0 {
		t.Errorf("Count = %d after every session was removed, want 0", h.Count())
	}
}

// Presence answers for one network, not for whoever happens to be connected.
//
// The MSP case makes this load-bearing rather than pedantic: one control plane holds forty
// customers, and a view of one that listed another's devices would be a cross-tenant leak
// arriving through a monitoring page (ADR-0004).
func TestNetworkPresenceIsScopedToItsNetwork(t *testing.T) {
	hub := NewHub()
	acme, zenith := uuid.New(), uuid.New()

	first := testSession(acme)
	first.setApplied(12)
	hub.Add(first)
	hub.Add(testSession(acme))
	hub.Add(testSession(zenith))

	got := hub.NetworkPresence(acme)
	if len(got) != 2 {
		t.Fatalf("presence for acme has %d entries, want 2", len(got))
	}
	for _, c := range got {
		if c.MembershipID == first.MembershipID && c.AppliedVersion != 12 {
			t.Errorf("applied version = %d, want the 12 the agent reported", c.AppliedVersion)
		}
		if c.ConnectedAt.IsZero() {
			t.Error("connected_at is zero, so a page cannot say how long a device has been up")
		}
	}

	// A network nobody is connected to, and a network that does not exist, are the same
	// answer here on purpose: presence knows who is talking to this process and nothing
	// about which networks exist.
	if got := hub.NetworkPresence(uuid.New()); len(got) != 0 {
		t.Errorf("an unknown network has %d connected devices, want 0", len(got))
	}

	hub.Remove(first)
	if got := hub.NetworkPresence(acme); len(got) != 1 {
		t.Errorf("after a disconnect acme has %d entries, want 1", len(got))
	}
}
