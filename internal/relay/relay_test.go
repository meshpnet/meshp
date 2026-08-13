package relay

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/relayproto"
)

// fakeAuth grants tokens of the form "network:keybyte".
type fakeAuth struct{ refuse bool }

func (a fakeAuth) Authenticate(token []byte) (relayproto.Key, string, error) {
	if a.refuse {
		return relayproto.Key{}, "", errors.New("refused by test")
	}
	var network string
	var b int
	if _, err := fmt.Sscanf(string(token), "%s %d", &network, &b); err != nil {
		return relayproto.Key{}, "", fmt.Errorf("malformed test token %q", token)
	}
	return key(byte(b)), network, nil
}

// token is padded to the length a signed token will actually be. A 7-byte fixture made the
// amplification assertion fire on a hello no real agent would send, which is the sort of
// unrealistic fixture that turns a good invariant into a nuisance.
func token(network string, k byte) []byte {
	return []byte(fmt.Sprintf("%s %d %s", network, k, strings.Repeat("s", 96)))
}

func key(b byte) relayproto.Key {
	var out relayproto.Key
	for i := range out {
		out[i] = b
	}
	return out
}

func addr(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

type fixture struct {
	t   *testing.T
	srv *Server
	clk *clock.Fake
	via int // which listening socket the next send arrives on
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clk := clock.NewFake()
	srv, err := New(Config{Auth: fakeAuth{}, SelfKey: key(0xFF), Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, srv: srv, clk: clk}
}

// send encodes a frame, hands it to the server, and returns the replies.
func (f *fixture) send(from netip.AddrPort, frame relayproto.Frame) []Out {
	f.t.Helper()
	buf := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)
	n, err := frame.Encode(buf)
	if err != nil {
		f.t.Fatalf("encoding %s: %v", frame.Type, err)
	}
	out := f.srv.Handle(f.via, from, buf[:n])

	// The property that matters most for something on a public UDP port: a reply must never
	// be larger than what prompted it, or the relay can be pointed at a third party and used
	// to amplify traffic at them. Checked on every single exchange in these tests rather
	// than once, because it is the kind of thing a later change breaks quietly.
	for _, o := range out {
		reply := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)
		rn, err := o.Frame.Encode(reply)
		if err != nil {
			f.t.Fatalf("the server produced an unencodable frame: %v", err)
		}
		if rn > n {
			f.t.Fatalf("amplification: a %d-byte %s produced a %d-byte %s reply",
				n, frame.Type, rn, o.Frame.Type)
		}
	}
	return out
}

// joinVia gets a session established for a key at an address, on a given socket.
func (f *fixture) joinVia(via int, network string, k byte, at string) {
	f.t.Helper()
	previous := f.via
	f.via = via
	defer func() { f.via = previous }()
	f.joinHere(network, k, at)
}

// join gets a session established for a key at an address, on socket 0.
func (f *fixture) join(network string, k byte, at string) {
	f.t.Helper()
	f.joinHere(network, k, at)
}

func (f *fixture) joinHere(network string, k byte, at string) {
	f.t.Helper()
	out := f.send(addr(at), relayproto.Frame{
		Type: relayproto.TypeHello, Key: key(k), Payload: token(network, k),
	})
	if len(out) != 1 || out[0].Frame.Type != relayproto.TypeWelcome {
		f.t.Fatalf("hello for %d was not welcomed: %+v", k, out)
	}
}

func TestAHelloIsWelcomedWithTheAddressTheRelaySees(t *testing.T) {
	f := newFixture(t)

	out := f.send(addr("203.0.113.7:41234"), relayproto.Frame{
		Type: relayproto.TypeHello, Key: key(1), Payload: token("acme", 1),
	})
	if len(out) != 1 {
		t.Fatalf("%d replies, want 1", len(out))
	}
	if out[0].Frame.Type != relayproto.TypeWelcome {
		t.Fatalf("replied with %s, want welcome", out[0].Frame.Type)
	}

	// The reflexive address, which is the thing an agent cannot learn any other way and the
	// reason it talks to a relay before it needs one.
	if got := string(out[0].Frame.Payload); got != "203.0.113.7:41234" {
		t.Errorf("welcome carries %q, want the observed address", got)
	}
	if out[0].To != addr("203.0.113.7:41234") {
		t.Errorf("replied to %s, want the sender", out[0].To)
	}

	if sess, ok := f.srv.Session(key(1)); !ok {
		t.Error("no session was recorded")
	} else if sess.Network != "acme" {
		t.Errorf("session network is %q, want acme", sess.Network)
	}
}

func TestABadTokenIsRefusedAndLeavesNoSession(t *testing.T) {
	clk := clock.NewFake()
	srv, err := New(Config{Auth: fakeAuth{refuse: true}, SelfKey: key(0xFF), Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, srv: srv, clk: clk}

	out := f.send(addr("198.51.100.9:1234"), relayproto.Frame{
		Type: relayproto.TypeHello, Key: key(1), Payload: token("acme", 1),
	})
	if len(out) != 1 || out[0].Frame.Type != relayproto.TypeRefused {
		t.Fatalf("expected a refusal, got %+v", out)
	}
	if _, ok := srv.Session(key(1)); ok {
		t.Error("a refused hello left a session behind")
	}
	// The refusal must not say what was wrong: a relay that explains itself is an oracle for
	// guessing tokens.
	if body := string(out[0].Frame.Payload); body != "refused" {
		t.Errorf("refusal says %q, which tells an attacker more than it should", body)
	}
}

// The token names the key. Without this check, anyone holding any valid token could claim
// any key and have that peer's traffic delivered to them.
func TestAHelloWhoseKeyDoesNotMatchItsTokenIsRefused(t *testing.T) {
	f := newFixture(t)

	out := f.send(addr("198.51.100.9:1234"), relayproto.Frame{
		Type:    relayproto.TypeHello,
		Key:     key(2),           // claiming key 2
		Payload: token("acme", 1), // with a token for key 1
	})
	if len(out) != 1 || out[0].Frame.Type != relayproto.TypeRefused {
		t.Fatalf("a mismatched hello was accepted: %+v", out)
	}
	if _, ok := f.srv.Session(key(2)); ok {
		t.Error("a mismatched hello established a session")
	}
}

func TestAPacketIsForwardedToItsPeerAndNamesItsSender(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")
	f.join("acme", 2, "203.0.113.2:2222")

	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(2), Payload: []byte("a wireguard packet"),
	})
	if len(out) != 1 {
		t.Fatalf("%d replies, want 1 forward", len(out))
	}
	if out[0].To != addr("203.0.113.2:2222") {
		t.Errorf("forwarded to %s, want peer 2", out[0].To)
	}
	if out[0].Frame.Type != relayproto.TypeRecv {
		t.Errorf("forwarded as %s, want recv", out[0].Frame.Type)
	}
	// The rewrite. Forwarding without it would return every packet to its sender, and the
	// receiving agent would have no idea which peer it came from.
	if out[0].Frame.Key != key(1) {
		t.Error("the forwarded frame does not name the sender")
	}
	if string(out[0].Frame.Payload) != "a wireguard packet" {
		t.Error("the payload was altered in transit")
	}
}

// The one policy a relay enforces. ACLs belong at the destination (ADR-0007), but two
// customers sharing infrastructure must never reach each other through it.
func TestForwardingAcrossNetworksIsRefused(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")
	f.join("other-customer", 2, "203.0.113.2:2222")

	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(2), Payload: []byte("packet"),
	})
	if len(out) != 0 {
		t.Errorf("a packet crossed between networks: %+v", out)
	}
	if f.srv.Stats().DroppedOtherNet != 1 {
		t.Error("the cross-network drop was not counted")
	}
}

// A public key is public. If a data frame could move where a key is reachable, anyone could
// have another device's traffic delivered to them by asserting its key — they could not
// decrypt it, but they could deny it and observe it.
func TestAKeyCannotBeHijackedByAnUnauthenticatedSender(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")
	f.join("acme", 2, "203.0.113.2:2222")

	// An attacker asserts key 1 from its own address, without a hello.
	out := f.send(addr("192.0.2.66:6666"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(2), Payload: []byte("packet"),
	})
	if len(out) != 0 {
		t.Errorf("an unauthenticated sender was forwarded for: %+v", out)
	}

	// And peer 1's traffic still goes to peer 1's address, not the attacker's.
	out = f.send(addr("203.0.113.2:2222"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(1), Payload: []byte("reply"),
	})
	if len(out) != 1 || out[0].To != addr("203.0.113.1:1111") {
		t.Errorf("the session was redirected: %+v", out)
	}
}

// Moving is legitimate — NAT mappings change — but it takes a fresh authenticated hello.
func TestAKeyMovesOnANewHello(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")
	f.join("acme", 2, "203.0.113.2:2222")

	f.join("acme", 2, "203.0.113.2:9999") // same key, new mapping

	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(2), Payload: []byte("packet"),
	})
	if len(out) != 1 || out[0].To != addr("203.0.113.2:9999") {
		t.Errorf("the packet did not follow the peer to its new address: %+v", out)
	}
}

// Telling a sender that a key is unknown would make the relay a presence oracle for any key
// anyone cares to guess. Public keys are public, so that is a real enumeration.
func TestSendingToAnUnknownPeerSaysNothing(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")

	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(99), Payload: []byte("packet"),
	})
	if len(out) != 0 {
		t.Errorf("the relay revealed something about an unknown key: %+v", out)
	}
	if f.srv.Stats().DroppedNoPeer != 1 {
		t.Error("the drop was not counted")
	}
}

func TestAPingIsAnsweredWithItsOwnPayload(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")

	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypePing, Key: key(1), Payload: []byte("nonce"),
	})
	if len(out) != 1 || out[0].Frame.Type != relayproto.TypePong {
		t.Fatalf("expected a pong: %+v", out)
	}
	if string(out[0].Frame.Payload) != "nonce" {
		t.Error("the pong does not echo the ping, so a round trip cannot be measured")
	}
}

func TestAPingFromNobodyIsIgnored(t *testing.T) {
	f := newFixture(t)
	out := f.send(addr("192.0.2.1:1"), relayproto.Frame{
		Type: relayproto.TypePing, Key: key(1), Payload: []byte("x"),
	})
	if len(out) != 0 {
		t.Errorf("an unauthenticated ping was answered, which is a reflector: %+v", out)
	}
}

// Noise on a public port must produce nothing at all.
func TestGarbageIsDroppedSilently(t *testing.T) {
	f := newFixture(t)
	for _, datagram := range [][]byte{
		{},
		{0},
		make([]byte, 5),
		make([]byte, 2000),
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
	} {
		if out := f.srv.Handle(0, addr("192.0.2.9:9"), datagram); len(out) != 0 {
			t.Errorf("%d bytes of garbage produced a reply: %+v", len(datagram), out)
		}
	}
	if f.srv.Stats().DroppedUndecodable == 0 {
		t.Error("undecodable datagrams were not counted")
	}
}

// The frames a relay emits are not frames it accepts. A peer sending one is confused or
// probing, and either way there is nothing to say.
func TestTheRelayDoesNotAnswerItsOwnFrameTypes(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")

	for _, typ := range []relayproto.Type{
		relayproto.TypeWelcome, relayproto.TypeRefused, relayproto.TypeRecv, relayproto.TypePong,
	} {
		payload := []byte("x")
		out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{Type: typ, Key: key(1), Payload: payload})
		if len(out) != 0 {
			t.Errorf("a %s was answered: %+v", typ, out)
		}
	}
}

func TestSessionsExpireWhenNothingIsHeard(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")
	f.join("acme", 2, "203.0.113.2:2222")

	f.clk.Advance(DefaultIdle - time.Second)
	// Peer 1 is still talking; peer 2 has gone quiet.
	f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypePing, Key: key(1), Payload: []byte("x"),
	})
	f.clk.Advance(2 * time.Second)

	if gone := f.srv.Expire(); gone != 1 {
		t.Errorf("expired %d sessions, want 1", gone)
	}
	if _, ok := f.srv.Session(key(1)); !ok {
		t.Error("the active session was expired")
	}
	if _, ok := f.srv.Session(key(2)); ok {
		t.Error("the idle session survived")
	}
}

// A session past its idle time is unusable even before Expire runs, or a relay that has not
// swept recently would keep forwarding to an address nobody is listening at.
func TestAStaleSessionCannotSendBeforeItIsSwept(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")
	f.join("acme", 2, "203.0.113.2:2222")

	f.clk.Advance(DefaultIdle + time.Minute)

	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(2), Payload: []byte("packet"),
	})
	if len(out) != 0 {
		t.Errorf("a stale session forwarded: %+v", out)
	}
}

func TestARelayWithoutAnAuthenticatorIsRefused(t *testing.T) {
	if _, err := New(Config{SelfKey: key(1)}); err == nil {
		t.Error("a relay was built with no authenticator, which is an open proxy")
	}
}

// Forwarding a maximum-sized payload must work: the largest WireGuard packet a relayed
// tunnel produces has to fit, or large packets are lost and only large ones — the symptom
// that gets diagnosed as anything but the relay.
func TestAMaximumSizedPacketIsForwarded(t *testing.T) {
	f := newFixture(t)
	f.join("acme", 1, "203.0.113.1:1111")
	f.join("acme", 2, "203.0.113.2:2222")

	payload := make([]byte, relayproto.MaxPayload)
	for i := range payload {
		payload[i] = byte(i)
	}
	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(2), Payload: payload,
	})
	if len(out) != 1 {
		t.Fatalf("a full-sized packet was not forwarded: %+v", out)
	}
	if len(out[0].Frame.Payload) != relayproto.MaxPayload {
		t.Errorf("forwarded %d bytes, want %d", len(out[0].Frame.Payload), relayproto.MaxPayload)
	}
}

// The amplification case in full. The rule is not "never reply" — it is "never reply with
// more bytes than arrived", so a relay cannot be pointed at a spoofed source address and used
// to bounce larger packets at someone. Asserted here across the smallest datagrams that
// decode, where the margin is tightest.
func TestARelayNeverRepliesWithMoreThanItReceived(t *testing.T) {
	f := newFixture(t)

	// A refusal is 33 bytes of header plus "refused", so anything under that gets nothing.
	const refusalSize = relayproto.HeaderLen + len("refused")

	for size := 1; size <= 32; size++ {
		frame := relayproto.Frame{Type: relayproto.TypeHello, Key: key(1), Payload: make([]byte, size)}
		buf := make([]byte, relayproto.HeaderLen+size)
		n, err := frame.Encode(buf)
		if err != nil {
			t.Fatal(err)
		}

		out := f.srv.Handle(0, addr("192.0.2.50:5050"), buf[:n])
		for _, o := range out {
			reply := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)
			rn, err := o.Frame.Encode(reply)
			if err != nil {
				t.Fatal(err)
			}
			if rn > n {
				t.Errorf("a %d-byte hello produced a %d-byte reply", n, rn)
			}
		}
		if n < refusalSize && len(out) != 0 {
			t.Errorf("a %d-byte hello, too small for even a refusal, got %d replies", n, len(out))
		}
	}

	// Silent refusals are still counted, so an operator can see them happening.
	if f.srv.Stats().HelloRefused == 0 {
		t.Error("refusals are invisible in the counters")
	}
}

// A relay listens on several ports, because networks exist that block UDP 443 while
// permitting 3478 — verified against a real network, not hypothesised. Two peers may
// therefore be talking to different sockets, and a forwarded packet has to leave by the one
// its destination is using: a peer's NAT only accepts a datagram whose source is the address
// it sent to. Getting this wrong yields a relay that works only when both peers happen to
// choose the same port, which is most of the time in testing and not in the field.
func TestAForwardedPacketLeavesByTheDestinationsSocket(t *testing.T) {
	f := newFixture(t)
	f.joinVia(0, "acme", 1, "203.0.113.1:1111") // peer 1 on socket 0, say udp/3478
	f.joinVia(1, "acme", 2, "203.0.113.2:2222") // peer 2 on socket 1, say udp/443

	// 1 -> 2 must leave by socket 1.
	f.via = 0
	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(2), Payload: []byte("packet"),
	})
	if len(out) != 1 {
		t.Fatalf("expected one forward, got %+v", out)
	}
	if out[0].Via != 1 {
		t.Errorf("forwarded via socket %d, want 1 — the socket peer 2 is talking to", out[0].Via)
	}

	// And 2 -> 1 must leave by socket 0.
	f.via = 1
	out = f.send(addr("203.0.113.2:2222"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(1), Payload: []byte("packet"),
	})
	if len(out) != 1 || out[0].Via != 0 {
		t.Errorf("the reverse direction went via %+v, want socket 0", out)
	}
}

// Replies to the sender go back out the way they came, for the same reason.
func TestRepliesLeaveByTheSocketTheyArrivedOn(t *testing.T) {
	f := newFixture(t)
	f.joinVia(2, "acme", 1, "203.0.113.1:1111")

	f.via = 2
	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypePing, Key: key(1), Payload: []byte("x"),
	})
	if len(out) != 1 || out[0].Via != 2 {
		t.Errorf("a pong left by %+v, want socket 2", out)
	}
}

// A peer that reconnects on a different port moves sockets as well as addresses — a NAT
// rebinding, or an agent that fell back from 443 to 3478 because the first was blocked.
func TestAPeerThatMovesSocketsIsFollowed(t *testing.T) {
	f := newFixture(t)
	f.joinVia(0, "acme", 1, "203.0.113.1:1111")
	f.joinVia(0, "acme", 2, "203.0.113.2:2222")

	// Peer 2 comes back on another port.
	f.joinVia(1, "acme", 2, "203.0.113.2:3333")

	f.via = 0
	out := f.send(addr("203.0.113.1:1111"), relayproto.Frame{
		Type: relayproto.TypeSend, Key: key(2), Payload: []byte("packet"),
	})
	if len(out) != 1 {
		t.Fatalf("expected a forward, got %+v", out)
	}
	if out[0].Via != 1 || out[0].To != addr("203.0.113.2:3333") {
		t.Errorf("forwarded to %s via socket %d, want 203.0.113.2:3333 via 1",
			out[0].To, out[0].Via)
	}
}
