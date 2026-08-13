// Package relayproto is the framing between an agent and a relay.
//
// A relay forwards WireGuard packets between devices that cannot reach each other
// directly. It must not be able to read what it forwards, which means it cannot work out
// where a packet is going: WireGuard's transport packets carry a receiver index chosen by
// the receiver, and a handshake carries the initiator's static key encrypted. So the
// destination travels outside the WireGuard packet, in a header this package defines
// (ADR-0016).
//
// It is deliberately the smallest thing that works. Every frame is one UDP datagram —
// there is no length prefix, because the datagram already has a length, and inventing one
// would only create a way for the two to disagree. Decoding never allocates for the
// payload: it returns a sub-slice of the buffer it was given, so a relay forwarding at
// volume does no copying per packet.
package relayproto

import (
	"errors"
	"fmt"
)

// KeyLen is the length of a raw WireGuard public key.
const KeyLen = 32

// HeaderLen is the size of every frame's header: one type byte and one key.
const HeaderLen = 1 + KeyLen

// MTU arithmetic.
//
// A relayed packet is a WireGuard packet inside a relay frame inside UDP inside IP, and if
// the total exceeds the path MTU the result is fragmentation or silent loss of large
// packets only — which presents as "most things work but some sites hang", the single
// hardest network fault to attribute. So the numbers are written out rather than guessed.
//
//	1500  a conventional Ethernet path
//	 -40  IPv6 header, the larger of the two so one number is safe for both
//	  -8  UDP header
//	 -33  this package's header (type + key)
//	 -32  WireGuard's own transport header and authentication tag
//	----
//	1387
//
// A direct path pays neither the relay header nor the outer UDP twice and can carry the
// conventional 1420. Relayed traffic cannot, and the server has to know which a peer is
// using before it tells the agent an MTU.
const (
	// MaxPayload is the largest WireGuard packet a frame may carry.
	MaxPayload = 1500 - 40 - 8 - HeaderLen

	// RelayedTunnelMTU is the tunnel MTU that keeps a relayed packet inside a 1500-byte
	// path. Smaller than the 1420 a direct path allows, which is the cost of relaying.
	RelayedTunnelMTU = MaxPayload - 32
)

// Type is what a frame is for.
type Type uint8

const (
	// TypeInvalid is not a frame. Zero is rejected deliberately: a buffer of zeroes is
	// the most likely thing to arrive by accident, and it should not decode.
	TypeInvalid Type = 0

	// TypeHello identifies an agent to a relay. The key is the sender's WireGuard public
	// key and the payload is the token the control plane issued (ADR-0016: the relay holds
	// no copy of the device database and verifies a signature instead).
	TypeHello Type = 1

	// TypeWelcome accepts a hello. The key is the relay's own, and the payload is the
	// address the relay observed the agent at — the server-reflexive candidate, which is
	// the thing that cannot be inferred from the control channel's TCP source address.
	TypeWelcome Type = 2

	// TypeRefused rejects a hello. The payload is a reason, for logs rather than for
	// branching on.
	TypeRefused Type = 3

	// TypeSend carries a WireGuard packet from an agent to a relay. The key is the peer it
	// is *for*.
	TypeSend Type = 4

	// TypeRecv carries a WireGuard packet from a relay to an agent. The key is the peer it
	// came *from*, which is what tells the agent which loopback socket to deliver it on.
	//
	// The same layout as TypeSend with the key meaning the opposite end. Two types rather
	// than one because "the other party" reads clearly in a diagram and disastrously in
	// code: a relay that forwarded a frame without rewriting the key would send every
	// packet back to its sender, and nothing about a single type would have caught it.
	TypeRecv Type = 5

	// TypePing keeps the agent's NAT mapping to the relay open and measures the path. The
	// key is the sender's own; the payload is opaque and echoed back.
	TypePing Type = 6

	// TypePong echoes a ping.
	TypePong Type = 7
)

func (t Type) String() string {
	switch t {
	case TypeHello:
		return "hello"
	case TypeWelcome:
		return "welcome"
	case TypeRefused:
		return "refused"
	case TypeSend:
		return "send"
	case TypeRecv:
		return "recv"
	case TypePing:
		return "ping"
	case TypePong:
		return "pong"
	default:
		return fmt.Sprintf("type(%d)", uint8(t))
	}
}

// carriesPayload reports whether a type is allowed to have one.
//
// Ping and pong carry opaque bytes, hello carries a token, and the data types carry a
// packet — so every type may. This exists for the reverse question: whether an empty
// payload is acceptable, answered per type in Validate.
func (t Type) valid() bool { return t >= TypeHello && t <= TypePong }

// Errors returned by Decode. Distinguished because a relay logs them at different levels:
// a truncated datagram is the internet being the internet, while an unknown type from an
// authenticated agent means the two ends disagree about the protocol.
var (
	// ErrShort means the datagram is smaller than a header.
	ErrShort = errors.New("relayproto: frame is shorter than a header")

	// ErrUnknownType means the type byte is not one this version knows.
	ErrUnknownType = errors.New("relayproto: unknown frame type")

	// ErrTooLarge means the payload will not fit a frame.
	ErrTooLarge = errors.New("relayproto: payload is larger than a frame allows")

	// ErrEmptyPayload means a type that requires a payload arrived without one.
	ErrEmptyPayload = errors.New("relayproto: frame carries no payload")
)

// Key is a raw WireGuard public key.
//
// An array rather than a slice so that a frame cannot be built with a key of the wrong
// length, and so that keys compare and map by value.
type Key [KeyLen]byte

// Frame is one datagram between an agent and a relay.
type Frame struct {
	Type Type

	// Key is the other end: the destination for a send, the source for a recv, and the
	// sender's own for a hello or a ping.
	Key Key

	// Payload is the frame's contents. For the data types it is a WireGuard packet, and
	// after Decode it aliases the buffer that was decoded — so it must be used or copied
	// before that buffer is reused.
	Payload []byte
}

// Encode writes a frame into dst and returns the bytes written.
//
// dst is supplied by the caller so a relay can reuse one buffer per connection rather than
// allocating per packet. A dst that is too small is an error rather than a silent
// truncation: a truncated WireGuard packet fails authentication at the far end, which
// would present as a peer that handshakes and then goes quiet.
func (f Frame) Encode(dst []byte) (int, error) {
	if err := f.Validate(); err != nil {
		return 0, err
	}
	need := HeaderLen + len(f.Payload)
	if len(dst) < need {
		return 0, fmt.Errorf("relayproto: buffer holds %d bytes, frame needs %d", len(dst), need)
	}
	dst[0] = byte(f.Type)
	copy(dst[1:HeaderLen], f.Key[:])
	copy(dst[HeaderLen:], f.Payload)
	return need, nil
}

// Validate reports whether a frame is one that may be sent.
func (f Frame) Validate() error {
	if !f.Type.valid() {
		return fmt.Errorf("%w: %d", ErrUnknownType, uint8(f.Type))
	}
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(f.Payload), MaxPayload)
	}
	switch f.Type {
	case TypeHello, TypeSend, TypeRecv:
		// A hello with no token authenticates nobody, and a data frame with no packet is
		// a hole in a WireGuard session that the far end would wait out.
		if len(f.Payload) == 0 {
			return fmt.Errorf("%w: a %s frame must carry one", ErrEmptyPayload, f.Type)
		}
	}
	return nil
}

// Decode reads a frame from a datagram.
//
// The returned frame's payload aliases buf: nothing is copied, because a relay's whole job
// is forwarding and a copy per packet is a cost paid on every byte of every customer's
// traffic. Callers that keep a payload beyond the next read must copy it themselves.
func Decode(buf []byte) (Frame, error) {
	if len(buf) < HeaderLen {
		return Frame{}, fmt.Errorf("%w: %d bytes, need at least %d", ErrShort, len(buf), HeaderLen)
	}

	f := Frame{Type: Type(buf[0])}
	copy(f.Key[:], buf[1:HeaderLen])
	if payload := buf[HeaderLen:]; len(payload) > 0 {
		f.Payload = payload
	}

	// Validated after parsing rather than before, so the error can say which type it was
	// and how big it was. An unknown type is the interesting case: it means the two ends
	// disagree about the protocol, and that is worth naming rather than dropping.
	if err := f.Validate(); err != nil {
		return Frame{}, err
	}
	return f, nil
}
