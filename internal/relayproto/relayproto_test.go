package relayproto

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(b byte) Key {
	var k Key
	for i := range k {
		k[i] = b
	}
	return k
}

func TestAFrameSurvivesARoundTrip(t *testing.T) {
	for _, typ := range []Type{TypeHello, TypeWelcome, TypeRefused, TypeSend, TypeRecv, TypePing, TypePong} {
		t.Run(typ.String(), func(t *testing.T) {
			want := Frame{Type: typ, Key: testKey(0xAB), Payload: []byte("a wireguard packet, notionally")}

			buf := make([]byte, HeaderLen+MaxPayload)
			n, err := want.Encode(buf)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if n != HeaderLen+len(want.Payload) {
				t.Errorf("encoded %d bytes, want %d", n, HeaderLen+len(want.Payload))
			}

			got, err := Decode(buf[:n])
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got.Type != want.Type {
				t.Errorf("type is %s, want %s", got.Type, want.Type)
			}
			if got.Key != want.Key {
				t.Error("the key did not survive")
			}
			if !bytes.Equal(got.Payload, want.Payload) {
				t.Errorf("payload is %q, want %q", got.Payload, want.Payload)
			}
		})
	}
}

// A relay forwarding at volume must not copy a payload per packet, so Decode returns a
// sub-slice of the buffer. That is a deliberate sharing decision and worth pinning: if it
// ever starts copying, the cost is paid on every byte of every customer's traffic.
func TestDecodeDoesNotCopyThePayload(t *testing.T) {
	buf := make([]byte, HeaderLen+4)
	buf[0] = byte(TypeSend)
	copy(buf[HeaderLen:], []byte{1, 2, 3, 4})

	f, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf[HeaderLen] = 9
	if f.Payload[0] != 9 {
		t.Error("the payload was copied; a relay would pay for that on every packet")
	}
}

// A buffer of zeroes is the likeliest thing to arrive by accident — a misdirected datagram,
// a scanner, a bug at the far end. It must not decode into a valid frame.
func TestAllZeroesIsNotAFrame(t *testing.T) {
	if _, err := Decode(make([]byte, 200)); !errors.Is(err, ErrUnknownType) {
		t.Errorf("a datagram of zeroes decoded with %v, want an unknown type", err)
	}
}

func TestShortDatagramsAreRefused(t *testing.T) {
	for _, n := range []int{0, 1, HeaderLen - 1} {
		buf := make([]byte, n)
		if n > 0 {
			buf[0] = byte(TypeSend)
		}
		if _, err := Decode(buf); !errors.Is(err, ErrShort) {
			t.Errorf("a %d-byte datagram decoded with %v, want ErrShort", n, err)
		}
	}
}

// A header with no payload is a valid frame for a type that does not need one, and not for
// a type that does: a hello with no token authenticates nobody, and a data frame with no
// packet is a gap in a WireGuard session that the far end waits out.
func TestPayloadIsRequiredWhereItMeansSomething(t *testing.T) {
	header := make([]byte, HeaderLen)

	for _, typ := range []Type{TypeHello, TypeSend, TypeRecv} {
		header[0] = byte(typ)
		if _, err := Decode(header); !errors.Is(err, ErrEmptyPayload) {
			t.Errorf("an empty %s decoded with %v, want ErrEmptyPayload", typ, err)
		}
	}
	for _, typ := range []Type{TypeWelcome, TypeRefused, TypePing, TypePong} {
		header[0] = byte(typ)
		if _, err := Decode(header); err != nil {
			t.Errorf("an empty %s was refused: %v", typ, err)
		}
	}
}

func TestUnknownTypesAreRefused(t *testing.T) {
	// Everything outside the range this version knows, including the values a later
	// version would use — an agent talking to an older relay should be told, not ignored.
	for _, b := range []byte{0, 8, 9, 100, 255} {
		buf := make([]byte, HeaderLen+1)
		buf[0] = b
		if _, err := Decode(buf); !errors.Is(err, ErrUnknownType) {
			t.Errorf("type %d decoded with %v, want ErrUnknownType", b, err)
		}
	}
}

func TestAnOversizedPayloadIsRefused(t *testing.T) {
	f := Frame{Type: TypeSend, Key: testKey(1), Payload: make([]byte, MaxPayload+1)}
	if _, err := f.Encode(make([]byte, 4096)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("an oversized payload encoded with %v, want ErrTooLarge", err)
	}
	// And exactly at the limit is fine, because an off-by-one here would silently cap the
	// largest packet a tunnel can carry.
	f.Payload = make([]byte, MaxPayload)
	if _, err := f.Encode(make([]byte, 4096)); err != nil {
		t.Errorf("a payload of exactly MaxPayload was refused: %v", err)
	}
}

// Truncation must be an error rather than a short write. A truncated WireGuard packet fails
// authentication at the far end, so the symptom would be a peer that handshakes and then
// goes quiet — with nothing pointing at the relay.
func TestEncodingIntoATooSmallBufferFails(t *testing.T) {
	f := Frame{Type: TypeSend, Key: testKey(2), Payload: []byte("0123456789")}
	if _, err := f.Encode(make([]byte, HeaderLen+len(f.Payload)-1)); err == nil {
		t.Error("a frame was encoded into a buffer too small to hold it")
	}
	if _, err := f.Encode(make([]byte, HeaderLen+len(f.Payload))); err != nil {
		t.Errorf("a frame was refused by a buffer of exactly the right size: %v", err)
	}
}

// The MTU arithmetic, asserted rather than trusted. Getting it wrong produces loss of large
// packets only, which presents as "most things work but some sites hang" — the hardest
// network fault to attribute, and the reason the numbers are written out in the source.
func TestARelayedPacketFitsAConventionalPath(t *testing.T) {
	const (
		ipv6Header = 40
		udpHeader  = 8
		wgOverhead = 32
		path       = 1500
	)

	onTheWire := ipv6Header + udpHeader + HeaderLen + RelayedTunnelMTU + wgOverhead
	if onTheWire > path {
		t.Errorf("a full relayed packet is %d bytes on the wire, over a %d path", onTheWire, path)
	}
	if onTheWire != path {
		t.Errorf("a full relayed packet is %d bytes, leaving %d unused — the MTU is smaller "+
			"than it needs to be, which costs throughput on every relayed byte",
			onTheWire, path-onTheWire)
	}

	// And it is genuinely smaller than a direct path allows, which is the cost being
	// accounted for. 1420 is the conventional direct-path figure.
	if RelayedTunnelMTU >= 1420 {
		t.Errorf("the relayed MTU is %d, which does not account for the relay header",
			RelayedTunnelMTU)
	}

	// A frame holding the largest packet such a tunnel produces must fit MaxPayload.
	if RelayedTunnelMTU+wgOverhead > MaxPayload {
		t.Errorf("a %d-byte tunnel produces packets of %d, over the %d a frame holds",
			RelayedTunnelMTU, RelayedTunnelMTU+wgOverhead, MaxPayload)
	}
}

// Send and recv share a layout and mean opposite ends. The risk is a relay that forwards a
// frame without rewriting it, which would return every packet to its sender — so the types
// must not be interchangeable by accident.
func TestSendAndRecvAreDistinct(t *testing.T) {
	if TypeSend == TypeRecv {
		t.Fatal("send and recv are the same type; a relay could forward without rewriting")
	}
	buf := make([]byte, HeaderLen+1)
	buf[0] = byte(TypeSend)
	buf[HeaderLen] = 1

	f, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeSend {
		t.Errorf("decoded as %s, want send", f.Type)
	}
}

// Decode must not panic, index out of range, or accept anything Validate would refuse,
// whatever arrives on a public UDP port — which is the one part of a relay that anyone on
// the internet can reach without authenticating.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, HeaderLen))
	f.Add(make([]byte, HeaderLen+1))

	for _, typ := range []Type{TypeHello, TypeWelcome, TypeSend, TypeRecv, TypePing, TypePong} {
		buf := make([]byte, HeaderLen+8)
		buf[0] = byte(typ)
		f.Add(buf)
	}

	oversized := make([]byte, HeaderLen+MaxPayload+1)
	oversized[0] = byte(TypeSend)
	f.Add(oversized)

	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := Decode(data)
		if err != nil {
			return
		}

		// Anything that decoded must be something we would send back out, or the two
		// directions disagree about what is valid.
		if err := frame.Validate(); err != nil {
			t.Fatalf("Decode accepted a frame Validate refuses: %v", err)
		}

		// And it must re-encode to exactly what arrived. A decoder that loses or invents a
		// byte in a relay is a corrupted WireGuard packet, which fails authentication far
		// away from the cause.
		out := make([]byte, len(data))
		n, err := frame.Encode(out)
		if err != nil {
			t.Fatalf("a decoded frame would not re-encode: %v", err)
		}
		if n != len(data) || !bytes.Equal(out[:n], data) {
			t.Fatalf("re-encoding changed the datagram:\n got %x\nwant %x", out[:n], data)
		}
	})
}
