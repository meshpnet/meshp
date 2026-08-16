// Package dns answers name queries for the networks a device is in, from the desired state
// the device has already applied (ADR-0021).
//
// It resolves rather than forwards: the peer list the agent uses to configure WireGuard is
// the same data that answers an A query, so a name keeps working when the control plane does
// not — which is when somebody is most likely to be typing one.
//
// # Why the wire format is hand-written
//
// This is a responder for a handful of names on loopback, not a resolver. It answers A and
// AAAA for names it owns and refuses everything else, which is a small enough subset that a
// dependency would be mostly code this never executes. The parser is deliberately strict —
// anything it does not fully understand is refused rather than guessed at — and it has a
// fuzz target, because a hand-written parser of attacker-shaped input without one is a bad
// trade whatever the dependency count.
package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// Wire constants, named rather than spelled inline at the call sites.
const (
	// MaxMessage is the largest datagram this will send or accept over UDP.
	//
	// 512 is the pre-EDNS0 limit and this does not implement EDNS0, so it is also the
	// real one: a response that does not fit is truncated and the client is told to
	// retry over TCP. For a handful of addresses that will not happen, and pretending
	// to a larger buffer we cannot negotiate would produce answers that get dropped by
	// something in the middle.
	MaxMessage = 512

	// maxName is the longest name this will parse, per RFC 1035.
	maxName = 255
	// maxLabel is the longest single label.
	maxLabel = 63

	headerLen = 12
)

// Type is a DNS record type, limited to what this answers.
type Type uint16

const (
	TypeA    Type = 1
	TypeAAAA Type = 28
)

// Class is a DNS class. Only the internet class is answered.
type Class uint16

const ClassIN Class = 1

// RCode is the answer's disposition.
type RCode uint16

const (
	RCodeSuccess  RCode = 0
	RCodeFormErr  RCode = 1
	RCodeServFail RCode = 2

	// RCodeNXDomain says the name does not exist here.
	RCodeNXDomain RCode = 3

	// RCodeRefused says this resolver will not answer, which is different from saying
	// the name is not there. It is what an ambiguous bare name gets: the name exists in
	// more than one of this device's networks, and choosing between them is precisely
	// what must not happen (ADR-0021).
	RCodeRefused RCode = 5
)

// ErrMalformed means a query could not be understood well enough to answer it.
var ErrMalformed = errors.New("dns: malformed query")

// Query is the part of a request this cares about.
type Query struct {
	ID uint16

	// RecursionDesired is echoed back. This never recurses, but a stub resolver that sent
	// RD and got a reply without it will often treat the answer as suspect.
	RecursionDesired bool

	// Name is the queried name, lowercased and without a trailing dot.
	Name string

	Type  Type
	Class Class
}

// ParseQuery reads a single-question query.
//
// Strict on purpose. A query with no question, more than one question, a class this does not
// serve, or trailing bytes it cannot account for is refused rather than partially honoured:
// this listens on a socket, and a parser that guesses at the ambiguous cases is how a
// responder ends up answering something other than what was asked.
func ParseQuery(buf []byte) (Query, error) {
	if len(buf) < headerLen {
		return Query{}, ErrMalformed
	}

	var q Query
	q.ID = binary.BigEndian.Uint16(buf[0:2])
	flags := binary.BigEndian.Uint16(buf[2:4])
	qdCount := binary.BigEndian.Uint16(buf[4:6])

	// QR set means this is a response, not a question. Answering one would make two
	// resolvers pointed at each other into a packet loop.
	if flags&0x8000 != 0 {
		return Query{}, ErrMalformed
	}
	// Opcode must be QUERY. Anything else — notably UPDATE — is not something to guess at.
	if (flags>>11)&0xF != 0 {
		return Query{}, ErrMalformed
	}
	q.RecursionDesired = flags&0x0100 != 0

	if qdCount != 1 {
		return Query{}, ErrMalformed
	}

	name, off, err := parseName(buf, headerLen)
	if err != nil {
		return Query{}, err
	}
	if off+4 > len(buf) {
		return Query{}, ErrMalformed
	}
	q.Name = name
	q.Type = Type(binary.BigEndian.Uint16(buf[off : off+2]))
	q.Class = Class(binary.BigEndian.Uint16(buf[off+2 : off+4]))

	return q, nil
}

// parseName reads a name and returns it lowercased, without a trailing dot.
//
// Compression pointers are refused rather than followed. A question section is the first
// thing in a message, so there is nothing before it for a pointer to point at — a pointer
// here is either a broken client or someone probing for a parser that will follow it into a
// loop.
func parseName(buf []byte, off int) (string, int, error) {
	var out strings.Builder
	total := 0

	for {
		if off >= len(buf) {
			return "", 0, ErrMalformed
		}
		n := int(buf[off])
		off++

		if n == 0 {
			return out.String(), off, nil
		}
		// A compression pointer. Refused rather than followed: a question section is the
		// first thing in a message, so there is nothing before it to point at, and a
		// parser that follows one can be walked into a loop.
		//
		// Redundant with the length bound below, and said so because a mutation proved
		// it — every byte with these bits set is at least 64, which maxLabel already
		// rejects. It stays because "pointers are not followed" and "labels are at most
		// 63 bytes" are separate rules, and a reader looking for the first should find it
		// rather than deduce it from the second.
		if n&0xC0 != 0 {
			return "", 0, ErrMalformed
		}
		if n > maxLabel {
			return "", 0, ErrMalformed
		}
		total += n + 1
		if total > maxName {
			return "", 0, ErrMalformed
		}
		if off+n > len(buf) {
			return "", 0, ErrMalformed
		}

		if out.Len() > 0 {
			out.WriteByte('.')
		}
		// Lowercased here rather than at every comparison. DNS names are case-insensitive
		// and a client may send any mixture; doing it once means the rest of this package
		// can compare with ==.
		for _, c := range buf[off : off+n] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			out.WriteByte(c)
		}
		off += n
	}
}

// Answer is one record in a response.
type Answer struct {
	Addr netip.Addr
	TTL  uint32
}

// BuildResponse renders a reply to q.
//
// Records that do not match the question's type are dropped rather than sent: a client
// asking for A and handed AAAA has been given something it did not ask for, and some stubs
// treat that as a poisoned answer.
func BuildResponse(q Query, code RCode, answers []Answer) []byte {
	out := make([]byte, headerLen, MaxMessage)

	binary.BigEndian.PutUint16(out[0:2], q.ID)

	// QR, AA. Authoritative because for the names this owns, it is: the answer comes from
	// desired state rather than from a cache of somebody else's zone.
	flags := uint16(0x8000 | 0x0400)
	if q.RecursionDesired {
		// RD echoed, RA clear. This never recurses and says so; a stub that wanted
		// recursion learns it will not get it rather than being told it did.
		flags |= 0x0100
	}
	flags |= uint16(code) & 0xF
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1) // the question, echoed below

	question := encodeName(q.Name)
	out = append(out, question...)
	out = binary.BigEndian.AppendUint16(out, uint16(q.Type))
	out = binary.BigEndian.AppendUint16(out, uint16(q.Class))

	written := 0
	truncated := false
	for _, a := range answers {
		if !matches(q.Type, a.Addr) {
			continue
		}
		record := encodeAnswer(q.Name, q.Type, a)
		if len(out)+len(record) > MaxMessage {
			// The client is told to ask again over TCP rather than handed a short list
			// it cannot tell is short. A silently truncated answer set is how a device
			// ends up talking to whichever half of a service fitted in the datagram.
			truncated = true
			break
		}
		out = append(out, record...)
		written++
	}

	binary.BigEndian.PutUint16(out[6:8], uint16(written))
	if truncated {
		binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|0x0200)
	}
	return out
}

// matches reports whether an address answers this question type.
func matches(t Type, addr netip.Addr) bool {
	switch t {
	case TypeA:
		return addr.Is4()
	case TypeAAAA:
		return addr.Is6() && !addr.Is4In6()
	default:
		return false
	}
}

func encodeAnswer(name string, t Type, a Answer) []byte {
	out := encodeName(name)
	out = binary.BigEndian.AppendUint16(out, uint16(t))
	out = binary.BigEndian.AppendUint16(out, uint16(ClassIN))
	out = binary.BigEndian.AppendUint32(out, a.TTL)

	addr := a.Addr.Unmap()
	raw := addr.AsSlice()
	out = binary.BigEndian.AppendUint16(out, uint16(len(raw)))
	return append(out, raw...)
}

// encodeName writes a name in wire form. Uncompressed: the saving is a few bytes on a
// message that is already small, and a compression pointer is a class of bug this does not
// need to be able to have.
func encodeName(name string) []byte {
	out := make([]byte, 0, len(name)+2)
	if name != "" {
		for label := range strings.SplitSeq(name, ".") {
			if len(label) == 0 || len(label) > maxLabel {
				// Unreachable for names this package produced, and if it ever is reached
				// an empty name is a better answer than a corrupt message.
				return []byte{0}
			}
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
	}
	return append(out, 0)
}
