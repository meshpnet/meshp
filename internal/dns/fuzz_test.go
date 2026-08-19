package dns

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// A parser of packets off a socket, without a fuzz target, is a bad trade whatever the
// dependency count it saved. This is the argument in the package comment, honoured.
//
// The properties are the ones that matter for a responder: never panic, never allocate on
// somebody else's say-so, and never answer with something other than what was asked.
func FuzzParseQuery(f *testing.F) {
	f.Add(query(1, "fileserver.acme.internal", TypeA))
	f.Add(query(0, "", TypeA))
	f.Add(query(0xFFFF, "a.b.c.d.e.f.g", TypeAAAA))
	f.Add([]byte{})
	f.Add(make([]byte, headerLen))
	// A compression pointer in the question, which is refused rather than followed.
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1})
	// A label length that runs past the end of the buffer.
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x40, 'a'})

	zones := NewZones()
	zones.Replace("meshp0", Zone{Suffix: "acme.internal", Hosts: []Host{
		{Name: "fileserver", Addrs: []netip.Addr{netip.MustParseAddr("100.90.0.5")}},
	}})

	f.Fuzz(func(t *testing.T, in []byte) {
		q, err := ParseQuery(in)
		if err != nil {
			return
		}

		// A name that parsed must be renderable, or a response cannot echo the question
		// and every client drops the reply as not matching what it sent.
		if len(encodeName(q.Name)) > maxName+2 {
			t.Fatalf("accepted a name that renders to %d bytes: %q", len(encodeName(q.Name)), q.Name)
		}

		// Answering must never produce something a client would refuse to read, and must
		// never exceed what a datagram can carry.
		res := zones.Lookup(q.Name)
		answers := make([]Answer, 0, len(res.Addrs))
		for _, addr := range res.Addrs {
			answers = append(answers, Answer{Addr: addr, TTL: DefaultTTL})
		}
		reply := BuildResponse(q, res.Code, answers)

		if len(reply) > MaxMessage {
			t.Fatalf("built a %d-byte reply to a %d-byte query", len(reply), len(in))
		}
		if len(reply) < headerLen {
			t.Fatalf("built a %d-byte reply, which is shorter than a header", len(reply))
		}
		if binary.BigEndian.Uint16(reply[0:2]) != q.ID {
			t.Fatal("the reply does not carry the query's id")
		}
		if binary.BigEndian.Uint16(reply[2:4])&0x8000 == 0 {
			t.Fatal("the reply is not marked as a response, so two resolvers would loop")
		}
		// The reply must be parseable as far as its own question, or a client cannot
		// match it to what it sent.
		if _, _, err := parseName(reply, headerLen); err != nil {
			t.Fatalf("built a reply whose question will not parse: %v", err)
		}
	})
}
