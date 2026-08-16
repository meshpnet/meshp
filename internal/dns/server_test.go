package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// serve starts a resolver on a loopback port the kernel picks, and returns where it is.
func serve(t *testing.T, z *Zones) netip.AddrPort {
	t.Helper()
	s := NewServer(z, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx, netip.MustParseAddrPort("127.0.0.1:0")) }()

	deadline := time.Now().Add(5 * time.Second)
	for s.Addr().Port() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the resolver never bound")
		}
		time.Sleep(5 * time.Millisecond)
	}
	addr := s.Addr()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Listen: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the resolver did not stop when its context was cancelled")
		}
	})
	return addr
}

// ask sends a real query over a real socket and returns the raw reply.
func ask(t *testing.T, addr netip.AddrPort, name string, qtype Type) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(query(0x1234, name, qtype)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, MaxMessage)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// query builds a wire-format question, by hand, so the tests do not verify the encoder
// against itself.
func query(id uint16, name string, qtype Type) []byte {
	out := make([]byte, headerLen)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(out[4:6], 1)

	if name != "" {
		for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
	}
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(qtype))
	return binary.BigEndian.AppendUint16(out, uint16(ClassIN))
}

func rcode(reply []byte) RCode { return RCode(binary.BigEndian.Uint16(reply[2:4]) & 0xF) }
func ancount(reply []byte) int { return int(binary.BigEndian.Uint16(reply[6:8])) }

// addrs pulls the answer records out of a reply, so the assertions are about what a client
// would actually receive rather than about internal state.
func addrs(t *testing.T, reply []byte) []netip.Addr {
	t.Helper()
	_, off, err := parseName(reply, headerLen)
	if err != nil {
		t.Fatalf("reply question is malformed: %v", err)
	}
	off += 4 // qtype, qclass

	var out []netip.Addr
	for range ancount(reply) {
		_, next, err := parseName(reply, off)
		if err != nil {
			t.Fatalf("answer name is malformed: %v", err)
		}
		off = next
		if off+10 > len(reply) {
			t.Fatal("answer record is truncated")
		}
		length := int(binary.BigEndian.Uint16(reply[off+8 : off+10]))
		off += 10
		if off+length > len(reply) {
			t.Fatal("answer data is truncated")
		}
		addr, ok := netip.AddrFromSlice(reply[off : off+length])
		if !ok {
			t.Fatalf("answer holds %d bytes, which is not an address", length)
		}
		out = append(out, addr)
		off += length
	}
	return out
}

// The whole thing, over a socket: a query goes in, an address comes back.
func TestARealQueryGetsARealAnswer(t *testing.T) {
	addr := serve(t, twoCustomers(t))

	reply := ask(t, addr, "fileserver.acme.internal", TypeA)
	if got := rcode(reply); got != RCodeSuccess {
		t.Fatalf("rcode = %v", got)
	}
	if binary.BigEndian.Uint16(reply[0:2]) != 0x1234 {
		t.Error("the reply does not carry the query's id, so a client cannot match it")
	}
	got := addrs(t, reply)
	if len(got) != 1 || got[0] != netip.MustParseAddr("100.90.0.5") {
		t.Errorf("answers = %v", got)
	}
}

// A question for A must not be answered with AAAA. Some stubs treat a mismatched type as a
// poisoned answer, and rightly.
func TestOnlyTheAskedFamilyComesBack(t *testing.T) {
	addr := serve(t, twoCustomers(t))

	v4 := addrs(t, ask(t, addr, "fileserver.acme.internal", TypeA))
	if len(v4) != 1 || !v4[0].Is4() {
		t.Errorf("A query answered with %v", v4)
	}
	v6 := addrs(t, ask(t, addr, "fileserver.acme.internal", TypeAAAA))
	if len(v6) != 1 || v6[0].Is4() {
		t.Errorf("AAAA query answered with %v", v6)
	}
}

// A device with no address of the asked family exists and has no such record. That is a
// success with no answers, not NXDOMAIN — the difference tells a client whether to try the
// other family or give up.
func TestNoAddressOfThatFamilyIsNotAMissingName(t *testing.T) {
	addr := serve(t, twoCustomers(t))

	reply := ask(t, addr, "laptop.acme.internal", TypeAAAA)
	if got := rcode(reply); got != RCodeSuccess {
		t.Errorf("rcode = %v, want success with no answers", got)
	}
	if n := ancount(reply); n != 0 {
		t.Errorf("%d answers, want 0", n)
	}
}

// The ambiguity rule, over the wire.
func TestAnAmbiguousNameIsRefusedOverTheWire(t *testing.T) {
	addr := serve(t, twoCustomers(t))

	reply := ask(t, addr, "fileserver", TypeA)
	if got := rcode(reply); got != RCodeRefused {
		t.Errorf("rcode = %v, want REFUSED", got)
	}
	if n := ancount(reply); n != 0 {
		t.Errorf("a refused query carried %d answers", n)
	}
}

// Record types this does not serve are refused rather than answered empty. An empty success
// asserts "this name has no MX", which is a claim about a zone this does not own.
func TestUnservedTypesAreRefused(t *testing.T) {
	addr := serve(t, twoCustomers(t))

	for _, qtype := range []Type{15 /*MX*/, 16 /*TXT*/, 255 /*ANY*/, 12 /*PTR*/} {
		reply := ask(t, addr, "fileserver.acme.internal", qtype)
		if got := rcode(reply); got != RCodeRefused {
			t.Errorf("type %d got %v, want REFUSED", qtype, got)
		}
	}
}

// TCP is not optional: a truncated UDP answer tells the client to retry there, and a client
// that cannot is stuck with whatever fitted in 512 bytes.
func TestTCPAnswersToo(t *testing.T) {
	addr := serve(t, twoCustomers(t))

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	q := query(0x4321, "fileserver.acme.internal", TypeA)
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := conn.Write(append(framed, q...)); err != nil {
		t.Fatal(err)
	}

	var length [2]byte
	if _, err := conn.Read(length[:]); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := conn.Read(reply); err != nil {
		t.Fatal(err)
	}
	if got := rcode(reply); got != RCodeSuccess {
		t.Fatalf("rcode = %v", got)
	}
	if got := addrs(t, reply); len(got) != 1 || got[0] != netip.MustParseAddr("100.90.0.5") {
		t.Errorf("answers = %v", got)
	}
}

// A malformed query gets FORMERR when there is an id to reply to, so a client learns it sent
// nonsense rather than seeing what looks like packet loss and retrying forever.
func TestAMalformedQueryGetsFormErr(t *testing.T) {
	addr := serve(t, twoCustomers(t))

	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// A header claiming one question, and no question after it.
	bad := make([]byte, headerLen)
	binary.BigEndian.PutUint16(bad[0:2], 0xBEEF)
	binary.BigEndian.PutUint16(bad[4:6], 1)
	if _, err := conn.Write(bad); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, MaxMessage)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := rcode(buf[:n]); got != RCodeFormErr {
		t.Errorf("rcode = %v, want FORMERR", got)
	}
	if binary.BigEndian.Uint16(buf[0:2]) != 0xBEEF {
		t.Error("the FORMERR does not carry the query's id")
	}
}

// Listening anywhere but loopback is refused. A resolver on a routable address is one
// anybody on the café Wi-Fi can ask what machines are in your customers' networks.
func TestItRefusesToListenOffLoopback(t *testing.T) {
	s := NewServer(twoCustomers(t), nil)

	// A context that ends, and a result read with a deadline. Listen blocks until its
	// context is done, so a version of this that passed context.Background() would hang
	// rather than fail if the guard were removed — which is exactly what happened when a
	// mutation removed it. A test that hangs on the bug it is checking for is worse than
	// no test: it stalls the suite instead of naming the problem.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx, netip.MustParseAddrPort("0.0.0.0:0")) }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNotLoopback) {
			t.Errorf("err = %v, want ErrNotLoopback", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Listen did not refuse a non-loopback address; it bound and started serving")
	}
}
