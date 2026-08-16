package tunnel

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/dns"
	"github.com/meshpnet/meshp/internal/peerset"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// recordingNames captures what a reconciler publishes.
type recordingNames struct {
	mu        sync.Mutex
	zones     map[string]dns.Zone
	forgotten []string
}

func newRecordingNames() *recordingNames {
	return &recordingNames{zones: map[string]dns.Zone{}}
}

func (r *recordingNames) Replace(owner string, z dns.Zone) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.zones[owner] = z
}

func (r *recordingNames) Forget(owner string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.zones, owner)
	r.forgotten = append(r.forgotten, owner)
}

func (r *recordingNames) zone(owner string) dns.Zone {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.zones[owner]
}

// namedPeer is a peer with a chosen display name.
func namedPeer(key, deviceName string, ips ...string) *meshpv1.Peer {
	p := peer(key, ips...)
	p.DeviceName = deviceName
	return p
}

// labelled is a peer the server has named, which is the ordinary case.
func labelled(key, label string, ips ...string) *meshpv1.Peer {
	p := namedPeer(key, label, ips...)
	p.DnsLabel = label
	return p
}

// stateWithNames is a peer set carrying a search domain, as the server now sends one.
func stateWithNames(suffix string, peers ...*meshpv1.Peer) *peerset.Set {
	s := peerset.New()
	delta := &meshpv1.StateDelta{
		FromVersion: 0, ToVersion: 1, UpsertPeers: peers,
		Tunnel: &meshpv1.TunnelConfig{Mtu: 1420},
	}
	if suffix != "" {
		delta.Dns = &meshpv1.DnsConfig{SearchDomains: []string{suffix}}
	}
	s.Apply(delta)
	return s
}

// The peers handed to WireGuard are the same data that answers a query — no second source
// and nothing fetched (ADR-0021).
func TestPeersBecomeResolvableNames(t *testing.T) {
	link := newFakeLink()
	names := newRecordingNames()
	r := New(link, membership(), nil, nil, nil).WithNames(names)

	state := stateWithNames("acme.internal",
		labelled(bobKey, "bob", "100.90.0.2/32", "fd7c::2/128"),
		labelled(carolKey, "carol", "100.90.0.3/32"))

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	got := names.zone(membership().InterfaceName)
	if got.Suffix != "acme.internal" {
		t.Fatalf("suffix = %q", got.Suffix)
	}
	var labels []string
	for _, h := range got.Hosts {
		labels = append(labels, h.Name)
	}
	slices.Sort(labels)
	if !slices.Equal(labels, []string{"bob", "carol"}) {
		t.Errorf("hosts = %v", labels)
	}
	for _, h := range got.Hosts {
		if h.Name == "bob" && len(h.Addrs) != 2 {
			t.Errorf("bob has %d addresses, want both families", len(h.Addrs))
		}
	}
}

// A control plane that sends no search domain has not said what this network's names are,
// so there are none. Inventing a suffix here would resolve names the server never mentioned.
func TestNoSearchDomainMeansNoNames(t *testing.T) {
	link := newFakeLink()
	names := newRecordingNames()
	r := New(link, membership(), nil, nil, nil).WithNames(names)

	state := stateWithNames("", labelled(bobKey, "bob", "100.90.0.2/32"))
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	if z := names.zone(membership().InterfaceName); len(z.Hosts) != 0 {
		t.Errorf("published %d names with no search domain", len(z.Hosts))
	}
	if !slices.Contains(names.forgotten, membership().InterfaceName) {
		t.Error("the membership's names were not withdrawn")
	}
}

// A peer whose label the server did not assign, or assigned badly, is left out rather than
// repaired. Repairing would name a device something the server does not think it is called,
// so the name would resolve here and nowhere else.
func TestPeersWithoutAServerAssignedLabelAreLeftOut(t *testing.T) {
	link := newFakeLink()
	names := newRecordingNames()
	r := New(link, membership(), nil, nil, nil).WithNames(names)

	// One the server named, one whose label DNS cannot carry. A peer with no label at all
	// is the same path — ValidLabel refuses the empty string — and is covered by
	// TestValidLabelRejectsWhatDNSCannotCarry rather than duplicated here.
	good := namedPeer(bobKey, "Dave's laptop (spare)", "100.90.0.2/32")
	good.DnsLabel = "dave-s-laptop-spare"
	malformed := namedPeer(carolKey, "printer", "100.90.0.3/32")
	malformed.DnsLabel = "Not A Label"

	state := stateWithNames("acme.internal", good, malformed)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	z := names.zone(membership().InterfaceName)
	if len(z.Hosts) != 1 {
		t.Fatalf("%d hosts published, want only the one with a usable label: %+v", len(z.Hosts), z.Hosts)
	}
	// And the display name is not what resolves — the server's label is.
	if z.Hosts[0].Name != "dave-s-laptop-spare" {
		t.Errorf("published %q, want the server's label", z.Hosts[0].Name)
	}
}

// The whole chain, over a socket: desired state goes into a reconciler, and a real DNS
// query to a real resolver comes back with the peer's address.
//
// End to end for everything this package controls. What it cannot cover is the platform
// data plane — on a host with no WireGuard the reconciler is never constructed at all — so
// the fake link stands in for the kernel and everything above it is the shipping code.
func TestANameResolvesEndToEnd(t *testing.T) {
	zones := dns.NewZones()
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil).WithNames(zones)

	state := stateWithNames("acme.internal",
		labelled(bobKey, "fileserver", "100.90.0.2/32"),
		labelled(carolKey, "printer", "100.90.0.3/32"))
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	server := dns.NewServer(zones, nil)
	if err := server.Bind(netip.MustParseAddrPort("127.0.0.1:0")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(ctx) }()

	got := resolve(t, server.Addr(), "fileserver.acme.internal")
	if got != "100.90.0.2" {
		t.Errorf("fileserver.acme.internal resolved to %q, want 100.90.0.2", got)
	}

	// And a device that left stops resolving, which is what makes a revoked peer's name
	// go away rather than linger.
	shrunk := stateWithNames("acme.internal", labelled(carolKey, "printer", "100.90.0.3/32"))
	if _, err := r.Apply(context.Background(), shrunk); err != nil {
		t.Fatal(err)
	}
	if got := resolve(t, server.Addr(), "fileserver.acme.internal"); got != "" {
		t.Errorf("a peer that is gone still resolves, to %q", got)
	}
	if got := resolve(t, server.Addr(), "printer.acme.internal"); got != "100.90.0.3" {
		t.Errorf("printer stopped resolving too: %q", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the resolver did not stop")
	}
}

// resolve asks the resolver for an A record and returns the address, or "" when there is
// none.
//
// A hand-built query rather than net.Resolver, and that is the fix for a test I first wrote
// the other way. net.Resolver reads the host's /etc/resolv.conf for ndots, attempts and
// timeout even in pure-Go mode, so "a real client" turned out to mean "a client configured
// by whatever machine this runs on" — it passed here and timed out in CI. A test of this
// package must not depend on the resolver configuration of the machine running it.
func resolve(t *testing.T, at netip.AddrPort, name string) string {
	t.Helper()

	conn, err := net.Dial("udp", at.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Header: one question, recursion desired.
	q := []byte{0x2a, 0x2a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root, QTYPE=A, QCLASS=IN

	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no reply from the resolver: %v", err)
	}
	reply := buf[:n]
	if n < 12 {
		t.Fatalf("reply is %d bytes", n)
	}
	if answers := int(reply[6])<<8 | int(reply[7]); answers == 0 {
		return ""
	}

	// Walk past the echoed question, then past the answer's name, to the record data. Both
	// names are uncompressed, because this resolver does not compress.
	off := 12
	for off < len(reply) && reply[off] != 0 {
		off += int(reply[off]) + 1
	}
	off += 5 // root label, qtype, qclass
	for off < len(reply) && reply[off] != 0 {
		off += int(reply[off]) + 1
	}
	off += 1 + 2 + 2 + 4 // root label, type, class, ttl
	if off+2 > len(reply) {
		t.Fatal("reply is truncated before the record length")
	}
	length := int(reply[off])<<8 | int(reply[off+1])
	off += 2
	if off+length > len(reply) {
		t.Fatal("reply is truncated before the address")
	}
	addr, ok := netip.AddrFromSlice(reply[off : off+length])
	if !ok {
		t.Fatalf("record holds %d bytes, which is not an address", length)
	}
	return addr.String()
}
