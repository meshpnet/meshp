//go:build linux

package nftables

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The claim ADR-0004 has made since the beginning and that has never been true: one device,
// two customers, both using 192.168.1.0/24, and reaching one of them does not reach the
// other.
//
// Real interfaces, real namespaces, real packets. Every part of this can be made to pass by
// a renderer that produces plausible text — the crossover checks are the ones that cannot,
// because they require the two identical prefixes to actually be distinguishable.
//
// The topology is the smallest one that can be wrong:
//
//	custA (192.168.1.5) --vethA-- [this namespace] --vethB-- custB (192.168.1.5)
func TestTwoCustomersOnTheSamePrefixAreBothReachable(t *testing.T) {
	requireMapRoot(t)
	requireNFT(t)

	const (
		mappedA    = "100.71.5.0/24"
		mappedB    = "100.71.6.0/24"
		custPrefix = "192.168.1.0/24"
	)
	nsA := namespace(t, "mpmapa", "vethA", "inA", "192.168.1.5/24", "100.71.5.1/32")
	nsB := namespace(t, "mpmapb", "vethB", "inB", "192.168.1.5/24", "100.71.6.1/32")

	// The routing table holds the mapped prefixes, which are distinct, so there is nothing
	// for the kernel to contest. This is the whole of ADR-0020's third point.
	mapRun(t, "ip", "route", "add", mappedA, "dev", "vethA", "src", "100.71.5.1")
	mapRun(t, "ip", "route", "add", mappedB, "dev", "vethB", "src", "100.71.6.1")

	// Before the rules, so a pass below means the rules did it. Without this the test would
	// still pass if translation silently never happened and the addresses were reachable
	// some other way.
	if reachable("100.71.5.5:9001") {
		t.Fatal("setup: the mapped address answers before anything was mapped")
	}

	for _, spec := range []struct{ iface, mapped string }{{"vethA", mappedA}, {"vethB", mappedB}} {
		script, err := RenderMap(spec.iface, []Mapping{{
			Mapped: netip.MustParsePrefix(spec.mapped),
			Real:   netip.MustParsePrefix(custPrefix),
		}})
		if err != nil {
			t.Fatal(err)
		}
		// One table for the device, so the second interface must not remove the first's
		// rules. RenderMap rebuilds the table, which is why each interface is applied into
		// its own table name here -- see the note in the failure below.
		applyInto(t, spec.iface, script)
	}

	listen(t, nsA, "192.168.1.5", 9001)
	listen(t, nsB, "192.168.1.5", 9002)
	time.Sleep(300 * time.Millisecond)

	// Each customer is reachable at its own mapped address.
	if !reachable("100.71.5.5:9001") {
		t.Error("customer A is not reachable at its mapped address")
	}
	if !reachable("100.71.6.5:9002") {
		t.Error("customer B is not reachable at its mapped address")
	}

	// And this is the assertion the feature exists for. If the two prefixes were not really
	// disambiguated, one of these would open: both customers listen on 192.168.1.5, so a
	// packet that went to the wrong interface would still find a machine at that address --
	// just the wrong one, on a port it does not serve.
	if reachable("100.71.5.5:9002") {
		t.Error("customer B's port answered at customer A's mapped address: the prefixes are not disambiguated")
	}
	if reachable("100.71.6.5:9001") {
		t.Error("customer A's port answered at customer B's mapped address: the prefixes are not disambiguated")
	}
}

// The source arrives unmodified, which is what ADR-0007 runs on.
//
// The ACL check is inbound, at the destination, against the identity of the device reaching
// it. A translation that rewrote the source would hand every server in every customer's
// network one address for the whole MSP, and flatten every audit log to that address. This
// is asserted separately because a mapping that breaks it still passes every reachability
// check above.
func TestTheCustomerSeesTheRealSource(t *testing.T) {
	requireMapRoot(t)
	requireNFT(t)

	ns := namespace(t, "mpmapsrc", "vethS", "inS", "192.168.1.5/24", "100.71.5.1/32")
	mapRun(t, "ip", "route", "add", "100.71.5.0/24", "dev", "vethS", "src", "100.71.5.1")

	script, err := RenderMap("vethS", []Mapping{{
		Mapped: netip.MustParsePrefix("100.71.5.0/24"),
		Real:   netip.MustParsePrefix("192.168.1.0/24"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	applyInto(t, "vethS", script)

	listen(t, ns, "192.168.1.5", 9101)
	time.Sleep(300 * time.Millisecond)

	// Read from the customer's side: what address did the connection appear to come from?
	seen := connectAndReadPeer(t, ns, "100.71.5.5:9101", 9101)
	if seen == "" {
		t.Fatal("the customer never saw a connection")
	}
	if seen != "100.71.5.1" {
		t.Errorf("the customer saw the connection from %s, want 100.71.5.1 -- the source was rewritten", seen)
	}
}

// A prefix that does not fall on a byte boundary is ordinary in a customer's network, and the
// mask arithmetic is where that goes wrong. A /25 keeps seven host bits, so 100.71.7.130 must
// become 192.168.2.130 and not 192.168.2.2.
func TestAPrefixOffAByteBoundaryIsMappedCorrectly(t *testing.T) {
	requireMapRoot(t)
	requireNFT(t)

	ns := namespace(t, "mpmap25", "veth25", "in25", "192.168.2.130/25", "100.71.7.129/32")
	mapRun(t, "ip", "route", "add", "100.71.7.128/25", "dev", "veth25", "src", "100.71.7.129")

	script, err := RenderMap("veth25", []Mapping{{
		Mapped: netip.MustParsePrefix("100.71.7.128/25"),
		Real:   netip.MustParsePrefix("192.168.2.128/25"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	applyInto(t, "veth25", script)

	listen(t, ns, "192.168.2.130", 9201)
	time.Sleep(300 * time.Millisecond)

	if !reachable("100.71.7.130:9201") {
		t.Error("a /25 mapping did not carry the host part across")
	}
}

// --- helpers ---------------------------------------------------------------------------

func requireMapRoot(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("id", "-u").Output(); err != nil || string(out) != "0\n" {
		t.Skip("needs root")
	}
}

func mapRun(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

// namespace builds one customer: a namespace holding an address, and a veth to reach it by.
func namespace(t *testing.T, name, outer, inner, custAddr, ourAddr string) string {
	t.Helper()
	_ = exec.Command("ip", "netns", "del", name).Run()
	mapRun(t, "ip", "netns", "add", name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })

	mapRun(t, "ip", "link", "add", outer, "type", "veth", "peer", "name", inner)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", outer).Run() })
	mapRun(t, "ip", "link", "set", inner, "netns", name)

	mapRun(t, "ip", "netns", "exec", name, "ip", "addr", "add", custAddr, "dev", inner)
	mapRun(t, "ip", "netns", "exec", name, "ip", "link", "set", inner, "up")
	mapRun(t, "ip", "netns", "exec", name, "ip", "link", "set", "lo", "up")

	// This side never holds an address inside the customer's prefix. It cannot hold one on
	// two interfaces at once, and never needing to is the point of the mapping.
	mapRun(t, "ip", "addr", "add", ourAddr, "dev", outer)
	mapRun(t, "ip", "link", "set", outer, "up")

	// The customer needs a route back to the address it will see as the source.
	ourIP, _, _ := net.ParseCIDR(ourAddr)
	mapRun(t, "ip", "netns", "exec", name, "ip", "route", "add", ourIP.String()+"/32", "dev", inner)
	return name
}

// applyInto installs one interface's rules under a table of its own.
//
// RenderMap rebuilds MapTableName, so two interfaces rendered into the same table would have
// the second erase the first. That is correct for production, where one call carries every
// mapping the device holds, and wrong for this test, which renders per interface to keep each
// case readable. Rewriting the table name is the smaller distortion.
func applyInto(t *testing.T, iface, script string) {
	t.Helper()
	table := MapTableName + "_" + iface
	renamed := strings.ReplaceAll(script, MapTableName, table)
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "inet", table).Run()
	})
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(renamed)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejected the ruleset: %v\n%s\n%s", err, out, renamed)
	}
}

func listen(t *testing.T, ns, addr string, port int) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, "nc", "-l", "-k", "-s", addr, "-p", fmt.Sprint(port))
	if err := cmd.Start(); err != nil {
		t.Skipf("needs nc: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
}

func reachable(hostport string) bool {
	c, err := net.DialTimeout("tcp", hostport, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// connectAndReadPeer opens a connection and asks the customer's side who it came from.
func connectAndReadPeer(t *testing.T, ns, hostport string, port int) string {
	t.Helper()
	// ss inside the namespace reports the peer of the established connection, which is the
	// source address as the customer's kernel sees it -- not as this side believes it sent.
	c, err := net.DialTimeout("tcp", hostport, 3*time.Second)
	if err != nil {
		t.Fatalf("could not connect: %v", err)
	}
	defer func() { _ = c.Close() }()
	time.Sleep(300 * time.Millisecond)

	out, err := exec.Command("ip", "netns", "exec", ns, "ss", "-Htn", "state", "established",
		"sport", fmt.Sprintf("= :%d", port)).Output()
	if err != nil {
		t.Skipf("needs ss: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return ""
	}
	// The peer address is the last column; strip the port.
	peer := fields[len(fields)-1]
	if i := strings.LastIndexByte(peer, ':'); i >= 0 {
		return peer[:i]
	}
	return peer
}
