//go:build linux

package nftables

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

// The defect in #89, and the proof it is fixed.
//
// An advertiser on a host where something else drops forwarded packets rendered a correct
// ruleset, reported the route group applied, and carried nothing. Every chain registered at a
// hook runs and a drop in any of them ends the packet, so meshp's accept in its own table
// never got the chance. Docker leaves exactly this policy on every host it is installed on.
//
// Asserted with a real packet across real interfaces, because the whole failure was a ruleset
// that looked right. The middle step is the one that matters: it must be blocked, or the last
// step proves nothing.
func TestAPacketCrossesDespiteAForeignDropPolicy(t *testing.T) {
	requireMapRoot(t)
	requireNFT(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("needs iptables to install a foreign policy")
	}

	lan := netip.MustParsePrefix("10.50.0.0/24")
	carryLAN(t)
	t.Cleanup(func() { _ = RemoveCarry(context.Background()) })

	if !crossesToLAN(t) {
		t.Fatal("setup: nothing crossed before any policy was installed")
	}

	// What Docker leaves behind, and what an advertiser silently died on.
	mustRun(t, "iptables", "-P", "FORWARD", "DROP")
	t.Cleanup(func() { _ = exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run() })
	if crossesToLAN(t) {
		t.Fatal("setup: a drop policy did not stop anything, so the test below proves nothing")
	}

	if err := ApplyCarry(context.Background(), "vethcarry", []netip.Prefix{lan}); err != nil {
		t.Fatalf("ApplyCarry: %v", err)
	}
	if !crossesToLAN(t) {
		chain, _ := exec.Command("nft", "list", "chain", "ip", "filter", "FORWARD").Output()
		ours, _ := exec.Command("nft", "list", "chain", "ip", "filter", CarryChainName).Output()
		t.Fatalf("a carried prefix still does not cross:\n--- FORWARD ---\n%s\n--- ours ---\n%s", chain, ours)
	}
}

// The jump goes in once, however many times this runs. FORWARD belongs to the host, and a
// reconciler that appended to it every tick would grow somebody else's chain without bound.
func TestTheJumpIsAddedOnlyOnce(t *testing.T) {
	requireMapRoot(t)
	requireNFT(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("needs iptables")
	}
	// The table has to exist for any of this to happen at all.
	mustRun(t, "iptables", "-L", "FORWARD", "-n")
	t.Cleanup(func() { _ = RemoveCarry(context.Background()) })

	lan := []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")}
	for range 5 {
		if err := ApplyCarry(context.Background(), "vethcarry", lan); err != nil {
			t.Fatalf("ApplyCarry: %v", err)
		}
	}

	out, err := exec.Command("nft", "list", "chain", "ip", "filter", "FORWARD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "jump "+CarryChainName); n != 1 {
		t.Errorf("FORWARD holds %d jumps to %s after five passes, want 1:\n%s", n, CarryChainName, out)
	}
}

// And meshp takes itself back out, or a host keeps a chain and a jump for a daemon that has
// gone (Invariant 20).
func TestRemoveTakesMeshpOutOfTheHostsChain(t *testing.T) {
	requireMapRoot(t)
	requireNFT(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("needs iptables")
	}
	mustRun(t, "iptables", "-L", "FORWARD", "-n")

	lan := []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")}
	if err := ApplyCarry(context.Background(), "vethcarry", lan); err != nil {
		t.Fatalf("ApplyCarry: %v", err)
	}
	if err := RemoveCarry(context.Background()); err != nil {
		t.Fatalf("RemoveCarry: %v", err)
	}

	out, _ := exec.Command("nft", "list", "chain", "ip", "filter", "FORWARD").Output()
	if strings.Contains(string(out), CarryChainName) {
		t.Errorf("the host's FORWARD chain still names meshp:\n%s", out)
	}
	if exec.Command("nft", "list", "chain", "ip", "filter", CarryChainName).Run() == nil {
		t.Error("meshp's chain is still in the host's table")
	}
}

// --- topology -----------------------------------------------------------------------------

// carryLAN builds a client and a LAN either side of this host, so a packet has to be
// forwarded to get across.
func carryLAN(t *testing.T) {
	t.Helper()
	for _, ns := range []string{"mpcarrylan", "mpcarrycli"} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}
	mapRun(t, "ip", "netns", "add", "mpcarrylan")
	mapRun(t, "ip", "netns", "add", "mpcarrycli")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", "mpcarrylan").Run()
		_ = exec.Command("ip", "netns", "del", "mpcarrycli").Run()
	})

	mapRun(t, "ip", "link", "add", "vethlan", "type", "veth", "peer", "name", "inlan")
	mapRun(t, "ip", "link", "add", "vethcarry", "type", "veth", "peer", "name", "incli")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "vethlan").Run()
		_ = exec.Command("ip", "link", "del", "vethcarry").Run()
	})

	mapRun(t, "ip", "link", "set", "inlan", "netns", "mpcarrylan")
	mapRun(t, "ip", "link", "set", "incli", "netns", "mpcarrycli")
	mapRun(t, "ip", "addr", "add", "10.50.0.1/24", "dev", "vethlan")
	mapRun(t, "ip", "addr", "add", "10.60.0.1/24", "dev", "vethcarry")
	mapRun(t, "ip", "link", "set", "vethlan", "up")
	mapRun(t, "ip", "link", "set", "vethcarry", "up")

	mapRun(t, "ip", "-n", "mpcarrylan", "addr", "add", "10.50.0.2/24", "dev", "inlan")
	mapRun(t, "ip", "-n", "mpcarrylan", "link", "set", "inlan", "up")
	mapRun(t, "ip", "-n", "mpcarrylan", "route", "add", "default", "via", "10.50.0.1")
	mapRun(t, "ip", "-n", "mpcarrycli", "addr", "add", "10.60.0.2/24", "dev", "incli")
	mapRun(t, "ip", "-n", "mpcarrycli", "link", "set", "incli", "up")
	mapRun(t, "ip", "-n", "mpcarrycli", "route", "add", "default", "via", "10.60.0.1")

	if _, err := EnableForwarding(); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
}

func crossesToLAN(t *testing.T) bool {
	t.Helper()
	return exec.Command("ip", "netns", "exec", "mpcarrycli",
		"ping", "-c", "1", "-W", "2", "10.50.0.2").Run() == nil
}
