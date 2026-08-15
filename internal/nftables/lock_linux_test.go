//go:build linux

package nftables

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A lock that renders correctly, loads, and does not actually stop anything is the worst of
// the three outcomes: it reports a property the device does not have, which is the exact
// dishonesty ADR-0011 exists to prevent. So these run against a real kernel and a real nft,
// and the last two assert what a packet does rather than what a ruleset says.

func requireLockableKernel(t *testing.T) {
	t.Helper()
	if !Available(context.Background()) {
		t.Skip("nft is unavailable or unusable here; run this in the privileged container")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 is unavailable; run this in the privileged container")
	}
	t.Cleanup(func() {
		// Never leave a lock behind on a host that ran the tests. This is the cleanup path
		// the feature itself depends on, so a test that skipped it would be leaving the
		// machine in the state the ADR calls the worst bug we can ship.
		if script, err := RenderLock(LockSpec{}); err == nil {
			_ = Apply(context.Background(), script)
		}
	})
}

func lockLoaded(t *testing.T) bool {
	t.Helper()
	return exec.Command("nft", "list", "table", "inet", LockTableName).Run() == nil
}

// The kernel's opinion of the ruleset, which is the only one that counts. Every expression
// here — the reject verb, the port set, the ipv6-icmp match — is one nft could parse
// differently from how the manual reads.
func TestTheKernelAcceptsTheLock(t *testing.T) {
	requireLockableKernel(t)

	spec := LockSpec{
		Interface: "meshp0",
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.7:3478"),
			netip.MustParseAddrPort("[2001:db8::1]:443"),
		},
		Excluded: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}
	script, err := RenderLock(spec)
	if err != nil {
		t.Fatalf("RenderLock: %v", err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("the kernel refused the lock: %v\n%s", err, script)
	}
	if !lockLoaded(t) {
		t.Fatal("the lock applied without error and is not in the kernel")
	}

	out, err := exec.Command("nft", "list", "table", "inet", LockTableName).CombinedOutput()
	if err != nil {
		t.Fatalf("listing: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "policy drop") {
		t.Errorf("the loaded chain does not drop by default:\n%s", out)
	}
}

// Applying twice must be a no-op rather than an accumulation. The reconciler is a loop, so
// anything that grows a rule per pass grows without bound.
func TestApplyingTheLockTwiceChangesNothing(t *testing.T) {
	requireLockableKernel(t)

	spec := LockSpec{Interface: "meshp0", Endpoints: []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.7:3478"),
	}}
	script, err := RenderLock(spec)
	if err != nil {
		t.Fatalf("RenderLock: %v", err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	first, _ := exec.Command("nft", "list", "table", "inet", LockTableName).CombinedOutput()
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	second, _ := exec.Command("nft", "list", "table", "inet", LockTableName).CombinedOutput()

	if string(first) != string(second) {
		t.Errorf("applying the lock twice changed it:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

// Removal, which is the path that decides whether this feature is safe to have at all.
func TestTheLockCanBeTakenOff(t *testing.T) {
	requireLockableKernel(t)

	script, err := RenderLock(LockSpec{Interface: "meshp0"})
	if err != nil {
		t.Fatalf("RenderLock: %v", err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("applying: %v", err)
	}
	if !lockLoaded(t) {
		t.Fatal("the lock is not loaded, so removing it proves nothing")
	}
	// What the agent asks at startup to decide whether it has something to reclaim, and
	// whether to say so. A LockHeld that disagreed with the kernel would either leave a
	// machine locked out or report an outage that never happened.
	if !LockHeld(context.Background()) {
		t.Error("LockHeld reports nothing while a lock is installed")
	}

	off, err := RenderLock(LockSpec{})
	if err != nil {
		t.Fatalf("RenderLock(empty): %v", err)
	}
	if err := Apply(context.Background(), off); err != nil {
		t.Fatalf("removing: %v", err)
	}
	if lockLoaded(t) {
		t.Error("the lock survived its own removal")
	}
	if LockHeld(context.Background()) {
		t.Error("LockHeld still reports a lock after it was removed")
	}

	// And removing one that is not there has to work, because the caller that needs it most
	// is an agent starting up with no idea what its previous life left behind.
	if err := Apply(context.Background(), off); err != nil {
		t.Errorf("removing a lock that was not installed failed: %v", err)
	}
}

// What a packet actually does.
//
// Run inside a namespace with one veth to the host, because a locked chain in the root
// namespace would cut off the machine running the tests — including, on a CI runner, the
// job's own connection. The namespace gives a real routing table, a real interface and a
// real reachable address to be denied.
func TestTheLockStopsAndRestoresRealTraffic(t *testing.T) {
	requireLockableKernel(t)

	const ns = "meshplock"
	const hostIP = "10.98.0.1"
	const nsIP = "10.98.0.2"

	_ = exec.Command("ip", "netns", "del", ns).Run()
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Skipf("cannot create a network namespace here: %v: %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		_ = exec.Command("ip", "link", "del", "vlock0").Run()
	})

	for _, args := range [][]string{
		{"ip", "link", "add", "vlock0", "type", "veth", "peer", "name", "vlock1"},
		{"ip", "addr", "add", hostIP + "/24", "dev", "vlock0"},
		{"ip", "link", "set", "vlock0", "up"},
		{"ip", "link", "set", "vlock1", "netns", ns},
		{"ip", "-n", ns, "addr", "add", nsIP + "/24", "dev", "vlock1"},
		{"ip", "-n", ns, "link", "set", "vlock1", "up"},
		{"ip", "-n", ns, "link", "set", "lo", "up"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
		}
	}

	reaches := func(target string) bool {
		return exec.Command("ip", "netns", "exec", ns,
			"ping", "-c", "1", "-W", "2", target).Run() == nil
	}
	applyInNS := func(t *testing.T, script string) {
		t.Helper()
		cmd := exec.Command("ip", "netns", "exec", ns, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("applying in the namespace: %v: %s\n%s", err, out, script)
		}
	}

	// Without this the rest proves nothing: a lock that blocks traffic which was never
	// flowing is indistinguishable from one that works.
	if !reaches(hostIP) {
		t.Skip("the namespace cannot reach the host before any lock; nothing to prove")
	}

	locked, err := RenderLock(LockSpec{Interface: "meshp0"})
	if err != nil {
		t.Fatalf("RenderLock: %v", err)
	}
	applyInNS(t, locked)
	if reaches(hostIP) {
		t.Error("traffic still left the namespace with the lock on")
	}

	// And it fails audibly rather than hanging. A dropped packet leaves the application
	// waiting out its own timeout and tells the user nothing; the refusal is what ADR-0011
	// means by the error message being the product. Timed rather than matched on text
	// because ping's wording varies: a rejection returns in microseconds over a veth, and
	// the -W 3 below is what a silent drop would cost instead.
	started := time.Now()
	_ = exec.Command("ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "3", hostIP).Run()
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("the lock took %s to refuse a packet, so it is dropping silently rather "+
			"than rejecting; applications will hang instead of failing", elapsed.Round(time.Millisecond))
	}

	// Loopback has to survive, or the lock takes the machine out rather than its egress.
	if !reaches("127.0.0.1") {
		t.Error("the lock broke loopback, which takes the machine out rather than its egress")
	}

	// An exclusion is how the local network keeps working while tunnelled.
	excluded, err := RenderLock(LockSpec{
		Interface: "meshp0",
		Excluded:  []netip.Prefix{netip.MustParsePrefix(hostIP + "/32")},
	})
	if err != nil {
		t.Fatalf("RenderLock: %v", err)
	}
	applyInNS(t, excluded)
	if !reaches(hostIP) {
		t.Error("an excluded prefix was still blocked")
	}

	// And taking the lock off gives the network back. This is the assertion that decides
	// whether the feature is safe to ship: everything above is recoverable only if this
	// works every time.
	off, err := RenderLock(LockSpec{})
	if err != nil {
		t.Fatalf("RenderLock(empty): %v", err)
	}
	applyInNS(t, off)
	if !reaches(hostIP) {
		t.Error("the network did not come back after the lock was removed")
	}
}
