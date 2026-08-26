package pf

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// blocked is the range this package's privileged tests refuse.
//
// TEST-NET-1, reserved for documentation and routed nowhere. Everything else is carved out,
// so the only thing a lock installed by a test can stop is traffic to an address that was
// never going to arrive — which matters, because these run on a machine that has to go on
// working afterwards, including if the test dies before its cleanup.
var blocked = netip.MustParsePrefix("192.0.2.0/24")

// root reports whether this run can touch the packet filter, and skips if it cannot.
func root(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("reading and loading pf rules needs root; the privileged CI run covers this")
	}
}

// The claim ADR-0026 rests on, checked against a real macOS on every run.
//
// meshp's rules are nested under Apple's anchor because that is the only anchor point the
// shipped /etc/pf.conf references. If a macOS release renames it, drops the wildcard, or
// stops loading com.apple from a file, meshp's rules go on being loaded and quietly stop
// being evaluated — a device reporting that it fails closed while everything leaks.
//
// This test failing is that change arriving. It is not a bug in the test.
func TestTheAnchorPointADR0026DependsOnIsStillThere(t *testing.T) {
	root(t)

	if !anchorPointPresent(t.Context()) {
		out, _ := exec.Command("pfctl", "-s", "rules").Output()
		t.Fatalf("the main ruleset no longer evaluates anchors nested under %q, so a lock "+
			"loaded into %s would never be looked at.\n\nThis is what ADR-0026 accepts as "+
			"its risk, and it has happened. macOS's anchor arrangement has to be looked at "+
			"again before this platform can fail closed.\n\npfctl -s rules:\n%s",
			anchorPoint, AnchorName, out)
	}
	if New(t.Context()) == nil {
		t.Error("the anchor point is there and this host still says it cannot refuse egress")
	}
}

// A host that cannot read the packet filter says so, rather than finding out at apply time.
//
// The answer decides what the agent claims it can do, and a device that claimed fail-closed
// egress and then failed to install it on every reconcile would be placed in networks that
// require the property and never have it.
func TestWithoutPrivilegeThisHostSaysItCannotLock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this is about what an unprivileged agent reports; the unprivileged CI run covers it")
	}
	if New(t.Context()) != nil {
		t.Error("an agent that cannot read pf reported that it can refuse egress")
	}
	if Held(t.Context()) {
		t.Error("an agent that cannot read pf reported that a lock is installed")
	}
}

// The rendering is what pf will actually take, checked by asking pf.
//
// Unprivileged on purpose: parsing a ruleset needs no access to /dev/pf, so this runs in both
// CI passes and on any developer's Mac. It is the difference between a renderer that produces
// plausible text and one that produces a ruleset.
func TestTheRenderedLockIsSomethingPfWillLoad(t *testing.T) {
	script, err := RenderLock(example())
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if out, err := parseCheck(script); err != nil {
		t.Fatalf("pf will not load the rendered lock: %v\n%s\n--- ruleset\n%s", err, out, script)
	}

	// And the check is not vacuous. A ruleset pf would reject has to be rejected, or this
	// test would go on passing after the renderer started emitting nonsense.
	if _, err := parseCheck("pass out quick on utun7! all\n"); err == nil {
		t.Error("pfctl accepted a ruleset it should have refused, so parsing proves nothing here")
	}
}

// The whole of it: a lock refuses what it does not name, and pf's own accounting says so.
//
// Everything except TEST-NET-1 is carved out, so this proves the anchor is reached and its
// catch-all is enforced without taking the machine off the network for the length of a test.
func TestALockRefusesWhatItDoesNotName(t *testing.T) {
	root(t)
	ctx := t.Context()

	lock := &Lock{}
	// Before anything else, so a failure part-way through still gives the machine back.
	t.Cleanup(func() {
		if err := lock.ApplyLock(context.WithoutCancel(ctx), "", nil, nil, false); err != nil {
			t.Errorf("could not remove the lock this test installed: %v", err)
		}
	})

	// lo0 as the tunnel, because it certainly exists. Which interface carries the tunnel is
	// not what this is testing — whether the anchor is evaluated and its catch-all refuses is.
	if err := lock.ApplyLock(ctx, "lo0", nil, everythingExcept(blocked), false); err != nil {
		t.Fatalf("installing the lock: %v", err)
	}
	if !Held(ctx) {
		t.Fatal("the lock was installed and this host reports no lock")
	}
	if !enabled(ctx) {
		t.Fatal("the rules are loaded and the packet filter is not running, so nothing is " +
			"evaluating them")
	}

	// A packet pf has to decide about. It is going nowhere either way; what matters is that
	// the anchor's catch-all is what stops it.
	conn, err := net.DialTimeout("tcp", "192.0.2.1:443", 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Error("a connection to a refused address succeeded")
	}

	if packets := blockedPackets(t, ctx); packets == 0 {
		t.Error("pf counted nothing against the catch-all, so meshp's rules were not what " +
			"stopped that packet — the anchor is loaded and is not being evaluated")
	}
}

// The lock outlives the process, and is found again and taken off.
//
// ADR-0011 requires the first half: rules that vanished with the daemon would fail open
// exactly when they are needed. Invariant 20 requires the second, and this is the reference
// on pf being enabled — the part with no Linux counterpart, because meshp does not own the
// switch and has to give it back.
func TestTheLockAndTheReferenceOnPfAreBothGivenBack(t *testing.T) {
	root(t)
	ctx := t.Context()

	lock := &Lock{}
	t.Cleanup(func() { _ = lock.ApplyLock(context.WithoutCancel(ctx), "", nil, nil, false) })

	if err := lock.ApplyLock(ctx, "lo0", nil, everythingExcept(blocked), false); err != nil {
		t.Fatalf("installing the lock: %v", err)
	}
	if _, err := os.Stat(tokenPath); err != nil {
		t.Errorf("no reference on pf was remembered at %s: %v\n"+
			"a killed daemon's reference is then one nothing can ever give back, and pf "+
			"stays enabled until the machine reboots", tokenPath, err)
	}

	if err := lock.ApplyLock(ctx, "", nil, nil, false); err != nil {
		t.Fatalf("removing the lock: %v", err)
	}
	if Held(ctx) {
		t.Error("the lock was removed and this host still reports one")
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Errorf("the reference on pf was not given back: %s is still there", tokenPath)
	}

	// And again on a machine that has no lock. The reconciler releases on every pass through
	// a state that does not want one, and `meshp down` releases whether or not anything was
	// ever installed — so a removal that failed when there was nothing to remove would put a
	// error in the log of every device that has never claimed a default route.
	if err := lock.ApplyLock(ctx, "", nil, nil, false); err != nil {
		t.Errorf("removing a lock that is not installed was an error: %v", err)
	}
}

// parseCheck asks pfctl whether it would take a ruleset, without loading it.
func parseCheck(script string) (string, error) {
	cmd := exec.Command("pfctl", "-a", AnchorName, "-n", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// packetCount reads the counters pfctl prints beneath each rule.
var packetCount = regexp.MustCompile(`Packets:\s*(\d+)`)

// blockedPackets is how many packets meshp's catch-all has refused.
//
// Read per rule rather than summed, because every other rule in the anchor is a pass rule
// and the machine's ordinary traffic keeps them busy. Only the catch-all's count says the
// lock refused something.
func blockedPackets(t *testing.T, ctx context.Context) int {
	t.Helper()
	out, err := pfctlOutput(ctx, "-a", AnchorName, "-s", "rules", "-v")
	if err != nil {
		t.Fatalf("reading the anchor's counters: %v", err)
	}

	rule := ""
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			rule = strings.TrimSpace(line)
			continue
		}
		if !strings.HasPrefix(rule, "block") {
			continue
		}
		if match := packetCount.FindStringSubmatch(line); match != nil {
			count, err := strconv.Atoi(match[1])
			if err != nil {
				t.Fatalf("unreadable packet count %q", match[1])
			}
			return count
		}
	}
	t.Fatalf("no counters against a block rule in the anchor. If pfctl's output has changed "+
		"shape this test has to learn the new one rather than be deleted.\n\n%s", out)
	return 0
}

// everythingExcept covers the whole address space apart from one prefix.
//
// The siblings along the path from the root: flipping bit i of the prefix and stopping there
// gives the half of that level the prefix is not in, and together they tile everything else.
func everythingExcept(p netip.Prefix) []netip.Prefix {
	// IPv6 entire, because this is only ever used to leave one IPv4 range refused.
	out := []netip.Prefix{netip.MustParsePrefix("::/0")}
	octets := p.Addr().AsSlice()
	for i := range p.Bits() {
		flipped := append([]byte(nil), octets...)
		flipped[i/8] ^= 1 << (7 - i%8)
		sibling, ok := netip.AddrFromSlice(flipped)
		if !ok {
			continue
		}
		out = append(out, netip.PrefixFrom(sibling, i+1).Masked())
	}
	return out
}
