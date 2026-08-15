package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/nftables"
	"github.com/meshpnet/meshp/internal/wglink"
)

// capture runs report and returns what a person would see.
func capture(t *testing.T, f findings) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	report(f, "/run/meshp/meshpd.sock")
	_ = w.Close()
	os.Stdout = original

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading: %v", err)
	}
	return buf.String()
}

// The case this command exists for, and the one ADR-0011 predicts the support ticket about.
// Whoever is reading this is at a console on a machine that cannot reach anything, so the
// exact commands have to be on the screen — they cannot look them up.
func TestAStrandedMachineIsToldHowToFixItByHand(t *testing.T) {
	out := capture(t, findings{locked: true, claimed: true})

	for _, want := range []struct{ text, why string }{
		{"nft delete table inet " + nftables.LockTableName,
			"the exact command, because there is no way to search for it"},
		{"ip rule del fwmark", "the routing half, which the firewall command does not undo"},
		{"systemctl start meshpd", "the thing to try first, which fixes it without root surgery"},
	} {
		if !strings.Contains(out, want.text) {
			t.Errorf("missing %q\n  needed because: %s\n\n%s", want.text, want.why, out)
		}
	}

	// And it says why, or it reads as a malfunction rather than the feature working.
	if !strings.Contains(out, "meshpd is not running") {
		t.Error("the output does not say what is missing")
	}
}

// Only the parts that are actually installed. Telling someone to remove a table that is not
// there teaches them the output is guesswork, and the next instruction gets ignored too.
func TestOnlyTheRelevantUndoIsOffered(t *testing.T) {
	lockOnly := capture(t, findings{locked: true})
	if strings.Contains(lockOnly, "ip rule del") {
		t.Errorf("offered to remove routing rules that are not installed:\n%s", lockOnly)
	}

	routeOnly := capture(t, findings{claimed: true})
	if strings.Contains(routeOnly, "nft delete table") {
		t.Errorf("offered to remove a firewall table that is not installed:\n%s", routeOnly)
	}
}

// A working full tunnel also refuses traffic. Reporting that as a fault would train people
// to ignore this command on exactly the machines where it matters.
func TestAWorkingFullTunnelIsNotAFault(t *testing.T) {
	f := findings{locked: true, claimed: true, daemonUp: true, enrolled: true,
		sessions: 1, interfaces: 1}
	if f.strandedEgress() {
		t.Fatal("a healthy full tunnel was diagnosed as stranded")
	}

	out := capture(t, f)
	if strings.Contains(out, "nft delete table") {
		t.Errorf("a healthy machine was told to tear down its own protection:\n%s", out)
	}
	if !strings.Contains(out, "on purpose") {
		t.Errorf("the output does not explain that the refusal is deliberate:\n%s", out)
	}
}

// A device that is blocking and has no tunnel is a real situation and the worst one to be
// silent about: nothing gets out at all, and the reason is not obvious from the outside.
func TestALockedMachineWithNoTunnelSaysSo(t *testing.T) {
	out := capture(t, findings{locked: true, claimed: true, daemonUp: true, enrolled: true})

	if !strings.Contains(out, "No tunnel is up") {
		t.Errorf("a device blocking with no tunnel did not say so:\n%s", out)
	}
}

// meshp not being the problem is an answer worth giving plainly. Someone runs this because
// their network is broken, and "it is not us" saves them looking here.
func TestAnIdleMachineSaysMeshpIsNotTheCause(t *testing.T) {
	out := capture(t, findings{})

	if !strings.Contains(out, "not blocking anything") {
		t.Errorf("a machine meshp is not touching was not told so:\n%s", out)
	}
	if strings.Contains(out, "nft delete") {
		t.Errorf("offered surgery on a machine with nothing installed:\n%s", out)
	}
}

// The stranded case is the only fault. Everything else is a description.
func TestOnlyAStrandedMachineIsAFault(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    findings
		want bool
	}{
		{"locked with no daemon", findings{locked: true}, true},
		{"route claimed with no daemon", findings{claimed: true}, true},
		{"healthy full tunnel", findings{locked: true, claimed: true, daemonUp: true}, false},
		{"daemon down and nothing installed", findings{}, false},
		{"running and idle", findings{daemonUp: true, enrolled: true}, false},
	} {
		if got := tc.f.strandedEgress(); got != tc.want {
			t.Errorf("%s: strandedEgress = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The mark has to be printed the way `ip` expects it, or the command on the screen does not
// work when typed — which is the only thing this command is for.
func TestTheMarkIsPrintedAsIpExpectsIt(t *testing.T) {
	out := capture(t, findings{claimed: true})

	if !strings.Contains(out, "fwmark 0x6d657368") {
		t.Errorf("the mark is not in the hex form `ip rule` takes:\n%s", out)
	}
	if !strings.Contains(out, "flush table 1835365224") {
		t.Errorf("the table is not in the decimal form `ip route` takes:\n%s", out)
	}
	// And the two agree, since one number is used for both by design.
	if wglink.EgressMark != wglink.EgressTable {
		t.Error("the mark and the table have drifted apart")
	}
}
