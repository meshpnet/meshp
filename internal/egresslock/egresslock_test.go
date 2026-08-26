package egresslock

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/tunnel"
)

// What this package returns is what the reconciler holds.
//
// A compile-time check written as a test, because the thing it guards is a signature: the
// lock is its own interface as of #167, and a change to it that this package did not follow
// would otherwise surface as a build failure in cmd/meshpd rather than here.
func TestWhatThisReturnsIsTheLockTheReconcilerWants(t *testing.T) {
	var _ tunnel.EgressLock = New(t.Context())
}

// A platform that can refuse egress can say how to stop refusing.
//
// The two have to arrive together. ADR-0011 keeps the lock installed across a crash on
// purpose, so the only thing between a killed daemon and a machine somebody has to physically
// recover is the command `meshp doctor` prints — and a platform that grew a lock without
// growing an undo would print nothing at all in exactly that situation.
func TestAPlatformThatCanLockSaysHowToStop(t *testing.T) {
	commands := Undo()

	switch runtime.GOOS {
	case "linux", "darwin":
		if len(commands) == 0 {
			t.Fatal("this platform has a lock and offers no way to take it off by hand")
		}
	default:
		if len(commands) != 0 {
			t.Fatalf("this platform has no lock and offers commands anyway: %v", commands)
		}
		return
	}

	for _, command := range commands {
		if strings.Contains(command, "%!") {
			t.Errorf("%q has a formatting error in it", command)
		}
		if !strings.HasPrefix(command, "sudo ") {
			t.Errorf("%q is printed to somebody at a console and does not ask for root", command)
		}
	}
}

// And the command names something this machine has.
//
// The failure this catches is #156's, in the half of `meshp doctor` that #156 does not
// touch: until macOS grew a lock, both the daemon and the doctor printed `nft delete table`
// on every platform, so a Mac was told to run a program it has never had. A command for the
// wrong operating system is worse than none — whoever reads it is at a console on a machine
// with no network and cannot look anything up.
func TestTheUndoNamesAProgramThisMachineHas(t *testing.T) {
	for _, command := range Undo() {
		fields := strings.Fields(strings.TrimPrefix(command, "sudo "))
		if len(fields) == 0 {
			t.Errorf("%q names no program", command)
			continue
		}
		if _, err := exec.LookPath(fields[0]); err != nil {
			if runtime.GOOS == "darwin" {
				// pfctl is part of macOS. Not finding it means this is printing somebody
				// else's command.
				t.Errorf("%q names %q, which this macOS does not have", command, fields[0])
				continue
			}
			t.Skipf("%q is not installed here, so this machine cannot check its own advice; "+
				"the data plane job has it", fields[0])
		}
	}
}
