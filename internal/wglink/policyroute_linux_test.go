//go:build linux

package wglink

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The routing mechanism from ADR-0019, against a real kernel.
//
// These assert routing decisions rather than traffic, using `ip route get`, which answers
// the question the kernel would ask itself for a packet — including with a mark, which is
// the whole point here. That makes the three cases directly observable without a WireGuard
// device, a relay, or anything to send.
//
// Everything runs inside a namespace. Installing these rules in the root namespace would
// send the machine's own traffic into a table whose default route is a dummy interface,
// which on a CI runner takes away the connection the job is reporting over.

const (
	prns    = "meshproute" // the namespace
	prTun   = "meshptun0"  // stands in for the tunnel
	prGW    = "10.97.0.1"
	prOther = "8.8.8.8"
)

func prRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"netns", "exec", prns}, args...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func prMust(t *testing.T, args ...string) string {
	t.Helper()
	out, err := prRun(t, args...)
	if err != nil {
		t.Fatalf("ip netns exec %s %s: %v: %s", prns, strings.Join(args, " "), err, out)
	}
	return out
}

// routeFor asks the kernel where a packet would go, optionally carrying the mark.
func routeFor(t *testing.T, dest string, mark bool) string {
	t.Helper()
	args := []string{"ip", "route", "get", dest}
	if mark {
		args = append(args, "mark", "0x6d657368")
	}
	out, err := prRun(t, args...)
	if err != nil {
		t.Fatalf("route get %s (mark=%v): %v: %s", dest, mark, err, out)
	}
	return out
}

func setupPolicyRouteNS(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 is unavailable; run this in the privileged container")
	}
	_ = exec.Command("ip", "netns", "del", prns).Run()
	if out, err := exec.Command("ip", "netns", "add", prns).CombinedOutput(); err != nil {
		t.Skipf("cannot create a network namespace here: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", prns).Run() })

	// A LAN with a gateway, and a dummy standing in for the tunnel. Enough for the kernel
	// to have a real decision to make: a specific route, a default route, and somewhere
	// else the rules can send things.
	prMust(t, "ip", "link", "set", "lo", "up")
	prMust(t, "ip", "link", "add", "eth0", "type", "dummy")
	prMust(t, "ip", "addr", "add", "10.97.0.2/24", "dev", "eth0")
	prMust(t, "ip", "link", "set", "eth0", "up")
	prMust(t, "ip", "route", "add", "default", "via", prGW, "dev", "eth0")
	prMust(t, "ip", "link", "add", prTun, "type", "dummy")
	prMust(t, "ip", "link", "set", prTun, "up")
}

// claimInNS runs the claim inside the namespace.
//
// Re-executing this test binary under `ip netns exec` is the only way to get these netlink
// calls into another namespace: rules are installed by whichever namespace the calling
// thread is in, and Go offers no supported way to move a live goroutine between them.
// inNamespace runs fn with this thread inside the namespace.
//
// Entering it directly rather than re-executing the test binary under `ip netns exec`. A
// re-exec needs a second Test function that does nothing in an ordinary run, and CI refuses
// any skip in the data-plane log on the grounds that a skipped data-plane test reports
// success without testing anything. That guard is right, so the helper had to go.
//
// The thread is locked for the duration because a namespace is a property of a thread, not
// of a process: an unlocked goroutine could be rescheduled onto a thread that is still in
// the original namespace, and the netlink calls would quietly land in the wrong place.
//
// If the return fails the thread stays locked and is never unlocked, so it dies with this
// goroutine instead of going back into the pool still inside the namespace. A poisoned
// worker thread would make unrelated tests fail later, somewhere else, for no visible reason.
func inNamespace(t *testing.T, ns string, fn func() error) {
	t.Helper()
	runtime.LockOSThread()

	original, err := os.Open("/proc/self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("opening this namespace: %v", err)
	}
	defer func() { _ = original.Close() }()

	target, err := os.Open("/var/run/netns/" + ns)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("opening namespace %s: %v", ns, err)
	}
	defer func() { _ = target.Close() }()

	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("entering namespace %s: %v", ns, err)
	}

	fnErr := fn()

	if err := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil {
		t.Fatalf("could not return from namespace %s: %v", ns, err)
	}
	runtime.UnlockOSThread()

	if fnErr != nil {
		t.Fatalf("inside namespace %s: %v", ns, fnErr)
	}
}

func claimInNS(t *testing.T) {
	t.Helper()
	inNamespace(t, prns, func() error {
		if err := ClaimDefaultRoute(prTun, EgressMark); err != nil {
			return err
		}
		// Twice, because the reconciler is a loop: a second claim must add nothing rather
		// than accumulate a rule per pass.
		if err := ClaimDefaultRoute(prTun, EgressMark); err != nil {
			return fmt.Errorf("second claim: %w", err)
		}
		held, err := DefaultRouteClaimed(EgressMark)
		if err != nil || !held {
			return fmt.Errorf("DefaultRouteClaimed = %v after claiming: %w", held, err)
		}
		return nil
	})
}

func releaseInNS(t *testing.T) {
	t.Helper()
	inNamespace(t, prns, func() error {
		if err := ReleaseDefaultRoute(EgressMark); err != nil {
			return err
		}
		// And again, because the caller that needs this most is a daemon starting up with
		// no idea what its previous life did.
		if err := ReleaseDefaultRoute(EgressMark); err != nil {
			return fmt.Errorf("second release: %w", err)
		}
		held, err := DefaultRouteClaimed(EgressMark)
		if err != nil || held {
			return fmt.Errorf("DefaultRouteClaimed = %v after releasing: %w", held, err)
		}
		return nil
	})
}

// The three cases, and getting any of them wrong is a broken device.
func TestTheKernelRoutesTheThreeCasesCorrectly(t *testing.T) {
	setupPolicyRouteNS(t)

	// Before the claim, everything follows the ordinary default route. Without this the
	// assertions below cannot tell a working mechanism from a namespace that never had a
	// route to begin with.
	if before := routeFor(t, prOther, false); !strings.Contains(before, "via "+prGW) {
		t.Fatalf("before claiming, %s did not use the gateway: %s", prOther, before)
	}

	claimInNS(t)

	// 1. Ordinary traffic takes the tunnel. This is what claiming a default route means.
	if got := routeFor(t, prOther, false); !strings.Contains(got, prTun) {
		t.Errorf("ordinary traffic did not take the tunnel: %s", got)
	}

	// 2. The tunnel's own packets do not. A marked packet has to follow the real default
	// route, or the outer WireGuard traffic is routed into the tunnel carrying it and the
	// tunnel never establishes — with the kill switch already installed.
	if got := routeFor(t, prOther, true); !strings.Contains(got, "via "+prGW) {
		t.Errorf("the tunnel's own traffic was routed into the tunnel: %s", got)
	}

	// 3. The local network is untouched. A device that loses its own LAN has lost its
	// printer, its NAS, and the gateway its outer packets leave through — and it is the
	// case that breaks if the two rules are installed in the wrong order.
	if got := routeFor(t, "10.97.0.5", false); !strings.Contains(got, "eth0") {
		t.Errorf("the local network was routed into the tunnel: %s", got)
	}
}

// Giving the network back, which is what decides whether this mechanism is safe to have.
// These rules outlive the process, so a device that could not be released would be one
// routing through a tunnel that is gone.
func TestReleasingGivesTheRoutingBack(t *testing.T) {
	setupPolicyRouteNS(t)

	claimInNS(t)
	if got := routeFor(t, prOther, false); !strings.Contains(got, prTun) {
		t.Fatalf("nothing was claimed, so releasing proves nothing: %s", got)
	}

	releaseInNS(t)
	if got := routeFor(t, prOther, false); !strings.Contains(got, "via "+prGW) {
		t.Errorf("ordinary traffic did not go back to the gateway after releasing: %s", got)
	}
	if got := routeFor(t, "10.97.0.5", false); !strings.Contains(got, "eth0") {
		t.Errorf("the local network is wrong after releasing: %s", got)
	}

	// And the table is empty. Routing is already correct without this — once the rules are
	// gone nothing consults the table, so leaving routes in it changes no decision, and a
	// test that only asked where packets go would not notice.
	//
	// It is asserted anyway because Invariant 20 is about what is left behind rather than
	// about what still works. A table holding a route to an interface that no longer exists
	// is state this process created and did not remove, and the next person to look at the
	// machine has to work out whose it is.
	if out := prMust(t, "ip", "route", "show", "table", fmt.Sprint(EgressTable)); out != "" {
		t.Errorf("the egress table still holds routes after releasing:\n%s", out)
	}
}
