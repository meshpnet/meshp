//go:build linux

package pathprobe

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The claim this whole package rests on: a probe leaves by the interface it was bound to,
// and not by whichever one the routing table prefers.
//
// It matters because the alternative is a false positive with teeth. If a dial could fall
// back to the physical interface — during the gap after an egress claim fails, or for a
// group whose route was never installed — it would report the advertiser healthy while
// measuring the local network, and the device would sit on a dead gateway forever with
// every check agreeing it was fine.
//
// Two namespaces joined by a veth pair stand in for a device and something on the far side
// of a tunnel. There is no WireGuard here on purpose: what is being tested is the socket
// option, and adding an encrypted tunnel underneath would only make a failure harder to
// attribute. The interface that carries the route and the interface that does not are the
// whole experiment.

func privileged() bool { return os.Geteuid() == 0 }

func run(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// netnsRun runs fn inside a named network namespace.
//
// The thread is locked because a namespace is a property of a thread rather than a process:
// without it the runtime could move the goroutine between two calls and open sockets in the
// wrong place. Every socket fn uses must be opened inside fn for the same reason.
func netnsRun(t *testing.T, name string, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatalf("opening this thread's namespace: %v", err)
	}
	defer func() { _ = original.Close() }()

	target, err := os.Open("/var/run/netns/" + name)
	if err != nil {
		t.Fatalf("opening namespace %s: %v", name, err)
	}
	defer func() { _ = target.Close() }()

	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		t.Fatalf("entering namespace %s: %v", name, err)
	}
	defer func() {
		if err := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil {
			// Leaving the thread in the wrong namespace would corrupt every later test.
			t.Fatalf("returning from namespace %s: %v", name, err)
		}
	}()

	fn()
}

func TestAProbeLeavesByTheInterfaceItWasBoundTo(t *testing.T) {
	if !privileged() {
		t.Skip("needs root to create namespaces and interfaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2 to set up the namespaces")
	}

	const (
		nsClient = "probeClient"
		nsServer = "probeServer"
		// The path that works.
		clientAddr = "10.98.0.1"
		serverAddr = "10.98.0.2"
		// A second interface with no route to the server. Standing in for the physical
		// interface a probe must never quietly fall back to.
		decoyAddr = "10.98.1.1"
		port      = 39443
	)

	cleanup := func() {
		_ = exec.Command("ip", "netns", "del", nsClient).Run()
		_ = exec.Command("ip", "netns", "del", nsServer).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	run(t, "ip", "netns", "add", nsClient)
	run(t, "ip", "netns", "add", nsServer)

	// The working path.
	run(t, "ip", "link", "add", "tun0", "type", "veth", "peer", "name", "tun1")
	run(t, "ip", "link", "set", "tun0", "netns", nsClient)
	run(t, "ip", "link", "set", "tun1", "netns", nsServer)
	run(t, "ip", "-n", nsClient, "addr", "add", clientAddr+"/24", "dev", "tun0")
	run(t, "ip", "-n", nsServer, "addr", "add", serverAddr+"/24", "dev", "tun1")
	run(t, "ip", "-n", nsClient, "link", "set", "tun0", "up")
	run(t, "ip", "-n", nsServer, "link", "set", "tun1", "up")
	run(t, "ip", "-n", nsClient, "link", "set", "lo", "up")
	run(t, "ip", "-n", nsServer, "link", "set", "lo", "up")

	// The decoy: up, addressed, and with no path to the server whatsoever. Its peer end
	// stays in the client namespace and is left down, so anything sent through it is lost.
	run(t, "ip", "-n", nsClient, "link", "add", "phys0", "type", "veth", "peer", "name", "phys1")
	run(t, "ip", "-n", nsClient, "addr", "add", decoyAddr+"/24", "dev", "phys0")
	run(t, "ip", "-n", nsClient, "link", "set", "phys0", "up")

	// A listener the client can reach, but only one way.
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		netnsRun(t, nsServer, func() {
			listener, err := net.Listen("tcp", serverAddr+":"+itoa(port))
			if err != nil {
				t.Errorf("listening in %s: %v", nsServer, err)
				close(ready)
				return
			}
			defer func() { _ = listener.Close() }()
			close(ready)

			// Two connections: one per successful dial the test expects. Accepting and
			// closing immediately is enough — the probe only cares that the handshake
			// completed.
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
			for range 2 {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		})
	}()
	<-ready

	target := netip.MustParseAddrPort(serverAddr + ":" + itoa(port))
	dialer := &BoundDialer{Timeout: 2 * time.Second}

	// dial rather than Probe, and the reason is the whole hazard netnsRun exists for.
	//
	// A namespace belongs to a thread. netnsRun locks this goroutine to a thread it has moved
	// into nsClient, so a socket opened here is opened there — but Probe fans out across
	// goroutines, and those run on other threads, which are still in the root namespace. A
	// test that called Probe would open its sockets in the wrong place and fail with "no
	// such device" while the code under test was perfectly correct.
	//
	// So the binding is tested here, one dial at a time, and Probe's fan-out is tested over
	// loopback below, where no namespace is involved.
	netnsRun(t, nsClient, func() {
		// Bound to the interface that carries the route: it works, and it reports a time.
		got := dialer.dial(context.Background(), "tun0", target, 2*time.Second)
		if got.Err != nil {
			t.Fatalf("a probe bound to the interface that carries the route failed: %v", got.Err)
		}
		if got.RTT <= 0 {
			t.Error("a successful probe reported no round trip time")
		}

		// The same target, bound to an interface with no path to it. This is the assertion
		// the package exists for: the routing table would have sent this through tun0 and
		// reported success, and binding is what stops it.
		decoy := dialer.dial(context.Background(), "phys0", target, 2*time.Second)
		if decoy.Err == nil {
			t.Error("a probe bound to an interface with no route to the target succeeded, " +
				"so the binding is not deciding where packets go and every verdict is about " +
				"whatever path the kernel picked")
		}

		// And once more through the working interface, to prove the decoy did not break the
		// dialer rather than the path.
		if again := dialer.dial(context.Background(), "tun0", target, 2*time.Second); again.Err != nil {
			t.Errorf("the working path stopped working after a bound failure: %v", again.Err)
		}
	})

	<-done
}

// Probe dials every target at once and returns one outcome per target, in order.
//
// Over loopback rather than in a namespace, because the fan-out is the subject: Probe's
// goroutines run on threads this test does not control, and a namespace belongs to a thread.
// What is being checked here is that concurrency does not lose, reorder or duplicate an
// answer — a round that dropped a target would silently lower the denominator the quorum is
// measured against.
func TestEveryTargetGetsAnAnswerInOrder(t *testing.T) {
	if !privileged() {
		t.Skip("needs root to bind a socket to an interface")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	live := netip.MustParseAddrPort(listener.Addr().String())
	// Reserved for documentation (RFC 5737) and routed nowhere, so it times out rather than
	// reaching a stranger.
	dead := netip.MustParseAddrPort("192.0.2.1:9")

	dialer := &BoundDialer{Timeout: time.Second}
	targets := []netip.AddrPort{live, dead, live, dead, live}
	got := dialer.Probe(context.Background(), "lo", targets)

	if len(got) != len(targets) {
		t.Fatalf("%d outcomes for %d targets", len(got), len(targets))
	}
	for i, o := range got {
		if o.Target != targets[i] {
			t.Fatalf("outcome %d is about %s, want %s — the answers came back reordered",
				i, o.Target, targets[i])
		}
		wantErr := targets[i] == dead
		if (o.Err != nil) != wantErr {
			t.Errorf("outcome %d for %s: err = %v, want error: %v", i, o.Target, o.Err, wantErr)
		}
	}
}

// A target that nothing is listening on, reached through an interface that works, is a
// reachable path. The packet arrived and something answered — with a reset rather than an
// acceptance, but it answered, which is the whole question. Counting it as failure would
// make every verdict depend on whether the target still runs a service on that port.
func TestARefusedConnectionIsStillAWorkingPath(t *testing.T) {
	if !privileged() {
		t.Skip("needs root to create namespaces and interfaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2 to set up the namespaces")
	}

	const (
		nsClient = "refusedClient"
		nsServer = "refusedServer"
		client   = "10.97.0.1"
		server   = "10.97.0.2"
	)

	cleanup := func() {
		_ = exec.Command("ip", "netns", "del", nsClient).Run()
		_ = exec.Command("ip", "netns", "del", nsServer).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	run(t, "ip", "netns", "add", nsClient)
	run(t, "ip", "netns", "add", nsServer)
	run(t, "ip", "link", "add", "rtun0", "type", "veth", "peer", "name", "rtun1")
	run(t, "ip", "link", "set", "rtun0", "netns", nsClient)
	run(t, "ip", "link", "set", "rtun1", "netns", nsServer)
	run(t, "ip", "-n", nsClient, "addr", "add", client+"/24", "dev", "rtun0")
	run(t, "ip", "-n", nsServer, "addr", "add", server+"/24", "dev", "rtun1")
	run(t, "ip", "-n", nsClient, "link", "set", "rtun0", "up")
	run(t, "ip", "-n", nsServer, "link", "set", "rtun1", "up")

	dialer := &BoundDialer{Timeout: 2 * time.Second}
	netnsRun(t, nsClient, func() {
		// Nothing is listening there, and nothing is filtering either, so the kernel on the
		// far side answers with a reset. dial rather than Probe for the threading reason
		// given above.
		got := dialer.dial(context.Background(), "rtun0",
			netip.MustParseAddrPort(server+":39999"), 2*time.Second)
		if got.Err != nil {
			t.Errorf("a refused connection was counted as a broken path: %v", got.Err)
		}
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
