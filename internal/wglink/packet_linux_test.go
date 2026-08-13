//go:build linux

package wglink

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// The claim this whole milestone rests on: configuration produced by wgplan and applied by
// wglink carries a packet between two hosts.
//
// Two network namespaces joined by a veth pair stand in for two hosts on a network. Nothing
// here is a simulation of WireGuard — it is the kernel's WireGuard, handed the same
// operations the agent will hand it, and the assertion is an ICMP echo arriving. Everything
// up to now has only proved that meshp can describe an interface.
//
// The namespaces and the veth pair are scaffolding, so they are set up with `ip`. The code
// under test does not shell out for anything (ADR-0015); the endpoints are supplied here
// because nothing discovers them yet — that is the next milestone, and pretending otherwise
// would be the wrong thing to test.

// netnsRun runs fn inside a named network namespace.
//
// The thread is locked for the duration because a namespace is a property of a thread, not
// of a process: without locking, the Go runtime could move the goroutine to a thread still
// in the original namespace between two calls, and the sockets would be opened in the wrong
// place. Every socket fn uses must also be opened inside fn for the same reason.
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
			// Leaving the thread in the wrong namespace would corrupt every later test, so
			// this is fatal rather than logged.
			t.Fatalf("returning from namespace %s: %v", name, err)
		}
	}()

	fn()
}

func run(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func TestAPacketCrossesTheTunnel(t *testing.T) {
	if !privileged() {
		t.Skip("needs root to create namespaces and interfaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2 to set up the namespaces")
	}

	const (
		nsA = "meshpA"
		nsB = "meshpB"
		// The underlay: what the two hosts reach each other over.
		underlayA = "10.99.0.1"
		underlayB = "10.99.0.2"
		portA     = 51820
		portB     = 51821
		// The mesh addresses, which only exist inside the tunnel.
		meshA = "100.92.0.1"
		meshB = "100.92.0.2"
	)

	cleanup := func() {
		_ = exec.Command("ip", "netns", "del", nsA).Run()
		_ = exec.Command("ip", "netns", "del", nsB).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	run(t, "ip", "netns", "add", nsA)
	run(t, "ip", "netns", "add", nsB)
	run(t, "ip", "link", "add", "vethA", "type", "veth", "peer", "name", "vethB")
	run(t, "ip", "link", "set", "vethA", "netns", nsA)
	run(t, "ip", "link", "set", "vethB", "netns", nsB)
	run(t, "ip", "-n", nsA, "addr", "add", underlayA+"/24", "dev", "vethA")
	run(t, "ip", "-n", nsA, "link", "set", "vethA", "up")
	run(t, "ip", "-n", nsB, "addr", "add", underlayB+"/24", "dev", "vethB")
	run(t, "ip", "-n", nsB, "link", "set", "vethB", "up")

	// The underlay has to work, or a failure below would be ambiguous.
	if out, err := exec.Command("ip", "netns", "exec", nsA,
		"ping", "-c", "1", "-W", "2", underlayB).CombinedOutput(); err != nil {
		t.Fatalf("the veth pair does not carry traffic, so this test cannot mean anything: %v\n%s", err, out)
	}

	privA, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privB, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// One interface each, each knowing the other as its only peer. The endpoints are the
	// underlay addresses: supplied here because nothing discovers them yet.
	ifaceFor := func(name string, priv wgtypes.Key, port int, ownMesh, peerMesh, peerPub, peerEndpoint string) wgplan.Interface {
		return wgplan.Interface{
			Name:       name,
			PrivateKey: wgplan.Key(priv.String()),
			ListenPort: port,
			MTU:        1420,
			Addresses:  []netip.Prefix{netip.MustParsePrefix(ownMesh + "/32")},
			Peers: []wgplan.Peer{{
				PublicKey:        wgplan.Key(peerPub),
				AllowedIPs:       []netip.Prefix{netip.MustParsePrefix(peerMesh + "/32")},
				Endpoint:         peerEndpoint,
				KeepaliveSeconds: 25,
			}},
		}
	}

	wantA := ifaceFor("meshp0", privA, portA, meshA, meshB,
		privB.PublicKey().String(), fmt.Sprintf("%s:%d", underlayB, portB))
	wantB := ifaceFor("meshp0", privB, portB, meshB, meshA,
		privA.PublicKey().String(), fmt.Sprintf("%s:%d", underlayA, portA))

	// Configure each end from inside its own namespace, through the code under test.
	for ns, want := range map[string]wgplan.Interface{nsA: wantA, nsB: wantB} {
		netnsRun(t, ns, func() {
			l, err := New()
			if err != nil {
				t.Fatalf("%s: opening the link: %v", ns, err)
			}
			defer func() { _ = l.Close() }()

			observed, err := l.Observe(want.Name)
			if err != nil {
				t.Fatalf("%s: observing: %v", ns, err)
			}
			plan, err := wgplan.For(want, observed)
			if err != nil {
				t.Fatalf("%s: planning: %v", ns, err)
			}
			if err := ApplyPlan(l, want.Name, plan); err != nil {
				t.Fatalf("%s: applying:\n%s\nfailed: %v", ns, plan, err)
			}
		})
	}

	// The assertion the milestone is named for.
	out, err := exec.Command("ip", "netns", "exec", nsA,
		"ping", "-c", "3", "-W", "5", meshB).CombinedOutput()
	if err != nil {
		wgA, _ := exec.Command("ip", "netns", "exec", nsA, "wg", "show").CombinedOutput()
		routesA, _ := exec.Command("ip", "-n", nsA, "route", "show").CombinedOutput()
		t.Fatalf("no packet crossed the tunnel: %v\n--- ping ---\n%s\n--- wg in %s ---\n%s\n--- routes ---\n%s",
			err, out, nsA, wgA, routesA)
	}
	t.Logf("a packet crossed the tunnel:\n%s", strings.TrimSpace(string(out)))

	// A handshake happened, so this was WireGuard and not some other path the addresses
	// happened to be reachable over.
	netnsRun(t, nsA, func() {
		l, err := New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()

		if kind, err := l.Kind("meshp0"); err != nil {
			t.Error(err)
		} else if kind != KindKernel {
			t.Errorf("kind is %q, want kernel", kind)
		}
	})

	handshake, err := exec.Command("ip", "netns", "exec", nsA,
		"wg", "show", "meshp0", "latest-handshakes").CombinedOutput()
	if err != nil {
		t.Skipf("cannot read handshakes: %v", err)
	}
	fields := strings.Fields(string(handshake))
	if len(fields) < 2 || fields[1] == "0" {
		t.Errorf("no handshake was recorded, so the ping did not go through WireGuard: %q", handshake)
	}

	// And the tunnel survives a reconcile: planning against the running interface finds
	// nothing to do, so the agent's next tick will not tear down a working session.
	netnsRun(t, nsA, func() {
		l, err := New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()

		observed, err := l.Observe(wantA.Name)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := wgplan.For(wantA, observed)
		if err != nil {
			t.Fatal(err)
		}
		if !plan.Empty() {
			t.Errorf("a working tunnel would be reconfigured on the next tick:\n%s", plan)
		}
	})

	// Still carrying traffic afterwards.
	if out, err := exec.Command("ip", "netns", "exec", nsA,
		"ping", "-c", "1", "-W", "5", meshB).CombinedOutput(); err != nil {
		t.Errorf("the tunnel stopped working after a reconcile: %v\n%s", err, out)
	}
}

// WireGuard learns a peer's endpoint from the traffic it receives: the kernel updates it to
// the source of the most recent authenticated packet, which is how roaming works at all.
//
// So the kernel's endpoint for a peer is frequently one meshp never configured, and it is
// better information than anything the control plane has — it is where that peer actually
// is. A reconciler that treats it as drift and writes its own value back would undo roaming
// on a timer, and would never stop finding work to do (Invariant 18).
//
// This is the case with no configured endpoint at all, which is what every peer looks like
// until endpoint discovery exists: B does not know where A is, A knows where B is, and one
// ping from A teaches B.
func TestALearnedEndpointIsNotTreatedAsDrift(t *testing.T) {
	if !privileged() {
		t.Skip("needs root to create namespaces and interfaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2")
	}

	const (
		nsA, nsB             = "meshpRA", "meshpRB"
		underlayA, underlayB = "10.98.0.1", "10.98.0.2"
		portA, portB         = 51830, 51831
		meshA, meshB         = "100.93.0.1", "100.93.0.2"
	)

	cleanup := func() {
		_ = exec.Command("ip", "netns", "del", nsA).Run()
		_ = exec.Command("ip", "netns", "del", nsB).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	run(t, "ip", "netns", "add", nsA)
	run(t, "ip", "netns", "add", nsB)
	run(t, "ip", "link", "add", "vRA", "type", "veth", "peer", "name", "vRB")
	run(t, "ip", "link", "set", "vRA", "netns", nsA)
	run(t, "ip", "link", "set", "vRB", "netns", nsB)
	run(t, "ip", "-n", nsA, "addr", "add", underlayA+"/24", "dev", "vRA")
	run(t, "ip", "-n", nsA, "link", "set", "vRA", "up")
	run(t, "ip", "-n", nsB, "addr", "add", underlayB+"/24", "dev", "vRB")
	run(t, "ip", "-n", nsB, "link", "set", "vRB", "up")

	privA, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privB, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// A knows where B is. B knows nothing about where A is — no endpoint at all.
	wantA := wgplan.Interface{
		Name: "meshp0", PrivateKey: wgplan.Key(privA.String()), ListenPort: portA, MTU: 1420,
		Addresses: []netip.Prefix{netip.MustParsePrefix(meshA + "/32")},
		Peers: []wgplan.Peer{{
			PublicKey:        wgplan.Key(privB.PublicKey().String()),
			AllowedIPs:       []netip.Prefix{netip.MustParsePrefix(meshB + "/32")},
			Endpoint:         fmt.Sprintf("%s:%d", underlayB, portB),
			KeepaliveSeconds: 25,
		}},
	}
	wantB := wgplan.Interface{
		Name: "meshp0", PrivateKey: wgplan.Key(privB.String()), ListenPort: portB, MTU: 1420,
		Addresses: []netip.Prefix{netip.MustParsePrefix(meshB + "/32")},
		Peers: []wgplan.Peer{{
			PublicKey:  wgplan.Key(privA.PublicKey().String()),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix(meshA + "/32")},
			// No endpoint: this is every peer, before discovery exists.
			KeepaliveSeconds: 25,
		}},
	}

	for ns, want := range map[string]wgplan.Interface{nsA: wantA, nsB: wantB} {
		netnsRun(t, ns, func() {
			l, err := New()
			if err != nil {
				t.Fatalf("%s: %v", ns, err)
			}
			defer func() { _ = l.Close() }()
			obs, err := l.Observe(want.Name)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := wgplan.For(want, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err := ApplyPlan(l, want.Name, plan); err != nil {
				t.Fatalf("%s: %v", ns, err)
			}
		})
	}

	// A initiates. B now knows where A is, having been told by the packet rather than by us.
	if out, err := exec.Command("ip", "netns", "exec", nsA,
		"ping", "-c", "2", "-W", "5", meshB).CombinedOutput(); err != nil {
		t.Fatalf("the tunnel did not come up, so nothing was learned: %v\n%s", err, out)
	}

	netnsRun(t, nsB, func() {
		l, err := New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()

		obs, err := l.Observe(wantB.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(obs.Peers) != 1 {
			t.Fatalf("%d peers, want 1", len(obs.Peers))
		}
		learned := obs.Peers[0].Endpoint
		if learned == "" {
			t.Fatal("the kernel reports no endpoint, so it learned nothing and this test proves nothing")
		}
		t.Logf("B learned A's endpoint from traffic: %s", learned)

		// The claim: knowing less than the kernel is not a reason to overwrite it.
		plan, err := wgplan.For(wantB, obs)
		if err != nil {
			t.Fatal(err)
		}
		if !plan.Empty() {
			t.Errorf("a learned endpoint was treated as drift; every reconcile would rewrite\n"+
				"the peer and undo roaming:\n%s", plan)
		}
	})
}
