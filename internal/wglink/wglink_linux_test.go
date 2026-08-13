//go:build linux

package wglink

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// These tests need a Linux kernel with WireGuard and the privileges to create interfaces.
// They skip otherwise, so `go test ./...` stays useful for anyone without either, and are
// gated in CI where both are guaranteed.
//
// There is no fake here on purpose. Everything interesting in this package is behaviour
// the kernel provides — which routes it adds behind your back, what it reports a device's
// port as, whether removing an absent address is an error — and a test against a fake
// would assert only that the fake agrees with itself. The three-routes-not-one discovery
// that shaped Observe came from a real interface and could not have come from anywhere
// else.
func requireInterfaces(t *testing.T) Link {
	t.Helper()
	if !privileged() {
		t.Skip("needs root to create network interfaces")
	}
	l, err := New()
	if err != nil {
		t.Skipf("cannot manage interfaces here: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func genKey(t *testing.T) wgplan.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return wgplan.Key(k.String())
}

func pubOf(t *testing.T, private wgplan.Key) wgplan.Key {
	t.Helper()
	k, err := wgtypes.ParseKey(string(private))
	if err != nil {
		t.Fatal(err)
	}
	return wgplan.Key(k.PublicKey().String())
}

func prefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// wanted is an interface with one peer, named so tests do not collide.
func wanted(t *testing.T, name string) wgplan.Interface {
	t.Helper()
	peerPriv := genKey(t)
	return wgplan.Interface{
		Name:       name,
		PrivateKey: genKey(t),
		MTU:        1420,
		Addresses:  []netip.Prefix{prefix(t, "100.91.0.1/32"), prefix(t, "fd91::1/128")},
		Peers: []wgplan.Peer{{
			PublicKey:        pubOf(t, peerPriv),
			AllowedIPs:       []netip.Prefix{prefix(t, "100.91.0.2/32"), prefix(t, "fd91::2/128")},
			Endpoint:         "203.0.113.9:51820",
			KeepaliveSeconds: 25,
		}},
	}
}

func removeInterface(t *testing.T, l Link, name string) {
	t.Helper()
	obs, err := l.Observe(name)
	if err != nil || !obs.Exists {
		return
	}
	if err := ApplyPlan(l, name, wgplan.Teardown(obs)); err != nil {
		t.Logf("cleaning up %s: %v", name, err)
	}
}

// The whole cycle against a real interface: plan, apply, and find that what the kernel
// reports back is what was asked for.
func TestApplyingAPlanProducesTheInterfaceThatWasPlanned(t *testing.T) {
	l := requireInterfaces(t)
	const name = "wgt0"
	removeInterface(t, l, name)
	t.Cleanup(func() { removeInterface(t, l, name) })

	want := wanted(t, name)
	obs, err := l.Observe(name)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Exists {
		t.Fatalf("%s already exists", name)
	}

	plan, err := wgplan.For(want, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPlan(l, name, plan); err != nil {
		t.Fatalf("applying:\n%s\nfailed: %v", plan, err)
	}

	got, err := l.Observe(name)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Exists {
		t.Fatal("the interface does not exist after applying a plan that creates it")
	}
	if got.PrivateKey != want.PrivateKey {
		t.Error("the private key was not set")
	}
	if got.MTU != want.MTU {
		t.Errorf("MTU is %d, want %d", got.MTU, want.MTU)
	}
	if len(got.Peers) != 1 {
		t.Fatalf("%d peers, want 1", len(got.Peers))
	}
	if got.Peers[0].PublicKey != want.Peers[0].PublicKey {
		t.Error("the peer's key is not the one configured")
	}
	if got.Peers[0].Endpoint != want.Peers[0].Endpoint {
		t.Errorf("endpoint is %q, want %q", got.Peers[0].Endpoint, want.Peers[0].Endpoint)
	}
	if got.Peers[0].KeepaliveSeconds != 25 {
		t.Errorf("keepalive is %d, want 25", got.Peers[0].KeepaliveSeconds)
	}

	// Asked for no particular port, so the kernel chose one and must report it.
	if got.ListenPort == 0 {
		t.Error("the kernel reported no listen port")
	}

	if kind, err := l.Kind(name); err != nil {
		t.Error(err)
	} else if kind != KindKernel {
		t.Errorf("kind is %q, want kernel on this host", kind)
	}
}

// Invariant 18, against the kernel rather than a model of it. This is the test that would
// catch anything Observe fails to see: a field the diff cannot compare is a field that
// gets rewritten forever, and it shows up here as a second plan that is not empty.
func TestASecondPlanAgainstARealInterfaceIsEmpty(t *testing.T) {
	l := requireInterfaces(t)
	const name = "wgt1"
	removeInterface(t, l, name)
	t.Cleanup(func() { removeInterface(t, l, name) })

	want := wanted(t, name)
	obs, err := l.Observe(name)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := wgplan.For(want, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPlan(l, name, plan); err != nil {
		t.Fatal(err)
	}

	for round := range 3 {
		obs, err = l.Observe(name)
		if err != nil {
			t.Fatal(err)
		}
		again, err := wgplan.For(want, obs)
		if err != nil {
			t.Fatal(err)
		}
		if !again.Empty() {
			t.Fatalf("round %d: the interface is already as asked for, but the plan wants:\n%s",
				round+1, again)
		}
		if err := ApplyPlan(l, name, again); err != nil {
			t.Fatal(err)
		}
	}
}

// The finding that shaped Observe. Assigning an address makes the kernel add routes of its
// own — a local route for the address, and an IPv6 multicast route — both pointing at our
// interface. Seeing those as ours would have the reconciler withdraw them on every pass.
func TestTheKernelsOwnRoutesAreNotReportedAsOurs(t *testing.T) {
	l := requireInterfaces(t)
	const name = "wgt2"
	removeInterface(t, l, name)
	t.Cleanup(func() { removeInterface(t, l, name) })

	want := wanted(t, name)
	obs, _ := l.Observe(name)
	plan, err := wgplan.For(want, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPlan(l, name, plan); err != nil {
		t.Fatal(err)
	}

	got, err := l.Observe(name)
	if err != nil {
		t.Fatal(err)
	}

	// Exactly the peer's addresses, and nothing else.
	wantRoutes := map[netip.Prefix]bool{
		prefix(t, "100.91.0.2/32"): true,
		prefix(t, "fd91::2/128"):   true,
	}
	if len(got.Routes) != len(wantRoutes) {
		t.Errorf("observed %d routes, want %d: %v", len(got.Routes), len(wantRoutes), got.Routes)
	}
	for _, route := range got.Routes {
		if !wantRoutes[route] {
			t.Errorf("observed a route that meshp did not install: %s", route)
		}
	}

	// And the kernel really did add its own, so this test is testing something. Asked of
	// the kernel via `ip`, deliberately not through the code under test.
	out, err := exec.Command("ip", "route", "show", "table", "all", "dev", name).CombinedOutput()
	if err != nil {
		t.Skipf("cannot cross-check with ip: %v", err)
	}
	if !strings.Contains(string(out), "table local") {
		t.Errorf("expected the kernel to have added a local route for our own address;\n"+
			"this test proves nothing if it did not:\n%s", out)
	}
}

// Invariant 20. Everything installed comes off, and the interface goes with it.
func TestTeardownLeavesNothingBehind(t *testing.T) {
	l := requireInterfaces(t)
	const name = "wgt3"
	removeInterface(t, l, name)

	want := wanted(t, name)
	obs, _ := l.Observe(name)
	plan, err := wgplan.For(want, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPlan(l, name, plan); err != nil {
		t.Fatal(err)
	}

	obs, err = l.Observe(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPlan(l, name, wgplan.Teardown(obs)); err != nil {
		t.Fatalf("tearing down: %v", err)
	}

	after, err := l.Observe(name)
	if err != nil {
		t.Fatal(err)
	}
	if after.Exists {
		t.Error("the interface is still there after teardown")
	}

	// No routes anywhere still name it. A leftover route to a device that is gone is the
	// state this ordering exists to prevent.
	out, err := exec.Command("ip", "route", "show", "table", "all").CombinedOutput()
	if err == nil && strings.Contains(string(out), name) {
		t.Errorf("routes still reference %s after teardown:\n%s", name, out)
	}
}

// Applying a teardown twice, or to something that was never there, is not an error: the
// agent has to be able to clean up after a crash without knowing what it got through.
func TestTeardownIsSafeToRepeat(t *testing.T) {
	l := requireInterfaces(t)
	const name = "wgt4"
	removeInterface(t, l, name)

	want := wanted(t, name)
	obs, _ := l.Observe(name)
	plan, err := wgplan.For(want, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPlan(l, name, plan); err != nil {
		t.Fatal(err)
	}

	obs, err = l.Observe(name)
	if err != nil {
		t.Fatal(err)
	}
	teardown := wgplan.Teardown(obs)
	if err := ApplyPlan(l, name, teardown); err != nil {
		t.Fatal(err)
	}
	// The same operations again, against a host where none of it is there any more.
	if err := ApplyPlan(l, name, teardown); err != nil {
		t.Errorf("repeating a teardown failed: %v", err)
	}
}

// An interface of the right name that is not a WireGuard device is not ours to take over:
// configuring keys on it would be configuring someone else's interface.
func TestANonWireGuardInterfaceIsRefused(t *testing.T) {
	l := requireInterfaces(t)
	const name = "wgt5"
	_ = exec.Command("ip", "link", "del", name).Run()

	if err := exec.Command("ip", "link", "add", name, "type", "dummy").Run(); err != nil {
		t.Skipf("cannot create a dummy interface: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })

	if _, err := l.Observe(name); err == nil {
		t.Error("a non-WireGuard interface was adopted")
	} else if !strings.Contains(err.Error(), "not a WireGuard interface") {
		t.Errorf("the error does not explain the problem: %v", err)
	}
}

// Anything whose written form differs from the form the kernel reports back is a field the
// diff can never satisfy: the peer is rewritten on every reconcile, its session resets each
// time, and nothing looks wrong because both values are individually correct. Invariant 18
// is the guard, and these are the fields most likely to breach it.
func TestEveryPeerFieldSurvivesARoundTripThroughTheKernel(t *testing.T) {
	l := requireInterfaces(t)

	psk := genKey(t)
	cases := map[string]wgplan.Peer{
		"an IPv4 endpoint": {
			Endpoint: "203.0.113.9:51820",
		},
		"an IPv6 endpoint, where the bracketed form could differ": {
			Endpoint: "[2001:db8::9]:51820",
		},
		"a preshared key, which some interfaces decline to report": {
			PresharedKey: psk,
		},
		"a keepalive": {
			KeepaliveSeconds: 25,
		},
		"all of them at once": {
			Endpoint:         "[2001:db8::9]:51820",
			PresharedKey:     psk,
			KeepaliveSeconds: 25,
		},
	}

	i := 0
	for name, tweak := range cases {
		name, tweak := name, tweak
		i++
		iface := fmt.Sprintf("wgrt%d", i)
		t.Run(name, func(t *testing.T) {
			removeInterface(t, l, iface)
			t.Cleanup(func() { removeInterface(t, l, iface) })

			want := wanted(t, iface)
			want.Peers[0].Endpoint = tweak.Endpoint
			want.Peers[0].PresharedKey = tweak.PresharedKey
			want.Peers[0].KeepaliveSeconds = tweak.KeepaliveSeconds

			obs, err := l.Observe(iface)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := wgplan.For(want, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err := ApplyPlan(l, iface, plan); err != nil {
				t.Fatal(err)
			}

			obs, err = l.Observe(iface)
			if err != nil {
				t.Fatal(err)
			}
			again, err := wgplan.For(want, obs)
			if err != nil {
				t.Fatal(err)
			}
			if !again.Empty() {
				got := "no peers"
				if len(obs.Peers) > 0 {
					p := obs.Peers[0]
					got = fmt.Sprintf("endpoint=%q psk_set=%t keepalive=%d",
						p.Endpoint, p.PresharedKey != "", p.KeepaliveSeconds)
				}
				t.Errorf("this peer would be rewritten on every reconcile.\n"+
					"asked for: endpoint=%q psk_set=%t keepalive=%d\n"+
					"kernel reports: %s\nplan:\n%s",
					want.Peers[0].Endpoint, want.Peers[0].PresharedKey != "",
					want.Peers[0].KeepaliveSeconds, got, again)
			}
		})
	}
}
