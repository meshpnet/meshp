//go:build linux

package nftables

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// A packet actually crossing, which is the one claim every other test in this package
// stops short of. Rendering can be right, the ruleset can load, the route can exist, and
// nothing can cross — that combination has been the shape of most of the real bugs here.
//
// The topology is the smallest one that is not a lie:
//
//	netns "meshpmesh"  100.90.0.2  <-->  meshp0 100.90.0.1   the mesh side
//	                       meshpveth 192.168.77.1  <-->  lan0 192.168.77.2 in netns "meshplan"
//
// The gateway is the container itself, with a namespace on each side. Both sides are
// namespaces rather than local addresses because a packet the gateway generates is never
// forwarded — it has no incoming interface, so the forward chain never sees it and iifname
// cannot match in postrouting. Testing with a locally generated packet exercises a path no
// real traffic takes.
//
// A LAN with no idea the mesh exists is the whole point: the namespace holds one connected
// route, 192.168.77.0/24, and no default. It can therefore only answer a packet whose source
// address it can reach on that subnet. If the source rewriting does not happen it receives a
// packet from 100.90.0.1, has nowhere to send the reply, and the ping fails — so a reply is
// possible only if forwarding and rewriting both worked.
//
// TestWithoutTheRulesetNothingCrosses is not decoration. It is what makes the positive test
// mean anything, and it has already earned its place once: with a default route in the
// namespace the ping succeeded with meshp's rules removed, and every other assertion here
// would have been passing for a reason that had nothing to do with this package.

func run(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := run(t, name, args...); err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
}

// setupLAN builds the topology and returns once it is ready.
func setupLAN(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 is unavailable; run this in the privileged container")
	}
	if out, err := run(t, "ip", "netns", "add", "meshplan"); err != nil {
		t.Skipf("cannot create a network namespace here: %s", out)
	}
	t.Cleanup(func() {
		_, _ = run(t, "ip", "netns", "del", "meshplan")
		_, _ = run(t, "ip", "netns", "del", "meshpmesh")
		_, _ = run(t, "ip", "link", "del", "meshpveth")
		_, _ = run(t, "ip", "link", "del", "meshp0")
	})

	// The mesh side is a veth to a namespace standing in for a mesh device, not a dummy.
	// The difference is the whole test: a packet from a namespace *arrives on* meshp0 and is
	// forwarded, while one generated on the gateway itself is not forwarded at all — it has
	// no incoming interface, so nothing in the forward chain sees it and iifname cannot
	// match in postrouting. The first version used a dummy and proved only that.
	if out, err := run(t, "ip", "netns", "add", "meshpmesh"); err != nil {
		t.Skipf("cannot create a network namespace here: %s", out)
	}
	mustRun(t, "ip", "link", "add", "meshp0", "type", "veth", "peer", "name", "mesh0")
	mustRun(t, "ip", "link", "set", "mesh0", "netns", "meshpmesh")
	mustRun(t, "ip", "addr", "add", "100.90.0.1/24", "dev", "meshp0")
	mustRun(t, "ip", "link", "set", "meshp0", "up")
	mustRun(t, "ip", "netns", "exec", "meshpmesh", "ip", "addr", "add", "100.90.0.2/24", "dev", "mesh0")
	mustRun(t, "ip", "netns", "exec", "meshpmesh", "ip", "link", "set", "mesh0", "up")
	mustRun(t, "ip", "netns", "exec", "meshpmesh", "ip", "link", "set", "lo", "up")
	// What an assignment installs on a client: the carried prefix via the advertiser.
	mustRun(t, "ip", "netns", "exec", "meshpmesh",
		"ip", "route", "add", "192.168.77.0/24", "via", "100.90.0.1")

	// The LAN, and a namespace that has never heard of 100.90.0.0/24.
	mustRun(t, "ip", "link", "add", "meshpveth", "type", "veth", "peer", "name", "lan0")
	mustRun(t, "ip", "link", "set", "lan0", "netns", "meshplan")
	mustRun(t, "ip", "addr", "add", "192.168.77.1/24", "dev", "meshpveth")
	mustRun(t, "ip", "link", "set", "meshpveth", "up")
	mustRun(t, "ip", "netns", "exec", "meshplan", "ip", "addr", "add", "192.168.77.2/24", "dev", "lan0")
	mustRun(t, "ip", "netns", "exec", "meshplan", "ip", "link", "set", "lan0", "up")
	mustRun(t, "ip", "netns", "exec", "meshplan", "ip", "link", "set", "lo", "up")

	// Deliberately no default route. This namespace knows 192.168.77.0/24 and nothing else,
	// which is what an ordinary LAN device looks like: a printer or a NAS has never heard of
	// 100.90.0.0/24 and has no gateway that could reach it.
	//
	// The first version of this test gave the namespace a default route via the gateway,
	// which made 100.90.0.1 reachable and meant a reply proved nothing — the ping passed
	// with meshp's rules removed. The negative test below is what caught it, and it is the
	// only reason this file asserts anything.
}

func branchGroup() []*meshpv1.AdvertisedRoutes_Group {
	return []*meshpv1.AdvertisedRoutes_Group{
		{RouteGroupId: "g", Name: "branch", Prefixes: []string{"192.168.77.0/24"}},
	}
}

// pingLAN sends from the mesh namespace to the LAN host, and reports whether a reply came.
//
// From the namespace rather than from the gateway, so the packet genuinely arrives on
// meshp0 and is forwarded. A packet the gateway generates itself never enters the forward
// chain and has no incoming interface for postrouting to match on, so it would test a path
// no real traffic takes.
func pingLAN(t *testing.T) bool {
	t.Helper()
	_, err := run(t, "ip", "netns", "exec", "meshpmesh",
		"ping", "-c", "2", "-W", "2", "192.168.77.2")
	return err == nil
}

// The claim: with forwarding and rewriting in place, a mesh address reaches a LAN that has
// never heard of it — and gets an answer.
func TestAPacketCrossesIntoACarriedLAN(t *testing.T) {
	requireNFT(t)
	setupLAN(t)

	if _, err := EnableForwarding(); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	script, err := RenderForward("meshp0", branchGroup())
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("loading the forwarding ruleset: %v", err)
	}
	t.Cleanup(func() {
		if empty, renderErr := RenderForward("meshp0", nil); renderErr == nil {
			_ = Apply(context.Background(), empty)
		}
	})

	if !pingLAN(t) {
		lan, _ := run(t, "ip", "netns", "exec", "meshplan", "ip", "route", "show")
		rules, _ := run(t, "nft", "list", "table", "inet", ForwardTableName)
		t.Fatalf("nothing crossed into the carried LAN.\nlan routes:\n%s\nruleset:\n%s", lan, rules)
	}
}

// The other half of the same claim, and the reason a reply is proof rather than a
// coincidence: without the ruleset the LAN receives a packet from an address it cannot
// reach and the ping fails, whatever the routing table says.
func TestWithoutTheRulesetNothingCrosses(t *testing.T) {
	requireNFT(t)
	setupLAN(t)

	if _, err := EnableForwarding(); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	// Explicitly removed, so this is testing the absence of meshp's rules rather than the
	// state a previous test happened to leave behind.
	empty, err := RenderForward("meshp0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), empty); err != nil {
		t.Fatal(err)
	}

	if pingLAN(t) {
		t.Fatal("a packet crossed with no source rewriting in place; " +
			"the LAN answered an address it has no route to, so this test proves nothing")
	}
}

// Withdrawing has to stop it. A gateway that kept forwarding after being withdrawn is a
// path nobody knows about, and nothing upstream would notice.
func TestWithdrawingStopsPacketsCrossing(t *testing.T) {
	requireNFT(t)
	setupLAN(t)

	if _, err := EnableForwarding(); err != nil {
		t.Fatal(err)
	}
	script, err := RenderForward("meshp0", branchGroup())
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatal(err)
	}
	if !pingLAN(t) {
		t.Fatal("nothing crossed to begin with")
	}

	empty, err := RenderForward("meshp0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), empty); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Apply(context.Background(), empty) })

	if pingLAN(t) {
		t.Fatal("packets still cross after the device stopped carrying the prefix")
	}
}
