//go:build darwin

package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/meshpnet/meshp/internal/egress"
	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/wglink"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// The addresses this test claims with. Documentation ranges for everything the carve-out
// keeps direct, so the routes it pins can only ever point at something that is not there,
// and a mesh address of its own so it never collides with wglink's claim test.
const (
	// claimLabel is what the agent calls the interface. On macOS no interface has that name:
	// the kernel makes a utunN and wglink writes the mapping to a name file. Every bug in
	// #200 lived in the gap between the two names, so the label is the point of the test.
	claimLabel = "meshp0"

	claimOwnV4 = "100.90.78.1"
	claimOwnV6 = "fd7c:6d65:7368:78::1"

	// The control plane and a relay: TEST-NET-2, so a host route to either reaches nothing.
	claimControlPlane = "198.51.100.10"
	claimRelay        = "198.51.100.20"

	// An operator's exclusion, as the control plane sends it in TunnelConfig. TEST-NET-3.
	claimKeptDirect      = "203.0.113.0/24"
	claimKeptDirectProbe = "203.0.113.9"

	// Somewhere on the internet in each half the claim takes, and one for IPv6. Only ever
	// looked up in the routing table; nothing is sent to them.
	claimInternetLow  = "1.1.1.1"
	claimInternetHigh = "149.112.112.112"
	claimInternetV6   = "2606:4700:4700::1111"
)

// claimRecord is where macOS's egress router writes down what it installed, so that a
// process that did not make a claim can still take it off (wglink's egressRecordPath, #160).
// Named here rather than exported from wglink because this test only needs to know that it
// exists while a claim does and is gone afterwards — and it checks the first half, so a path
// that moved would fail loudly rather than make the second half vacuous.
const claimRecord = "/var/run/meshp/egress-routes"

// A full tunnel claimed on macOS the way the agent claims one, asserted on the routing table.
//
// #200's three bugs were found on a laptop, and all three lived where the agent hands the
// router what it knows — the label meshp0, the tunnel's addresses, the carve-out — on a
// platform where the label is not the name of anything:
//
//   - the tunnel's own address was collected as a local network to keep off the tunnel,
//     because applyEgress gave LocalNetworks the label and it skipped by a name the kernel
//     does not have
//   - route(8) refuses 255.255.255.255/32, which every carve-out contains
//   - halvesFor and `route -interface` were handed the label rather than the utun
//
// wglink's claim test has claimed with the label and a computed carve-out since #208, which
// catches them where they land in the router. It cannot see the reconciler's half: it builds
// the carve-out itself, from addresses it reads off the device, so what applyEgress actually
// passes is never what it claims with — and that is where the first of the three started.
//
// So this goes in through the reconciler, with nothing pre-digested: a real wglink link and
// router, the membership named meshp0, and desired state carrying an egress group, a relay
// and an operator's exclusion, converged by Apply as cmd/meshpd does. Each of the three made
// the claim fail outright, and the first would otherwise have pinned the device's own address
// to the LAN gateway; both are asserted.
//
// The routing table rather than traffic, because a hosted runner has no advertiser to send
// traffic to. What it can prove is where the kernel would send a packet, asked of route(8)
// rather than of wglink's own reader — the code under test should not also be the witness.
//
// Fail-closed is switched off for this network, and that is deliberate. None of the three
// bugs touched the lock, which pf's own tests load on this runner already, and the lock's
// catch-all is `block return`: inside the claim window it would reset the runner's own
// connections rather than delay them, which is how a check like this becomes a flaky job. The
// claim path is otherwise identical — applyEgress computes the same carve-out and calls the
// same Claim.
//
// Like wglink's claim test, this takes the machine's traffic for the length of the claim: a
// default route into a utun whose only peer has no endpoint. Every cleanup is registered
// before anything is installed, nothing inside the window talks to the network, and the job
// runs packages one at a time so no other test is relying on the network meanwhile.
func TestAFullTunnelIsClaimedTheWayTheAgentClaimsIt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: a utun goes through PF_SYSTEM and a claim writes the routing " +
			"table; the privileged CI run covers this")
	}
	refuseIfThisHostIsClaimingAlready(t)

	lan := lookUp(t, "default")
	if lan.gateway == "" || lan.iface == "" {
		t.Skipf("this machine has no IPv4 default route (%s), so there is no gateway for the "+
			"carve-out to be pinned to", lan)
	}

	// Where everything went before, to hold the release to. The tunnel's own address is not
	// here: before the claim it has no interface, and after the release it still has one
	// until the teardown, so it is asserted inside the claim instead.
	restored := []string{"default", claimInternetLow, claimInternetHigh, claimInternetV6,
		claimControlPlane, claimRelay, claimKeptDirectProbe}
	before := make(map[string]routeTo, len(restored))
	for _, destination := range restored {
		before[destination] = lookUp(t, destination)
	}

	// Built as cmd/meshpd builds one on this platform: wglink's link and router, no filter
	// (macOS has none), and a resolver that remembers. The resolver writes beside the test
	// rather than under /var/run — every address here is a literal, so nothing resolves, and
	// a root test should not leave a file behind if that ever changes.
	link, err := wglink.New()
	if err != nil {
		t.Fatalf("opening the host's interface manager: %v", err)
	}
	logger, said := recordingLogger()
	router := wglink.NewRouter()
	r := New(link, Membership{
		InterfaceName: claimLabel,
		PrivateKey:    ourKey,
		AddressV4:     claimOwnV4,
		AddressV6:     claimOwnV6,
		ControlURL:    "https://" + claimControlPlane + ":8443",
	}, nil, nil, logger).WithEgress(router)
	r.resolve = egress.Remembering(nil, filepath.Join(t.TempDir(), "resolved-addresses"))

	// Registered before anything is installed and run in reverse: the routing first, then the
	// interface, then the link. The router's Release is the one reclaimEgressLock uses after
	// a crash, so it takes off what it remembers, what the record names, and the halves when
	// it knows nothing — the runner's own routing comes back however far this got.
	t.Cleanup(func() { _ = link.Close() })
	t.Cleanup(func() {
		if err := r.Teardown(); err != nil {
			t.Errorf("tearing down %s: %v", claimLabel, err)
		}
	})
	t.Cleanup(func() {
		if err := router.Release(); err != nil {
			t.Errorf("giving the routing back: %v", err)
		}
	})

	// Twice, because the agent claims on every pass and a claim that only works once is a
	// laptop that loses its tunnel a minute later. The second pass meets its own routes
	// already in the table, and the interface planner meets the halves on its interface.
	for pass := 1; pass <= 2; pass++ {
		unapplied, err := r.Apply(t.Context(), fullTunnelState(uint64(pass)))
		if err != nil || len(unapplied) != 0 {
			t.Fatalf("pass %d did not converge: unapplied %v, error %v.\n"+
				"With fail-closed enforced, a device that cannot claim refuses all egress "+
				"with nothing carrying it — the symptom #200 was filed for.\n\nthe agent said:\n%s",
				pass, unapplied, err, saidSoFar(said))
		}
	}

	// The premise. If macOS ever called the interface meshp0, the label and the kernel's
	// name would be the same thing and this would pass without testing the translation.
	if _, err := net.InterfaceByName(claimLabel); err == nil {
		t.Fatalf("an interface called %s exists, so the agent's name is also the kernel's and "+
			"this test cannot see the difference between them", claimLabel)
	}
	device := kernelNameOf(t, claimLabel)

	// Everything bound for the internet goes into the tunnel, in both halves of IPv4 and in
	// IPv6, because the tunnel carries an address of each family.
	for _, destination := range []string{claimInternetLow, claimInternetHigh, claimInternetV6} {
		if got := lookUp(t, destination); got.iface != device {
			t.Errorf("%s goes %s, not into the tunnel (%s behind %s): the claim did not take "+
				"the route a device in an egress group sends its traffic by",
				destination, got, device, claimLabel)
		}
	}

	// The device's own mesh address stays the tunnel's. The first of #200's bugs asked the
	// kernel to route it through the LAN gateway; the kernel refused, and the whole claim
	// with it. Had it accepted, this is where it would show.
	if got := lookUp(t, claimOwnV4); got.gateway == lan.gateway || got.iface == lan.iface {
		t.Errorf("the device's own mesh address %s goes %s — pinned to the LAN, as if the "+
			"tunnel's address were a local network to keep off the tunnel", claimOwnV4, got)
	}

	// What must not go into the tunnel goes where it went before: through the gateway the
	// machine was using when the claim was made. A relay or control plane routed into the
	// tunnel is a tunnel carrying its own packets and a device nobody can reach.
	for _, kept := range []struct{ destination, what string }{
		{claimControlPlane, "the control plane"},
		{claimRelay, "the relay"},
		{claimKeptDirectProbe, "a prefix the control plane asked to keep direct"},
	} {
		got := lookUp(t, kept.destination)
		if got.gateway != lan.gateway || got.iface != lan.iface {
			t.Errorf("%s (%s) goes %s, not via the original gateway %s on %s",
				kept.what, kept.destination, got, lan.gateway, lan.iface)
		}
	}

	// And it is written down, so a daemon that dies holding this claim can be followed by one
	// that takes it off. Checked here so the absence asserted after the release means
	// something.
	recorded := readClaimRecord(t)
	for _, want := range []string{"0.0.0.0/1", "128.0.0.0/1", claimControlPlane + "/32", claimRelay + "/32"} {
		if !slices.Contains(recorded, want) {
			t.Errorf("%s does not name %s, so a restarted daemon could not take it off: %v",
				claimRecord, want, recorded)
		}
	}
	if slices.Contains(recorded, claimOwnV4+"/32") {
		t.Errorf("the claim recorded the device's own address %s as a route it installed", claimOwnV4)
	}

	// The group is withdrawn, the way a device learns it: the next state no longer carries
	// it, and the same Apply gives the default route back.
	if unapplied, err := r.Apply(t.Context(), withdrawnState(3)); err != nil || len(unapplied) != 0 {
		t.Fatalf("withdrawing the group did not converge: unapplied %v, error %v\n\nthe agent said:\n%s",
			unapplied, err, saidSoFar(said))
	}
	if strings.Contains(saidSoFar(said), "could not stop sending everything through the tunnel") {
		t.Errorf("the release reported a failure:\n%s", saidSoFar(said))
	}

	for _, destination := range restored {
		if got := lookUp(t, destination); got != before[destination] {
			t.Errorf("%s went %s before the claim and goes %s after the release; "+
				"the routing table was not given back as it was found",
				destination, before[destination], got)
		}
	}
	if _, err := os.Stat(claimRecord); !os.IsNotExist(err) {
		t.Errorf("%s outlived the release (stat: %v); the next start would try to take off "+
			"routes that may no longer be meshp's", claimRecord, err)
	}
	if held, err := wglink.EgressHeld(); err != nil || held {
		t.Errorf("after the release, EgressHeld = %v (error %v); meshp doctor would report "+
			"a machine stranded by a claim that is gone", held, err)
	}

	// Last, the interface: leaving a network takes it away, and with it the name file that
	// would otherwise translate meshp0 into a utun number the kernel hands to somebody else.
	if err := r.Teardown(); err != nil {
		t.Fatalf("tearing down %s: %v", claimLabel, err)
	}
	if _, err := os.Stat(filepath.Join("/var/run/wireguard", claimLabel+".name")); !os.IsNotExist(err) {
		t.Errorf("the name file for %s outlived its interface (stat: %v)", claimLabel, err)
	}
}

// fullTunnelState is desired state for a device in a network with an egress group.
//
// Built through a real delta, as a control plane would send it: the group, a relay to keep
// reachable, an exclusion an operator asked for, and fail-closed explicitly declined for the
// reason the test gives.
func fullTunnelState(version uint64) *peerset.Set {
	s := peerset.New()
	s.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: version,
		UpsertPeers: []*meshpv1.Peer{peer(bobKey, "100.90.78.2/32")},
		Tunnel: &meshpv1.TunnelConfig{
			Mtu:              1420,
			ExcludedPrefixes: []string{claimKeptDirect},
			FailClosedPolicy: meshpv1.TunnelConfig_FAIL_CLOSED_DISABLED,
		},
		Relays: &meshpv1.RelayConfig{Relays: []*meshpv1.RelayConfig_Relay{
			{Id: "relay-test", Endpoints: []string{claimRelay + ":3478"}},
		}},
		RouteGroups: []*meshpv1.RouteGroupAssignment{
			assignmentTo("exit", bobKey, "0.0.0.0/0", "::/0"),
		},
	})
	return s
}

// withdrawnState is the same network with the egress group taken away.
func withdrawnState(version uint64) *peerset.Set {
	s := fullTunnelState(version)
	s.Apply(&meshpv1.StateDelta{
		FromVersion: version, ToVersion: version + 1,
		RemovedRouteGroupIds: []string{"group-exit"},
	})
	return s
}

// refuseIfThisHostIsClaimingAlready skips on a machine where the answer would be about
// something else.
//
// A developer running this with meshpd up would have this test fight the agent over meshp0
// and the default route. On a runner none of it is true, and a skip there is a failure anyway:
// the job refuses a test that skipped in both of its runs.
func refuseIfThisHostIsClaimingAlready(t *testing.T) {
	t.Helper()
	if client, err := wgctrl.New(); err == nil {
		_, err := client.Device(claimLabel)
		_ = client.Close()
		if err == nil {
			t.Skipf("%s is already being served on this machine; stop meshpd and run this again", claimLabel)
		}
	}
	if held, err := wglink.EgressHeld(); err != nil {
		t.Fatalf("reading the routing table: %v", err)
	} else if held {
		t.Skip("something already claims a default route on this machine, so a claim here " +
			"could not be told apart from it")
	}
	if _, err := os.Stat(claimRecord); err == nil {
		t.Skipf("%s exists, so a previous claim has not been released", claimRecord)
	}
}

// kernelNameOf is the interface the kernel gave the agent's label, read from the name file
// wglink writes — the same translation the router has to make.
func kernelNameOf(t *testing.T, label string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("/var/run/wireguard", label+".name"))
	if err != nil {
		t.Fatalf("reading the name file for %s: %v", label, err)
	}
	device := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(device, "utun") {
		t.Fatalf("%s is mapped to %q, which is not a utun", label, device)
	}
	return device
}

// readClaimRecord is the prefixes the claim record names, one per line.
func readClaimRecord(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(claimRecord)
	if err != nil {
		t.Fatalf("a claim is in place and %s cannot be read: %v", claimRecord, err)
	}
	return strings.Fields(string(raw))
}

// routeTo is where the routing table sends one destination, as route(8) reports it. Zero
// means there is no route at all.
type routeTo struct {
	destination, gateway, iface string
}

func (r routeTo) String() string {
	if r == (routeTo{}) {
		return "nowhere (no route)"
	}
	if r.gateway == "" {
		return fmt.Sprintf("to %s on %s", r.destination, r.iface)
	}
	return fmt.Sprintf("to %s via %s on %s", r.destination, r.gateway, r.iface)
}

// lookUp asks the kernel where it would send a packet for one destination.
//
// route(8) rather than wglink's reader, so the witness is not the code under test. Its exit
// status is no use: it prints "not in table" and exits zero when there is no route.
func lookUp(t *testing.T, destination string) routeTo {
	t.Helper()
	family := "-inet"
	if addr, err := netip.ParseAddr(destination); err == nil && addr.Is6() {
		family = "-inet6"
	}
	out, err := exec.Command("/sbin/route", "-n", "get", family, destination).CombinedOutput()
	if bytes.Contains(out, []byte("not in table")) {
		return routeTo{}
	}
	if err != nil {
		t.Fatalf("route -n get %s %s: %v: %s", family, destination, err, out)
	}
	var got routeTo
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch value = strings.TrimSpace(value); key {
		case "destination":
			got.destination = value
		case "gateway":
			got.gateway = value
		case "interface":
			got.iface = value
		}
	}
	return got
}

// saidSoFar is everything the reconciler has logged, which is where a failed claim's reason
// goes: Apply reports the component, and only the log says which route the kernel refused.
func saidSoFar(lines *loggedLines) string {
	lines.mu.Lock()
	defer lines.mu.Unlock()
	return lines.buf.String()
}
