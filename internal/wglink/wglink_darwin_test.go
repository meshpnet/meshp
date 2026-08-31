//go:build darwin

package wglink

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// requireRoot skips a test that cannot run without it.
//
// Creating a utun goes through PF_SYSTEM, which is root-only on this platform, so the tests
// that touch a real interface are unrunnable on a developer's machine unless they choose to
// run the suite as root. They are not optional in CI: the macos job runs them under sudo,
// which is the whole reason that job exists (#144).
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: creating a utun device goes through PF_SYSTEM")
	}
}

// The routing table is read, not guessed at. Against this host's real routes, whatever they
// are — the assertion is about the shape of what comes back rather than its contents, since
// no test can know what is in a developer's or a runner's routing table.
func TestRoutesAreReadFromTheKernel(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}

	// A machine with no interface carrying a route is not one this can say anything about.
	found := false
	for _, iface := range ifaces {
		routes, err := interfaceRoutes(iface.Index)
		if err != nil {
			t.Fatalf("reading routes for %s: %v", iface.Name, err)
		}
		for _, prefix := range routes {
			found = true
			if !prefix.IsValid() {
				t.Errorf("%s: invalid prefix %v", iface.Name, prefix)
			}
			if prefix.Addr() != prefix.Masked().Addr() {
				t.Errorf("%s: %v has bits set below its prefix length, so the netmask was misread",
					iface.Name, prefix)
			}
		}
	}
	if !found {
		t.Skip("no interface on this host carries a route this can check")
	}
}

// An interface that does not exist is absent rather than an error: that is what the planner
// needs in order to decide to create it.
func TestObservingAnAbsentInterface(t *testing.T) {
	l := &darwinLink{devices: map[string]*runningDevice{}}

	obs, err := l.Observe("meshp-nonexistent-" + t.Name())
	if err != nil {
		t.Fatalf("observing an absent interface: %v", err)
	}
	if obs.Exists {
		t.Error("an interface that does not exist reported as existing")
	}
}

// A name file left behind by a process that died is tidied away, not adopted.
//
// This is the ordinary state after meshpd is killed: the tunnel went with the process, and
// the file outlived it. Reporting it as an existing interface would have the planner
// configure something that is not there — and configure it forever, since every pass would
// find the same file.
func TestAStaleNameFileIsNotAnInterface(t *testing.T) {
	dir := t.TempDir()
	name := "meshp-stale"
	path := filepath.Join(dir, name+".name")
	if err := os.WriteFile(path, []byte("utun-that-is-not-there\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	l := &darwinLink{devices: map[string]*runningDevice{}, runDir: dir}
	real, ok, err := l.resolve(name)
	if err != nil {
		t.Fatalf("resolving a stale name: %v", err)
	}
	if ok {
		t.Errorf("a stale name file resolved to %q", real)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("the stale name file was left behind, so the next pass will read it again")
	}
}

// The mapping is written where wg-quick(8) and anybody debugging would look for it.
func TestTheNameFileRecordsTheRealInterface(t *testing.T) {
	dir := t.TempDir()
	l := &darwinLink{devices: map[string]*runningDevice{}, runDir: dir}

	if got := l.nameFile("meshp0"); got != filepath.Join(dir, "meshp0.name") {
		t.Errorf("name file = %q", got)
	}
}

// An IPv4 netmask is rendered the way ifconfig wants it, which is hexadecimal and not
// dotted-quad. Getting this wrong is not a parse error — ifconfig accepts a dotted-quad too
// — but it is worth pinning, because the two are easy to confuse and only one is what the
// manual page documents for this argument.
func TestIPv4NetmaskRendering(t *testing.T) {
	for _, tc := range []struct {
		bits int
		want string
	}{
		{32, "0xffffffff"},
		{24, "0xffffff00"},
		{16, "0xffff0000"},
		{0, "0x00000000"},
	} {
		if got := ipv4Netmask(tc.bits); got != tc.want {
			t.Errorf("ipv4Netmask(%d) = %s, want %s", tc.bits, got, tc.want)
		}
	}
}

// The kernel's own link-local address on a utun is not something meshp installed, so it must
// not be reported as an address the planner could withdraw.
func TestLinkLocalAddressesAreNotOurs(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		addrs, err := interfaceAddresses(&iface)
		if err != nil {
			t.Fatalf("reading addresses of %s: %v", iface.Name, err)
		}
		for _, prefix := range addrs {
			if prefix.Addr().IsLinkLocalUnicast() {
				t.Errorf("%s: reported the kernel's link-local address %v as ours",
					iface.Name, prefix)
			}
		}
	}
}

// --- with a real interface -----------------------------------------------------------

// The whole of it: a tunnel comes into existence, is configured through wgctrl exactly as a
// Linux one would be, holds an address and a route, and reports itself honestly.
func TestATunnelComesUpAndIsObservedBack(t *testing.T) {
	requireRoot(t)

	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const name = "meshptest0"
	key := genDarwinKey(t)
	addr := netip.MustParsePrefix("100.90.77.1/32")
	via := netip.MustParsePrefix("100.90.77.0/24")

	plan := wgplan.Plan{Ops: []wgplan.Op{
		{Kind: wgplan.CreateDevice, Device: wgplan.Device{MTU: 1380}},
		{Kind: wgplan.SetDevice, Device: wgplan.Device{PrivateKey: key, ListenPort: 51899, MTU: 1380}},
		{Kind: wgplan.AddAddress, Prefix: addr},
		{Kind: wgplan.BringUp},
		{Kind: wgplan.AddRoute, Prefix: via},
	}}
	t.Cleanup(func() { _ = l.Apply(name, wgplan.Op{Kind: wgplan.DestroyDevice}) })

	if err := ApplyPlan(l, name, plan); err != nil {
		t.Fatalf("applying the plan: %v", err)
	}

	obs, err := l.Observe(name)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !obs.Exists {
		t.Fatal("the interface was created and does not exist")
	}
	if !obs.Up {
		t.Error("the interface was brought up and is down")
	}
	if obs.ListenPort != 51899 {
		t.Errorf("listen port = %d, want 51899", obs.ListenPort)
	}
	if obs.MTU != 1380 {
		t.Errorf("MTU = %d, want 1380", obs.MTU)
	}
	if obs.PrivateKey != key {
		t.Error("the private key that came back is not the one that went in")
	}
	if !hasPrefix(obs.Addresses, addr) {
		t.Errorf("addresses = %v, want to contain %v", obs.Addresses, addr)
	}
	if !hasPrefix(obs.Routes, via) {
		t.Errorf("routes = %v, want to contain %v", obs.Routes, via)
	}

	// ADR-0015 requires this be reported rather than inferred. On macOS it is always
	// userspace, and a build that started claiming otherwise would be claiming a kernel
	// implementation that does not exist on this platform.
	kind, err := l.Kind(name)
	if err != nil {
		t.Fatalf("Kind: %v", err)
	}
	if kind != KindUserspace {
		t.Errorf("kind = %s, want userspace", kind)
	}

	// And the mapping is on disk, where wg-quick(8) and anybody debugging would look.
	raw, err := os.ReadFile(filepath.Join(wireguardRunDir, name+".name"))
	if err != nil {
		t.Fatalf("reading the name file: %v", err)
	}
	if real := strings.TrimSpace(string(raw)); !strings.HasPrefix(real, "utun") {
		t.Errorf("the name file says %q, want a utun", real)
	}
}

// Applying the same plan twice changes nothing, which is what makes the reconcile loop safe
// to run on a timer. A create that failed on an interface that already exists, or an address
// that could not be added twice, would make every pass after the first report an error.
func TestApplyingTheSamePlanTwiceIsQuiet(t *testing.T) {
	requireRoot(t)

	l, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const name = "meshptest1"
	key := genDarwinKey(t)
	t.Cleanup(func() { _ = l.Apply(name, wgplan.Op{Kind: wgplan.DestroyDevice}) })

	create := wgplan.Plan{Ops: []wgplan.Op{
		{Kind: wgplan.CreateDevice, Device: wgplan.Device{MTU: 1380}},
		{Kind: wgplan.SetDevice, Device: wgplan.Device{PrivateKey: key, ListenPort: 51898, MTU: 1380}},
		{Kind: wgplan.BringUp},
	}}
	if err := ApplyPlan(l, name, create); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := ApplyPlan(l, name, create); err != nil {
		t.Fatalf("second apply of the same plan: %v", err)
	}
}

// Destroying an interface that is not there is success. The reconciler asks for it whenever
// a membership goes away, including when it was never up.
// A converged interface plans to nothing.
//
// The test that was missing, and the one that would have saved a laptop. The one above
// applies the same *plan* twice, which is a different and much weaker question: applying
// AddRoute twice is quiet whether or not the route was already there. What matters is what
// the planner decides after reading the machine back — the loop the agent actually runs.
//
// It carries an IPv6 address because that is what made the bug appear and what every real
// membership has. macOS installs fe80::/64, ff00::/8, ff01::/32 and ff02::/32 the moment one
// goes on an interface; those were reported as routes on the interface, the planner withdrew
// them, the kernel put them back, and the route socket woke the reconciler to do it again —
// twice a second, indefinitely.
func TestAConvergedInterfacePlansToNothing(t *testing.T) {
	requireRoot(t)

	l, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const name = "meshptest2"
	key := genDarwinKey(t)
	t.Cleanup(func() { _ = l.Apply(name, wgplan.Op{Kind: wgplan.DestroyDevice}) })

	want := wgplan.Interface{
		Name:       name,
		PrivateKey: key,
		MTU:        1380,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.90.78.1/32"),
			netip.MustParsePrefix("fd7c:6d65:7368:90::1/128"),
		},
	}

	first, err := wgplan.For(want, wgplan.Observed{})
	if err != nil {
		t.Fatalf("planning the first pass: %v", err)
	}
	if err := ApplyPlan(l, name, first); err != nil {
		t.Fatalf("applying the first plan: %v", err)
	}

	// Read the machine back and ask what is left to do. Nothing is the only right answer:
	// anything else is an operation that will be planned again on the pass after this one.
	observed, err := l.Observe(name)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	second, err := wgplan.For(want, observed)
	if err != nil {
		t.Fatalf("planning the second pass: %v", err)
	}
	if len(second.Ops) != 0 {
		t.Errorf("a converged interface still plans %d operations: %s\n"+
			"observed routes: %v", len(second.Ops), second, observed.Routes)
	}
}

func TestDestroyingNothingIsFine(t *testing.T) {
	requireRoot(t)

	l, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.Apply("meshp-never-existed", wgplan.Op{Kind: wgplan.DestroyDevice}); err != nil {
		t.Errorf("destroying an absent interface: %v", err)
	}
}

func genDarwinKey(t *testing.T) wgplan.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return wgplan.Key(k.String())
}

func hasPrefix(all []netip.Prefix, want netip.Prefix) bool {
	for _, p := range all {
		if p == want {
			return true
		}
	}
	return false
}
