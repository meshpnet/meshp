//go:build windows

package wglink

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// requireAdmin skips what cannot run without it.
//
// Creating a WinTun adapter installs a driver, so none of this works unelevated. A skip
// rather than a failure keeps `go test ./...` useful on a developer's machine; CI runs
// elevated, where these are not optional.
func requireAdmin(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs administrator: creating a WinTun adapter installs a driver")
	}
}

// The whole of the first slice: an adapter comes up, is configured through wgctrl exactly as
// a Linux or macOS one is, holds an address and a route, and is observed back.
//
// ADR-0015's claim is that "set this private key, these peers, these allowed IPs" is written
// once and runs everywhere. This is where that is either true on Windows or it is not — the
// key and port below go in through the same wgctrl call the other two platforms use, and
// come back out of the same Observe.
func TestAWinTunAdapterComesUpAndIsObservedBack(t *testing.T) {
	requireAdmin(t)

	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const name = "meshptest0"
	key := genWindowsKey(t)
	addr := netip.MustParsePrefix("100.90.77.1/32")
	via := netip.MustParsePrefix("100.90.77.0/24")

	plan := wgplan.Plan{Ops: []wgplan.Op{
		{Kind: wgplan.CreateDevice, Device: wgplan.Device{MTU: 1380}},
		{Kind: wgplan.SetDevice, Device: wgplan.Device{PrivateKey: key, ListenPort: 51899, MTU: 1380}},
		{Kind: wgplan.AddAddress, Prefix: addr},
		{Kind: wgplan.BringUp},
		{Kind: wgplan.AddRoute, Prefix: via},
	}}
	// Registered before the plan runs, so a failure part-way through still takes the adapter
	// off this machine.
	t.Cleanup(func() { _ = l.Apply(name, wgplan.Op{Kind: wgplan.DestroyDevice}) })

	if err := ApplyPlan(l, name, plan); err != nil {
		t.Fatalf("applying the plan: %v", err)
	}

	obs, err := l.Observe(name)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !obs.Exists {
		t.Fatal("the adapter was created and does not exist")
	}
	if !obs.Up {
		t.Error("the adapter was brought up and is down")
	}
	if obs.ListenPort != 51899 {
		t.Errorf("listen port = %d, want 51899", obs.ListenPort)
	}
	if obs.PrivateKey != key {
		t.Error("the private key that came back is not the one that went in; wgctrl is not " +
			"reaching this device over its UAPI pipe")
	}
	if !hasPrefix(obs.Addresses, addr) {
		t.Errorf("addresses = %v, want to contain %v", obs.Addresses, addr)
	}
	if !hasPrefix(obs.Routes, via) {
		t.Errorf("routes = %v, want to contain %v", obs.Routes, via)
	}

	// ADR-0015 requires this be reported rather than inferred. Windows does have an
	// in-kernel WireGuard — WireGuardNT — and meshp does not use it, so claiming anything
	// but userspace would be claiming a speed this build does not have.
	kind, err := l.Kind(name)
	if err != nil {
		t.Fatalf("Kind: %v", err)
	}
	if kind != KindUserspace {
		t.Errorf("kind = %s, want userspace", kind)
	}
}

// Applying the same plan twice changes nothing, which is what makes the reconcile loop safe
// to run on a timer. A create that failed on an adapter that already exists, or an address
// that could not be added twice, would make every pass after the first report an error.
func TestApplyingTheSamePlanTwiceIsQuietOnWindows(t *testing.T) {
	requireAdmin(t)

	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const name = "meshptest1"
	addr := netip.MustParsePrefix("100.90.78.1/32")
	via := netip.MustParsePrefix("100.90.78.0/24")
	plan := wgplan.Plan{Ops: []wgplan.Op{
		{Kind: wgplan.CreateDevice, Device: wgplan.Device{MTU: 1380}},
		{Kind: wgplan.SetDevice, Device: wgplan.Device{PrivateKey: genWindowsKey(t), ListenPort: 51898, MTU: 1380}},
		{Kind: wgplan.AddAddress, Prefix: addr},
		{Kind: wgplan.BringUp},
		{Kind: wgplan.AddRoute, Prefix: via},
	}}
	t.Cleanup(func() { _ = l.Apply(name, wgplan.Op{Kind: wgplan.DestroyDevice}) })

	for pass := 1; pass <= 2; pass++ {
		if err := ApplyPlan(l, name, plan); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}
}

// An adapter that was destroyed is reported absent, which is what the planner needs in order
// to build it again.
func TestDestroyingAnAdapterLeavesNothingBehind(t *testing.T) {
	requireAdmin(t)

	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	const name = "meshptest2"
	if err := l.Apply(name, wgplan.Op{Kind: wgplan.CreateDevice,
		Device: wgplan.Device{MTU: 1380}}); err != nil {
		t.Fatalf("creating: %v", err)
	}
	if obs, err := l.Observe(name); err != nil || !obs.Exists {
		t.Fatalf("after creating: exists=%v err=%v", obs.Exists, err)
	}

	if err := l.Apply(name, wgplan.Op{Kind: wgplan.DestroyDevice}); err != nil {
		t.Fatalf("destroying: %v", err)
	}
	obs, err := l.Observe(name)
	if err != nil {
		t.Fatalf("Observe after destroying: %v", err)
	}
	if obs.Exists {
		t.Error("a destroyed adapter is still reported as existing, so the reconciler would " +
			"never rebuild it")
	}
}

// Destroying what was never created is success, for the reason teardown always runs: a
// membership going away asks for this whether or not an adapter was ever made.
func TestDestroyingNothingIsFineOnWindows(t *testing.T) {
	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.Apply("meshpnope0", wgplan.Op{Kind: wgplan.DestroyDevice}); err != nil {
		t.Errorf("destroying an adapter that was never created: %v", err)
	}
}

// An adapter nothing created is absent rather than an error, and unelevated too — this is
// the state every non-Windows-service caller sees and it must not look like a fault.
func TestObservingAnAbsentAdapter(t *testing.T) {
	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	obs, err := l.Observe("meshpnope1")
	if err != nil {
		t.Fatalf("observing an adapter that does not exist: %v", err)
	}
	if obs.Exists {
		t.Error("an adapter nothing created was reported as existing")
	}
}

// The message somebody gets when they move meshpd.exe without its DLL.
//
// ADR-0028 makes the Windows build two files, and this is the one thing that will go wrong
// for whoever forgets that. Windows says "The specified module could not be found", which
// names neither the module nor the fix.
func TestAMissingDLLSaysWhichFileAndWhereItGoes(t *testing.T) {
	wrapped := wintunHint(errUnableToLoad{})
	for _, want := range []string{"wintun.dll", "beside meshpd.exe", "go run"} {
		if !strings.Contains(wrapped.Error(), want) {
			t.Errorf("the message does not mention %q: %s", want, wrapped)
		}
	}

	// And it leaves everything else alone, or every unrelated failure would come with
	// advice about a DLL.
	other := errSomethingElse{}
	if got := wintunHint(other); !errors.Is(got, other) {
		t.Errorf("an unrelated error was decorated: %v", got)
	}
	if wintunHint(nil) != nil {
		t.Error("nil was turned into an error")
	}
}

type errUnableToLoad struct{}

func (errUnableToLoad) Error() string {
	return "Error loading wintun.dll DLL: Unable to load library"
}

type errSomethingElse struct{}

func (errSomethingElse) Error() string { return "the adapter is in use" }

// hasPrefix reports whether a prefix is in a list. Its own copy rather than the macOS file's,
// because that one is built only on darwin.
func hasPrefix(all []netip.Prefix, want netip.Prefix) bool {
	for _, p := range all {
		if p == want {
			return true
		}
	}
	return false
}

func genWindowsKey(t *testing.T) wgplan.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return wgplan.Key(k.String())
}
