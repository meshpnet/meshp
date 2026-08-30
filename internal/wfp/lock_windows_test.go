//go:build windows

package wfp

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/meshpnet/meshp/internal/wglink"
	"github.com/meshpnet/meshp/internal/wgplan"
)

func requireAdmin(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs administrator: the filtering platform is not writable otherwise")
	}
}

// Every filter installPolicy can write is one deleteFilters can name.
//
// The list in everySlot is maintained by hand, because enumerating the engine needs a
// template structure this package would have to lay out itself — the memory-layout risk
// ADR-0030 borrowed the types to avoid. A slot that installation writes and removal does not
// know about is a filter nothing can ever take off, on a machine with no network.
func TestEveryFilterInstalledCanBeNamedAgain(t *testing.T) {
	slots := everySlot()
	seen := make(map[string]bool, len(slots))
	for _, slot := range slots {
		if seen[slot] {
			t.Errorf("%q is listed twice", slot)
		}
		seen[slot] = true
	}

	// The names installPolicy builds, spelled the way it spells them.
	required := []string{"loopback", "interface-v4", "interface-v6", "blockall-v4", "blockall-v6",
		"dns-v4", "dns-v6", "config-dhcp4", "config-dhcp6", "config-ndp",
		"endpoint-0-v4", "endpoint-0-v6", "excluded-0-v4", "excluded-0-v6",
	}
	for _, slot := range required {
		if !seen[slot] {
			t.Errorf("%q is installed and cannot be removed; a lock using it could never be "+
				"taken off", slot)
		}
	}
}

// Two filters never share a key, and the same filter always has the same one.
//
// The second half is what lets a process that did not install them remove them, which is the
// whole of Invariant 20 on this platform.
func TestAFilterKeyIsAFunctionOfItsSlot(t *testing.T) {
	first := filterKey("blockall-v4")
	if first != filterKey("blockall-v4") {
		t.Error("the same filter got two keys, so a restarted daemon could not find it")
	}

	seen := map[windows.GUID]string{}
	for _, slot := range everySlot() {
		key := filterKey(slot)
		if other, clash := seen[key]; clash {
			t.Errorf("%q and %q share a key, so installing one removes the other", slot, other)
		}
		seen[key] = slot
	}
}

// The carve-out is bounded, and the bound is enforced rather than assumed.
//
// A network with more exemptions than there are slots would otherwise install filters that
// removal cannot name.
func TestTheCarveOutIsBounded(t *testing.T) {
	var many []netip.AddrPort
	for i := range maxCarveOut + 10 {
		many = append(many, netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{198, 51, 100, byte(i % 250)}), 51820))
	}
	if got := len(sortedEndpoints(many)); got > maxCarveOut {
		t.Errorf("%d endpoints survived a limit of %d, so some would be unremovable",
			got, maxCarveOut)
	}

	var prefixes []netip.Prefix
	for i := range maxCarveOut + 10 {
		prefixes = append(prefixes, netip.PrefixFrom(
			netip.AddrFrom4([4]byte{10, byte(i % 250), 0, 0}), 16))
	}
	if got := len(sortedPrefixes(prefixes)); got > maxCarveOut {
		t.Errorf("%d exclusions survived a limit of %d", got, maxCarveOut)
	}
}

// The same lock installs the same filters however its inputs arrive.
func TestTheSameLockIsTheSameFilters(t *testing.T) {
	a := sortedEndpoints([]netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.7:51820"),
		netip.MustParseAddrPort("203.0.113.9:443"),
	})
	b := sortedEndpoints([]netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.9:443"),
		netip.MustParseAddrPort("198.51.100.7:51820"),
		netip.MustParseAddrPort("198.51.100.7:51820"),
	})
	if len(a) != len(b) || a[0] != b[0] || a[1] != b[1] {
		t.Errorf("the same endpoints in a different order gave %v and %v", a, b)
	}
}

// The whole of it: the lock goes on, refuses what it does not name, and comes off.
//
// Everything except TEST-NET-1 is carved out, so the only thing this refuses is traffic to an
// address that was never going to arrive. That keeps the runner on the network even if this
// test dies before its cleanup — the same shape the macOS pf test uses, and for the same
// reason.
func TestALockRefusesWhatItDoesNotName(t *testing.T) {
	requireAdmin(t)

	link, err := wglink.New()
	if err != nil {
		t.Fatalf("opening the interface manager: %v", err)
	}
	t.Cleanup(func() { _ = link.Close() })

	const iface = "meshptestwfp0"
	t.Cleanup(func() { _ = link.Apply(iface, wgplan.Op{Kind: wgplan.DestroyDevice}) })
	if err := link.Apply(iface, wgplan.Op{Kind: wgplan.CreateDevice,
		Device: wgplan.Device{MTU: 1380}}); err != nil {
		t.Fatalf("creating an adapter for the lock to permit: %v", err)
	}

	lock := &Lock{}
	// Registered before the lock goes on, so a failure part-way through still gives the
	// machine back.
	t.Cleanup(func() { _ = lock.ApplyLock(t.Context(), "", nil, nil, false) })

	blocked := netip.MustParsePrefix("192.0.2.0/24")
	if err := lock.ApplyLock(t.Context(), iface, nil, everythingExcept(blocked), false); err != nil {
		t.Fatalf("installing the lock: %v", err)
	}

	// A connection the lock has to decide about. It is going nowhere either way; what matters
	// is that meshp's catch-all is what stops it, and a filter refuses immediately where a
	// blackhole would time out.
	start := time.Now()
	conn, err := net.DialTimeout("tcp", "192.0.2.1:443", 4*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a connection to a refused address succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the connection took %s to fail, which is a blackhole rather than a "+
			"refusal — the lock is installed and is not what stopped it", elapsed)
	}

	// And something the carve-out names still works, or this proves only that the machine
	// has no network.
	if permitted, err := net.DialTimeout("tcp", "198.51.100.1:443", 1500*time.Millisecond); err == nil {
		_ = permitted.Close()
	} else if !isTimeout(err) {
		t.Errorf("a carved-out address was refused rather than simply unreachable: %v", err)
	}

	if err := lock.ApplyLock(t.Context(), "", nil, nil, false); err != nil {
		t.Fatalf("removing the lock: %v", err)
	}
}

// Removing a lock that is not there is success.
//
// Teardown always runs: a membership going away asks for this whether or not one was ever
// installed, and an error would report a failure to remove something never made.
func TestRemovingALockThatIsNotThere(t *testing.T) {
	requireAdmin(t)
	if err := (&Lock{}).ApplyLock(t.Context(), "", nil, nil, false); err != nil {
		t.Errorf("removing a lock that was never installed: %v", err)
	}
}

// A host that cannot reach the filtering platform says so rather than finding out per apply.
func TestWithoutPrivilegeThisHostSaysItCannotLock(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("this is about what an unprivileged agent reports; the unprivileged run covers it")
	}
	if New(t.Context()) != nil {
		t.Error("an agent that cannot open the filter engine reported that it can refuse egress")
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// everythingExcept covers the whole address space apart from one prefix.
func everythingExcept(p netip.Prefix) []netip.Prefix {
	out := []netip.Prefix{netip.MustParsePrefix("::/0")}
	octets := p.Addr().AsSlice()
	for i := range p.Bits() {
		flipped := append([]byte(nil), octets...)
		flipped[i/8] ^= 1 << (7 - i%8)
		sibling, ok := netip.AddrFromSlice(flipped)
		if !ok {
			continue
		}
		out = append(out, netip.PrefixFrom(sibling, i+1).Masked())
	}
	return out
}
