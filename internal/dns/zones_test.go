package dns

import (
	"net/netip"
	"slices"
	"testing"
)

func host(name string, addrs ...string) Host {
	h := Host{Name: name}
	for _, a := range addrs {
		h.Addrs = append(h.Addrs, netip.MustParseAddr(a))
	}
	return h
}

// twoCustomers is the shape ADR-0004 exists for and ADR-0021 has to survive: one device in
// two networks, each with a machine called fileserver.
func twoCustomers(t *testing.T) *Zones {
	t.Helper()
	z := NewZones()
	z.Replace("meshp0", Zone{Suffix: "acme.internal", Hosts: []Host{
		host("fileserver", "100.90.0.5", "fd7c::5"),
		host("laptop", "100.90.0.9"),
	}})
	z.Replace("meshp1", Zone{Suffix: "globex.internal", Hosts: []Host{
		host("fileserver", "100.91.0.5"),
		host("printer", "100.91.0.7"),
	}})
	return z
}

// A fully-qualified name says which network it means, so there is nothing to disambiguate.
func TestAQualifiedNameResolvesToItsOwnNetwork(t *testing.T) {
	z := twoCustomers(t)

	acme := z.Lookup("fileserver.acme.internal")
	if acme.Code != RCodeSuccess {
		t.Fatalf("code = %v", acme.Code)
	}
	if !slices.Contains(acme.Addrs, netip.MustParseAddr("100.90.0.5")) {
		t.Errorf("acme's fileserver resolved to %v", acme.Addrs)
	}

	globex := z.Lookup("fileserver.globex.internal")
	if !slices.Contains(globex.Addrs, netip.MustParseAddr("100.91.0.5")) {
		t.Errorf("globex's fileserver resolved to %v", globex.Addrs)
	}
	if slices.Contains(globex.Addrs, netip.MustParseAddr("100.90.0.5")) {
		t.Error("one customer's address answered for another customer's name")
	}
}

// Case and a trailing dot are how a stub resolver actually sends a name.
func TestNamesAreMatchedWithoutCaseOrTrailingDot(t *testing.T) {
	z := twoCustomers(t)
	for _, name := range []string{
		"FileServer.Acme.Internal",
		"fileserver.acme.internal.",
		"FILESERVER.ACME.INTERNAL.",
	} {
		if got := z.Lookup(name); got.Code != RCodeSuccess {
			t.Errorf("%q did not resolve: %v", name, got.Code)
		}
	}
}

// The decision this package exists for.
//
// A bare name matching two networks is refused rather than answered from whichever sorted
// first. An order would send a technician to a customer chosen by something they cannot see.
func TestAnAmbiguousBareNameIsRefused(t *testing.T) {
	z := twoCustomers(t)

	got := z.Lookup("fileserver")
	if got.Code != RCodeRefused {
		t.Fatalf("code = %v, want REFUSED — a bare name in two networks was answered", got.Code)
	}
	if len(got.Addrs) != 0 {
		t.Errorf("a refused name still carried addresses: %v", got.Addrs)
	}
	want := []string{"fileserver.acme.internal", "fileserver.globex.internal"}
	if !slices.Equal(got.Ambiguous, want) {
		t.Errorf("alternatives = %v, want %v — the error has to say what to type instead", got.Ambiguous, want)
	}
}

// And an unambiguous bare name works, or the rule would just be "bare names never resolve",
// which is a different and worse product.
func TestAnUnambiguousBareNameResolves(t *testing.T) {
	z := twoCustomers(t)

	got := z.Lookup("printer")
	if got.Code != RCodeSuccess {
		t.Fatalf("code = %v, want success — printer is only in one network", got.Code)
	}
	if !slices.Contains(got.Addrs, netip.MustParseAddr("100.91.0.7")) {
		t.Errorf("addrs = %v", got.Addrs)
	}
}

// A device in one network is the ordinary case, and every bare name must work there.
func TestOneNetworkHasNoAmbiguity(t *testing.T) {
	z := NewZones()
	z.Replace("meshp0", Zone{Suffix: "acme.internal", Hosts: []Host{host("fileserver", "100.90.0.5")}})

	if got := z.Lookup("fileserver"); got.Code != RCodeSuccess {
		t.Errorf("code = %v in a single-network device", got.Code)
	}
}

// A name under a suffix this device serves, for a device that is not there, does not exist.
//
// NXDOMAIN rather than REFUSED, and the difference matters: a stub that gets REFUSED may try
// the next search domain and find a different customer's machine, which is the ambiguity
// coming back through the side door.
func TestAMissingDeviceInAKnownNetworkDoesNotExist(t *testing.T) {
	z := twoCustomers(t)
	if got := z.Lookup("nosuchbox.acme.internal"); got.Code != RCodeNXDomain {
		t.Errorf("code = %v, want NXDOMAIN", got.Code)
	}
}

// A suffix this device does not serve is not ours to answer for. NXDOMAIN would be a claim
// about somebody else's zone.
func TestAForeignSuffixIsRefused(t *testing.T) {
	z := twoCustomers(t)
	for _, name := range []string{"example.com", "fileserver.other.internal", "www.google.com"} {
		if got := z.Lookup(name); got.Code != RCodeRefused {
			t.Errorf("%q got %v, want REFUSED", name, got.Code)
		}
	}
}

// Sub-labels are not devices. Answering `a.b.acme.internal` from the host called `b` would
// invent a name nobody configured.
func TestASubLabelIsNotADevice(t *testing.T) {
	z := twoCustomers(t)
	if got := z.Lookup("extra.fileserver.acme.internal"); got.Code != RCodeNXDomain {
		t.Errorf("code = %v, want NXDOMAIN", got.Code)
	}
}

// Replacing a membership's zone drops what it had. A revoked device must stop resolving, and
// merging would leave it answering forever.
func TestReplacingAZoneDropsTheOldNames(t *testing.T) {
	z := NewZones()
	z.Replace("meshp0", Zone{Suffix: "acme.internal", Hosts: []Host{
		host("old", "100.90.0.1"), host("kept", "100.90.0.2"),
	}})
	z.Replace("meshp0", Zone{Suffix: "acme.internal", Hosts: []Host{host("kept", "100.90.0.2")}})

	if got := z.Lookup("old.acme.internal"); got.Code == RCodeSuccess {
		t.Error("a name removed from the network still resolves")
	}
	if got := z.Lookup("kept.acme.internal"); got.Code != RCodeSuccess {
		t.Error("replacing a zone dropped a name that is still there")
	}
}

// Leaving a network takes its names with it, and un-shadows any bare name it was making
// ambiguous.
func TestForgettingANetworkResolvesTheAmbiguity(t *testing.T) {
	z := twoCustomers(t)
	if got := z.Lookup("fileserver"); got.Code != RCodeRefused {
		t.Fatalf("setup: expected ambiguity, got %v", got.Code)
	}

	z.Forget("meshp1")

	got := z.Lookup("fileserver")
	if got.Code != RCodeSuccess {
		t.Fatalf("code = %v after leaving the other network", got.Code)
	}
	if !slices.Contains(got.Addrs, netip.MustParseAddr("100.90.0.5")) {
		t.Errorf("addrs = %v", got.Addrs)
	}
	if got := z.Lookup("printer.globex.internal"); got.Code == RCodeSuccess {
		t.Error("a network this device has left still resolves")
	}
}

// The suffix list is what tells the system resolver which names to send here, so it has to
// be complete and stable.
func TestSuffixesAreListedInAStableOrder(t *testing.T) {
	z := twoCustomers(t)
	want := []string{"acme.internal", "globex.internal"}
	for range 5 {
		if got := z.Suffixes(); !slices.Equal(got, want) {
			t.Fatalf("suffixes = %v, want %v", got, want)
		}
	}
}

// A nil Zones answers rather than panicking. The agent builds one per daemon and a test or
// an early code path may not have.
func TestANilZonesIsSafe(t *testing.T) {
	var z *Zones
	if got := z.Lookup("anything"); got.Code != RCodeNXDomain {
		t.Errorf("code = %v", got.Code)
	}
	z.Replace("meshp0", Zone{Suffix: "x.internal"})
	z.Forget("meshp0")
	if got := z.Suffixes(); got != nil {
		t.Errorf("suffixes = %v", got)
	}
}
