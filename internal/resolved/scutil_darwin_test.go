//go:build darwin

package resolved

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: writing to the SystemConfiguration dynamic store")
	}
}

// scutil exits zero when it fails, which is the trap in driving it.
//
// This is not a test of meshp so much as a test of the assumption meshp is built on, pinned
// here because everything else in this file depends on it: if a future macOS made scutil
// report failures through its exit status instead, the check in run() would still be right,
// but a version of it that trusted the exit status would silently start reporting success
// for every failed configuration. Somebody should find that out here.
func TestScutilReportsFailureWithoutFailing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this is about what an unprivileged write looks like")
	}
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(
		"d.init\nd.add ServerAddresses * 127.0.0.1\nset State:/Network/Service/meshp-test-denied/DNS\nquit\n")
	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Skip("scutil now reports this through its exit status, which run() also handles")
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatal("an unprivileged write neither failed nor said anything, so run() cannot tell " +
			"a refused configuration from a successful one")
	}
}

// A refused write is an error, not a silent success. The whole of ADR-0021's requirement
// that a host which cannot configure its resolver says so.
func TestARefusedConfigurationIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs to be unprivileged for the write to be refused")
	}
	s := New(context.Background())
	if s == nil {
		t.Fatal("scutil is not reachable on this machine")
	}

	err := s.Configure(context.Background(), "meshptest0",
		netip.MustParseAddrPort("127.0.0.1:5353"), []string{"test-mesh.example"})
	if err == nil {
		t.Fatal("an unprivileged configuration reported success; the agent would believe names work")
	}
	if !strings.Contains(err.Error(), "scutil") {
		t.Errorf("error = %q, want it to name what refused", err)
	}
}

// A domain from the control plane must not be able to become another scutil command. The
// script goes to a process running as root on standard input, so a newline in a suffix is
// somebody else's line.
func TestADomainCannotSmuggleInAScutilCommand(t *testing.T) {
	for _, bad := range []string{
		"",
		"good.example\nremove State:/Network/Global/IPv4",
		"good.example remove",
		"good.example\ttab",
		"-leading-hyphen.example",
		strings.Repeat("a", 254),
		`quote".example`,
		`back\slash.example`,
	} {
		if err := validDomain(bad); err == nil {
			t.Errorf("validDomain(%q) allowed it", bad)
		}
	}
	for _, good := range []string{
		"hq.acme.meshp.internal",
		"a.example",
		"xn--bcher-kva.example",
	} {
		if err := validDomain(good); err != nil {
			t.Errorf("validDomain(%q) = %v, want it allowed", good, err)
		}
	}
}

// Two networks on one device get one key each rather than fighting over a global setting.
func TestEachInterfaceGetsItsOwnKey(t *testing.T) {
	a, b := storeKey("meshp0"), storeKey("meshp1")
	if a == b {
		t.Fatal("two interfaces share one key, so the second would overwrite the first")
	}
	for _, key := range []string{a, b} {
		if !strings.HasPrefix(key, "State:/Network/Service/") {
			t.Errorf("%q is not in the dynamic store's service namespace", key)
		}
		if !strings.HasSuffix(key, "/DNS") {
			t.Errorf("%q does not name a DNS dictionary", key)
		}
		if !strings.Contains(key, "meshp-") {
			t.Errorf("%q does not say it is meshp's, so nobody reading the store would know", key)
		}
	}
}

// --- with the real store -------------------------------------------------------------

// The whole of it: macOS honours a supplemental match domain pointing at a loopback port,
// and reverting removes it completely.
//
// This is the assumption the entire package rests on, and it is not one that can be reasoned
// about — either mDNSResponder collects supplemental domains from a service key meshp
// invented, on a non-standard port, or it does not. `scutil --dns` is asked because it
// reports the resolver list mDNSResponder actually assembled, rather than what was written.
func TestMacOSHonoursASupplementalDomain(t *testing.T) {
	requireRoot(t)

	s := New(context.Background())
	if s == nil {
		t.Fatal("scutil is not reachable")
	}
	const iface = "meshptest-dns"
	const domain = "test-mesh.example"
	t.Cleanup(func() { _ = s.Revert(context.Background(), iface) })

	if err := s.Configure(context.Background(), iface,
		netip.MustParseAddrPort("127.0.0.1:5353"), []string{domain}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	resolvers := systemResolvers(t)
	if !strings.Contains(resolvers, domain) {
		t.Fatalf("mDNSResponder did not pick up %s as a supplemental domain.\n"+
			"This is the assumption the package rests on — a service key meshp invented is "+
			"collected like any other.\nscutil --dns said:\n%s", domain, resolvers)
	}
	// The port matters as much as the domain: the agent listens on a high loopback port,
	// and a resolver that took the address and ignored the port would send every mesh
	// query to whatever is on 53.
	if !strings.Contains(resolvers, "5353") {
		t.Errorf("the supplemental resolver did not carry the port.\nscutil --dns said:\n%s", resolvers)
	}

	// And reverting leaves the store as it was, which is the claim that makes configuring
	// it defensible at all.
	if err := s.Revert(context.Background(), iface); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if after := systemResolvers(t); strings.Contains(after, domain) {
		t.Errorf("%s is still resolved after reverting.\nscutil --dns said:\n%s", domain, after)
	}
}

// Configuring twice is configuring once. The reconciler calls this every pass.
func TestConfiguringTwiceIsQuiet(t *testing.T) {
	requireRoot(t)

	s := New(context.Background())
	if s == nil {
		t.Fatal("scutil is not reachable")
	}
	const iface = "meshptest-dns-twice"
	t.Cleanup(func() { _ = s.Revert(context.Background(), iface) })

	for range 2 {
		if err := s.Configure(context.Background(), iface,
			netip.MustParseAddrPort("127.0.0.1:5353"), []string{"twice.example"}); err != nil {
			t.Fatalf("Configure: %v", err)
		}
	}
}

// Reverting an interface that was never configured is success. Teardown runs whenever a
// membership goes away, including when it never came up.
func TestRevertingSomethingNeverConfigured(t *testing.T) {
	requireRoot(t)

	s := New(context.Background())
	if s == nil {
		t.Fatal("scutil is not reachable")
	}
	if err := s.Revert(context.Background(), "meshptest-never-configured"); err != nil {
		t.Errorf("reverting an unconfigured interface: %v", err)
	}
}

// systemResolvers is what mDNSResponder assembled, not what was written to the store.
func systemResolvers(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("scutil", "--dns").CombinedOutput()
	if err != nil {
		t.Fatalf("scutil --dns: %v", err)
	}
	return string(out)
}
