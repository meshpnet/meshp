//go:build windows

package resolved

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// requireAdmin skips what cannot run without it. The policy table is under HKLM.
func requireAdmin(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs administrator: the name resolution policy table is under HKLM")
	}
}

// A domain becomes a suffix rule, deduplicated and in a stable order.
//
// The leading dot is the whole of split DNS here: without it a rule matches one exact name
// and everything under the network's domain goes wherever it was already going, which is a
// resolver that looks configured and answers nothing.
func TestDomainsBecomeSuffixRules(t *testing.T) {
	got := cleanDomains([]string{"Example.Meshp", "example.meshp.", "  ", ".other.meshp", ""})
	want := []string{".example.meshp", ".other.meshp"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
			break
		}
	}
}

// The same domain on the same interface is the same rule, and a different one is not.
//
// Configure runs on every reconcile. A key name that varied would leave one rule per pass
// until the policy table was the largest thing in the registry.
func TestARuleKeyIsAFunctionOfWhatItIsFor(t *testing.T) {
	first := ruleKeyName("meshp0", ".example.meshp")
	if first != ruleKeyName("meshp0", ".example.meshp") {
		t.Error("the same domain produced two different rules, so every reconcile would add one")
	}
	if first == ruleKeyName("meshp0", ".other.meshp") {
		t.Error("two domains share a rule, so configuring one would remove the other")
	}
	if first == ruleKeyName("meshp1", ".example.meshp") {
		t.Error("two interfaces share a rule, so one membership leaving would take another's names")
	}
	if !strings.HasPrefix(first, "{") || !strings.HasSuffix(first, "}") {
		t.Errorf("%q is not the braced form every rule Windows makes uses", first)
	}
}

// A resolver on any port but 53 is refused rather than configured.
//
// This is the safety property the whole implementation turns on. Windows accepts a rule
// naming a port, stores an empty server list, and black-holes the namespace while reporting
// success (ADR-0029) — so a version of this that passed the port through would break exactly
// the names it was asked to resolve and report that it had configured them.
func TestAResolverOnTheWrongPortIsRefused(t *testing.T) {
	err := (&System{}).Configure(t.Context(), "meshp0",
		netip.MustParseAddrPort("127.0.0.1:15353"), []string{"example.meshp"})

	if err == nil {
		t.Fatal("a resolver on a high port was accepted; the rule Windows writes for that " +
			"names no server at all and the domain resolves to nothing")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("got %v, want it to say this platform cannot do that", err)
	}
}

// The whole of it, against the real policy table and the real resolver.
//
// The assertion is that a query arrives, not that a registry key exists. Getting the values
// almost right produces a rule Windows accepts and does not use, which a structural test
// would call a pass — the failure mode ADR-0029 exists to describe.
func TestAConfiguredDomainReachesMeshp(t *testing.T) {
	requireAdmin(t)

	// A namespace nobody else uses, under a reserved TLD so nothing real is disturbed even
	// if a rule outlives this test.
	const domain = "slice.meshp-test.invalid"
	const iface = "meshptestdns0"

	server, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Skipf("something already holds 127.0.0.1:53 on this machine, which is the case "+
			"ADR-0029 says meshp reports rather than works around: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	sys := &System{}
	t.Cleanup(func() { _ = sys.Revert(context.WithoutCancel(t.Context()), iface) })
	if err := sys.Configure(t.Context(), iface,
		netip.MustParseAddrPort("127.0.0.1:53"), []string{domain}); err != nil {
		t.Fatalf("configuring: %v", err)
	}

	arrived := make(chan int, 1)
	go func() {
		buf := make([]byte, 1500)
		_ = server.SetReadDeadline(time.Now().Add(20 * time.Second))
		if n, _, err := server.ReadFrom(buf); err == nil {
			arrived <- n
		} else {
			arrived <- 0
		}
	}()

	// The policy table is read by the DNS client rather than pushed to it, so a rule written
	// a moment ago may not be in force yet. Asked more than once for that reason.
	go func() {
		for range 6 {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			_, _ = net.DefaultResolver.LookupHost(ctx, "a."+domain)
			cancel()
			time.Sleep(time.Second)
		}
	}()

	if n := <-arrived; n == 0 {
		t.Fatal("no query reached meshp's resolver for a domain it was configured to serve. " +
			"The rule exists — Windows accepts one it cannot use and says nothing — so what " +
			"this is telling us is that the values written are not the ones the DNS client reads")
	}
}

// A rule comes off, and leaves nothing.
//
// ADR-0021's test for whether a platform gets an implementation at all is whether there is a
// real undo. This is that, asserted rather than assumed.
func TestRevertLeavesNothingBehind(t *testing.T) {
	requireAdmin(t)

	const iface = "meshptestdns1"
	sys := &System{}
	t.Cleanup(func() { _ = sys.Revert(context.WithoutCancel(t.Context()), iface) })

	if err := sys.Configure(t.Context(), iface, netip.MustParseAddrPort("127.0.0.1:53"),
		[]string{"one.meshp-test.invalid", "two.meshp-test.invalid"}); err != nil {
		t.Fatalf("configuring: %v", err)
	}
	before, err := sys.rulesFor(iface)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(before) != 2 {
		t.Fatalf("configured two domains and found %d rules", len(before))
	}

	// Fewer domains than last time: the rule for the one that went away goes with it, or a
	// name nobody serves any more is directed at meshp forever.
	if err := sys.Configure(t.Context(), iface, netip.MustParseAddrPort("127.0.0.1:53"),
		[]string{"one.meshp-test.invalid"}); err != nil {
		t.Fatalf("reconfiguring: %v", err)
	}
	if narrowed, err := sys.rulesFor(iface); err != nil || len(narrowed) != 1 {
		t.Fatalf("after narrowing: %d rules, err=%v", len(narrowed), err)
	}

	if err := sys.Revert(t.Context(), iface); err != nil {
		t.Fatalf("reverting: %v", err)
	}
	after, err := sys.rulesFor(iface)
	if err != nil {
		t.Fatalf("listing after revert: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("%d rule(s) survived the revert: %v", len(after), after)
	}
}

// Reverting an interface that was never configured is success.
//
// Teardown always runs. A membership going away asks for this whether or not names were ever
// configured, and an error there would report a failure to remove something never made.
func TestRevertingWhatWasNeverConfigured(t *testing.T) {
	if err := (&System{}).Revert(t.Context(), "meshpnope0"); err != nil {
		t.Errorf("reverting an interface that never had rules: %v", err)
	}
}

// Nobody else's rules are touched.
//
// The policy table is shared. meshp finds its own by a marker it writes, and a rule without
// that marker belongs to whoever made it — a corporate DNS policy, most likely, on exactly
// the machines meshp most wants not to break.
func TestSomebodyElsesRuleIsLeftAlone(t *testing.T) {
	requireAdmin(t)

	const foreign = `{0BADC0DE-0000-4000-8000-00000BADC0DE}`
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyPath+`\`+foreign,
		registry.SET_VALUE)
	if err != nil {
		t.Skipf("cannot write to the policy table: %v", err)
	}
	_ = key.SetStringsValue("Name", []string{".somebody-else.invalid"})
	_ = key.Close()
	t.Cleanup(func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, policyPath+`\`+foreign) })

	sys := &System{}
	const iface = "meshptestdns2"
	if err := sys.Configure(t.Context(), iface, netip.MustParseAddrPort("127.0.0.1:53"),
		[]string{"ours.meshp-test.invalid"}); err != nil {
		t.Fatalf("configuring: %v", err)
	}
	if err := sys.Revert(t.Context(), iface); err != nil {
		t.Fatalf("reverting: %v", err)
	}

	if _, err := registry.OpenKey(registry.LOCAL_MACHINE, policyPath+`\`+foreign, registry.QUERY_VALUE); err != nil {
		t.Errorf("a rule meshp did not make was removed: %v", err)
	}
}
