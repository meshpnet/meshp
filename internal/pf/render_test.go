package pf

import (
	"net/netip"
	"strings"
	"testing"
)

// lockFor renders a lock and returns its rules, one per element.
func lockFor(t *testing.T, spec LockSpec) []string {
	t.Helper()
	script, err := RenderLock(spec)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	var out []string
	for _, line := range strings.Split(script, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// indexOf is the position of the first rule containing want, or -1.
func indexOf(rules []string, want string) int {
	for i, rule := range rules {
		if strings.Contains(rule, want) {
			return i
		}
	}
	return -1
}

// example is a lock with one of everything, so a test can assert about the whole shape
// rather than build a spec each time.
func example() LockSpec {
	return LockSpec{
		Interface: "utun7",
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.7:51820"),
			netip.MustParseAddrPort("[2001:db8::7]:443"),
		},
		Excluded: []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("fd00:1::/64"),
		},
		PreventDNSLeaks: true,
	}
}

// Everything a device may still reach while it fails closed, and nothing else. Each of these
// is a way for the machine to stay usable while the tunnel is the only way out, and every
// one of them missing is a different bricked laptop.
func TestALockPermitsWhatTheMachineNeedsToStayAlive(t *testing.T) {
	rules := lockFor(t, example())

	for _, want := range []struct{ rule, why string }{
		{"pass out quick on lo0 all no state",
			"the agent's own socket, a local resolver, and everything a desktop does with 127.0.0.1"},
		{"pass out quick on utun7 all no state",
			"the tunnel itself, which is what the traffic is supposed to use"},
		{"pass out quick inet proto { tcp udp } from any to 198.51.100.7 port 51820 no state",
			"the relay, without which there is no tunnel and the lock deadlocks"},
		{"pass out quick inet6 proto { tcp udp } from any to 2001:db8::7 port 443 no state",
			"the control plane, which is the only thing that can tell this device to stop"},
		{"pass out quick inet from any to { 192.168.1.0/24 } no state",
			"the local network: the printer, the NAS and often the default gateway"},
		{"pass out quick inet6 from any to { fd00:1::/64 } no state",
			"the same, for a network that is addressed with IPv6"},
		{"pass out quick proto udp from any to any port { 67 68 546 547 } no state",
			"renewing the lease, without which the machine loses its network some minutes later"},
		{"pass out quick inet6 proto icmp6 all no state",
			"neighbour discovery, without which IPv6 stops immediately"},
		{"block return out quick all",
			"and everything else is refused"},
	} {
		if indexOf(rules, want.rule) < 0 {
			t.Errorf("missing rule %q\n  needed because: %s\n\ngot:\n%s",
				want.rule, want.why, strings.Join(rules, "\n"))
		}
	}
}

// The single most load-bearing token in the file, and the one that has no counterpart in the
// nftables rendering.
//
// pf is last-match-wins. A ruleset whose rules were not quick would evaluate every one of
// them and take the last that matched, which is `block return out quick all` — so a lock
// missing this would refuse the tunnel, the control plane and the local network too, and the
// machine would have no network at all rather than a tunnelled one.
func TestEveryRuleStopsEvaluationWhereItMatches(t *testing.T) {
	for _, rule := range lockFor(t, example()) {
		if !strings.Contains(rule, " quick ") {
			t.Errorf("%q is not quick, so pf would go on looking and the final block would win", rule)
		}
	}
}

// pf consults its state table before its rules, so a pass rule that kept state would wave
// through every subsequent packet of a flow without evaluating it again.
//
// The nftables lock is stateless for the sharper version of the same reason: it deliberately
// has no established-accept, because a connection opened before the lock went up is exactly
// what it exists to stop.
func TestNoRulePermitsAFlowWithoutLookingAtIt(t *testing.T) {
	for _, rule := range lockFor(t, example()) {
		if strings.HasPrefix(rule, "pass ") && !strings.HasSuffix(rule, " no state") {
			t.Errorf("%q keeps state, so a flow it permitted once is never evaluated again", rule)
		}
	}
}

// ADR-0011 is explicit that the error message is the product: a dropped packet leaves an
// application hanging until it times out and the user learns nothing, while a rejected one
// fails immediately with something the operating system can already describe.
func TestTheRefusalIsAudibleAndComesLast(t *testing.T) {
	rules := lockFor(t, example())
	last := rules[len(rules)-1]

	if last != "block return out quick all" {
		t.Errorf("the last rule is %q, and it has to be the audible catch-all", last)
	}
	for _, rule := range rules {
		if strings.HasPrefix(rule, "block ") && !strings.HasPrefix(rule, "block return ") {
			t.Errorf("%q drops silently; ADR-0011 asks for an error the user can act on", rule)
		}
	}
}

// The ordering that makes PreventDNSLeaks mean anything.
//
// The resolver lives on the local network and the carve-out permits the local network, so a
// DNS rule placed after it would refuse nothing at all. The tunnel comes before both, or the
// device would be unable to resolve anything through the tunnel it just brought up — which
// is not a leak, it is the feature working and the machine being useless.
func TestDNSIsRefusedAfterTheTunnelAndBeforeTheLocalNetwork(t *testing.T) {
	rules := lockFor(t, example())

	tunnel := indexOf(rules, "on utun7")
	dns := indexOf(rules, "port 53")
	local := indexOf(rules, "192.168.1.0/24")

	if dns < 0 {
		t.Fatalf("a lock that prevents DNS leaks refuses no DNS:\n%s", strings.Join(rules, "\n"))
	}
	if tunnel >= dns || dns >= local {
		t.Errorf("the order is tunnel=%d dns=%d local=%d; it has to be tunnel, then dns, then local\n%s",
			tunnel, dns, local, strings.Join(rules, "\n"))
	}
}

// Off by default in the sense that matters: a network that has not asked for it gets a lock
// that does not interfere with the resolver it carved out.
func TestWithoutTheDNSPolicyNothingRefusesDNS(t *testing.T) {
	spec := example()
	spec.PreventDNSLeaks = false
	if i := indexOf(lockFor(t, spec), "port 53"); i >= 0 {
		t.Error("a lock that was not asked to prevent DNS leaks refuses DNS anyway")
	}
}

// Removal is a flush, not a ruleset. Rendering something for an empty interface would give a
// caller that renders first and loads second a way to load an empty ruleset over a live lock
// — which reads as "the lock is installed" and refuses nothing.
func TestNoInterfaceRendersNothingToLoad(t *testing.T) {
	script, err := RenderLock(LockSpec{})
	if err != nil {
		t.Fatalf("rendering an empty lock: %v", err)
	}
	if script != "" {
		t.Errorf("an empty lock rendered a ruleset:\n%s", script)
	}
}

// The name arrives as configuration and ends up in a file loaded by a process running as
// root, so it is checked rather than trusted.
func TestAnUnusableInterfaceNameIsRefused(t *testing.T) {
	for _, name := range []string{
		"utun7 all\nblock return out quick on lo0 all", // a second rule smuggled in
		"utun7; pfctl -d",
		"$(reboot)",
		"utun7 no state",
		"",                      // handled separately, and must not render rules
		strings.Repeat("u", 16), // longer than an interface name may be
	} {
		script, err := RenderLock(LockSpec{Interface: name})
		if err == nil && script != "" {
			t.Errorf("%q was accepted as an interface name and rendered:\n%s", name, script)
		}
	}
}

// The same lock renders the same ruleset, so an unchanged specification is not a changed
// file. It matters here more than it looks: loading an anchor resets the counters an
// operator is reading, and pf's state table is flushed on the transition into locked.
func TestTheSameLockRendersTheSameRulesetWhateverOrderItArrivesIn(t *testing.T) {
	one := example()
	two := example()
	two.Endpoints = []netip.AddrPort{two.Endpoints[1], two.Endpoints[0], two.Endpoints[0]}
	two.Excluded = []netip.Prefix{two.Excluded[1], two.Excluded[0], two.Excluded[0]}

	first, err := RenderLock(one)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	second, err := RenderLock(two)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if first != second {
		t.Errorf("the same lock rendered differently:\n--- first\n%s\n--- second\n%s", first, second)
	}
}

// A malformed exclusion costs that exclusion, not the lock.
//
// The alternative is a device that fails to install any lock because one carve-out was
// wrong, which turns a bad prefix into no protection at all — and the caller responds to a
// failed lock by refusing the default route, so a typo would take the whole feature down.
func TestAMalformedExclusionCostsOnlyItself(t *testing.T) {
	spec := example()
	spec.Excluded = append(spec.Excluded, netip.Prefix{})
	spec.Endpoints = append(spec.Endpoints, netip.AddrPort{})

	rules := lockFor(t, spec)
	if indexOf(rules, "192.168.1.0/24") < 0 {
		t.Errorf("one unusable exclusion took the good ones with it:\n%s", strings.Join(rules, "\n"))
	}
	if indexOf(rules, "block return out quick all") < 0 {
		t.Errorf("one unusable exclusion cost the whole lock:\n%s", strings.Join(rules, "\n"))
	}
}
