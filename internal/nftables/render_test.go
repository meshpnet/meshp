package nftables

import (
	"strings"
	"testing"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func rule(src, dst []string, proto string, ports ...string) *meshpv1.PacketFilter_Rule {
	return &meshpv1.PacketFilter_Rule{
		SrcPrefixes: src, DstPrefixes: dst, Protocol: proto, Ports: ports, Allow: true,
	}
}

func filter(inbound ...*meshpv1.PacketFilter_Rule) *meshpv1.PacketFilter {
	return &meshpv1.PacketFilter{Inbound: inbound, DefaultDeny: true}
}

func render(t *testing.T, f *meshpv1.PacketFilter) string {
	t.Helper()
	script, err := Render("meshp0", f)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return script
}

// The bound the whole design rests on: a mistake in here can drop mesh traffic and nothing
// else. Without the first rule in each chain, a policy mistake would take the host off its
// own network — including the connection an operator would use to fix it.
func TestTrafficOffTheInterfaceIsAcceptedFirst(t *testing.T) {
	script := render(t, filter(rule([]string{"100.90.0.2/32"}, []string{"100.90.0.1/32"}, "tcp", "22")))

	for _, chain := range []struct{ name, match string }{
		{"input", "iifname"},
		{"output", "oifname"},
	} {
		want := "add rule inet meshp " + chain.name + " " + chain.match + ` != "meshp0" accept`
		if !strings.Contains(script, want) {
			t.Fatalf("%s chain does not let non-mesh traffic past:\n%s", chain.name, script)
		}
		// And it is first, before anything that could drop.
		body := chainBody(t, script, chain.name)
		if len(body) == 0 || !strings.Contains(body[0], chain.match+` != "meshp0" accept`) {
			t.Errorf("%s chain's first rule is %q", chain.name, firstOr(body))
		}
	}

	// The chain policy must be accept too, so an empty chain fails open for the host.
	if strings.Contains(script, "policy drop") {
		t.Error("a chain defaults to drop; a rendering bug would cut the host off entirely")
	}
}

// Without conntrack, a device permitted to reach a server on tcp/22 sends its SYN and has
// the SYN-ACK dropped on the way back, so every allowed connection hangs instead of working.
func TestReturnTrafficIsAccepted(t *testing.T) {
	script := render(t, filter(rule([]string{"100.90.0.2/32"}, []string{"100.90.0.1/32"}, "tcp", "22")))
	for _, chain := range []string{"input", "output"} {
		if !strings.Contains(script, "add rule inet meshp "+chain+" ct state established,related accept") {
			t.Errorf("%s chain drops return traffic for connections it allowed", chain)
		}
	}
}

func TestARuleBecomesAMatchingExpression(t *testing.T) {
	script := render(t, filter(rule(
		[]string{"100.90.0.2/32", "100.90.0.3/32"}, []string{"100.90.0.1/32"}, "tcp", "22", "8000-8100")))

	want := `ip saddr { 100.90.0.2/32, 100.90.0.3/32 } ip daddr 100.90.0.1/32 tcp dport { 22, 8000-8100 } accept`
	if !strings.Contains(script, want) {
		t.Fatalf("expected\n  %s\nin\n%s", want, script)
	}
}

// A rule cannot match an IPv4 source against an IPv6 destination, and a table that tried
// would be rejected as a whole — taking the working half of the policy with it.
func TestFamiliesAreRenderedSeparately(t *testing.T) {
	script := render(t, filter(rule(
		[]string{"100.90.0.2/32", "fd7c::2/128"},
		[]string{"100.90.0.1/32", "fd7c::1/128"}, "any")))

	if !strings.Contains(script, "ip saddr 100.90.0.2/32 ip daddr 100.90.0.1/32 accept") {
		t.Errorf("the IPv4 half is missing:\n%s", script)
	}
	if !strings.Contains(script, "ip6 saddr fd7c::2/128 ip6 daddr fd7c::1/128 accept") {
		t.Errorf("the IPv6 half is missing:\n%s", script)
	}
	// And never crossed.
	if strings.Contains(script, "ip saddr 100.90.0.2/32 ip6 daddr") {
		t.Error("an IPv4 source was matched against an IPv6 destination")
	}
}

// A rule whose sides do not meet in a family is not a rule in that family. Emitting one
// half would leave the other side unconstrained, which turns a narrow rule into a wide one.
func TestAOneSidedFamilyIsSkippedEntirely(t *testing.T) {
	script := render(t, filter(rule(
		[]string{"fd7c::2/128"}, // v6 source only
		[]string{"100.90.0.1/32"}, "any")))

	for _, line := range chainBody(t, script, "input") {
		if strings.Contains(line, "saddr") || strings.Contains(line, "daddr") {
			t.Errorf("a rule was emitted for a family present on only one side: %q", line)
		}
	}
}

func TestProtocolsRenderCorrectly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proto string
		ports []string
		want  string
	}{
		{"any means no protocol match", "any", nil, "ip saddr 100.90.0.2/32 ip daddr 100.90.0.1/32 accept"},
		{"tcp with no ports means every port", "tcp", nil, "meta l4proto tcp accept"},
		{"udp with a port", "udp", []string{"53"}, "udp dport 53 accept"},
		{"icmp", "icmp", nil, "ip protocol icmp accept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := render(t, filter(rule(
				[]string{"100.90.0.2/32"}, []string{"100.90.0.1/32"}, tc.proto, tc.ports...)))
			if !strings.Contains(script, tc.want) {
				t.Errorf("expected %q in\n%s", tc.want, script)
			}
		})
	}
}

// Nothing from the wire reaches a script that runs as root. A control plane — compromised,
// or merely buggy — must not be able to put its own text into it.
func TestNothingUnparseableIsInterpolated(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *meshpv1.PacketFilter_Rule
	}{
		{"an injected command in a source", rule(
			[]string{"100.90.0.2/32 accept; add rule inet meshp input accept #"},
			[]string{"100.90.0.1/32"}, "any")},
		{"an injected command in a destination", rule(
			[]string{"100.90.0.2/32"},
			[]string{"; flush ruleset"}, "any")},
		{"an unparseable protocol", rule(
			[]string{"100.90.0.2/32"}, []string{"100.90.0.1/32"}, "tcp; drop")},
		{"an unparseable port", rule(
			[]string{"100.90.0.2/32"}, []string{"100.90.0.1/32"}, "tcp", "22 accept;")},
		{"a bare address rather than a prefix", rule(
			[]string{"100.90.0.2"}, []string{"100.90.0.1/32"}, "any")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Render("meshp0", filter(tc.r)); err == nil {
				t.Fatal("rendered a ruleset from input it could not parse")
			}
		})
	}

	// The interface name is configuration and ends up in a quoted string.
	for _, bad := range []string{"", "meshp0; flush ruleset", "a name with spaces", strings.Repeat("x", 16)} {
		if _, err := Render(bad, filter()); err == nil {
			t.Errorf("accepted interface name %q", bad)
		}
	}
}

// A rule that does not allow means something upstream is confused, and its intent cannot be
// guessed — the language has no way to express a denial.
func TestADenyRuleIsRefused(t *testing.T) {
	r := rule([]string{"100.90.0.2/32"}, []string{"100.90.0.1/32"}, "any")
	r.Allow = false
	if _, err := Render("meshp0", filter(r)); err == nil {
		t.Fatal("rendered a rule that is not an allow rule")
	}
}

// A policy that permits nothing still has to be a table that drops everything: an empty
// filter and an absent one mean opposite things.
func TestAnEmptyFilterStillDrops(t *testing.T) {
	script := render(t, &meshpv1.PacketFilter{DefaultDeny: true})
	if !strings.Contains(script, "counter drop") {
		t.Fatalf("an empty filter renders no drop, so it would permit everything:\n%s", script)
	}
}

// No policy means no enforcement, and it must be possible to go back to that state — a
// withdrawn policy that left its table behind would go on denying traffic forever.
func TestANilFilterRemovesTheTable(t *testing.T) {
	script, err := Render("meshp0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "delete table inet meshp") {
		t.Fatalf("a nil filter does not remove the table:\n%s", script)
	}
	if strings.Contains(script, "counter drop") || strings.Contains(script, "add chain") {
		t.Fatalf("a nil filter still installs rules:\n%s", script)
	}
}

// Every ruleset starts by removing what was there. Loading one on top of the last would
// leave rules from a policy nobody is enforcing any more, and there would be no window in
// which the two disagreed only because nft applies a whole file as one transaction.
func TestEveryRulesetReplacesWhatCameBefore(t *testing.T) {
	script := render(t, filter(rule([]string{"100.90.0.2/32"}, []string{"100.90.0.1/32"}, "any")))
	lines := strings.Split(strings.TrimSpace(script), "\n")
	if len(lines) < 3 {
		t.Fatalf("script is too short to replace anything:\n%s", script)
	}
	if lines[0] != "add table inet meshp" || lines[1] != "delete table inet meshp" {
		t.Fatalf("a ruleset does not begin by removing the previous one:\n%s", script)
	}
	// add-then-delete rather than delete alone, because deleting a table that is not there
	// fails and would make the first apply on a fresh host an error.
	if strings.Count(script, "delete table inet meshp") != 1 {
		t.Errorf("the table is removed more than once:\n%s", script)
	}
}

// Rendering the same filter twice gives the same script, so nothing downstream mistakes
// rendering order for a policy change.
func TestRenderingIsDeterministic(t *testing.T) {
	f := filter(
		rule([]string{"100.90.0.9/32", "100.90.0.2/32", "fd7c::2/128"},
			[]string{"100.90.0.1/32", "fd7c::1/128"}, "tcp", "443", "22"),
	)
	first := render(t, f)
	for range 20 {
		if got := render(t, f); got != first {
			t.Fatalf("two renderings differ:\n%s\n---\n%s", first, got)
		}
	}
}

// chainBody returns the rule lines added to one chain, in order.
func chainBody(t *testing.T, script, chain string) []string {
	t.Helper()
	prefix := "add rule inet meshp " + chain + " "
	var out []string
	for _, line := range strings.Split(script, "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			out = append(out, rest)
		}
	}
	return out
}

func firstOr(lines []string) string {
	if len(lines) == 0 {
		return "<nothing>"
	}
	return lines[0]
}

// ---------------------------------------------------------------------------
// Forwarding

func carried(prefixes ...string) []*meshpv1.AdvertisedRoutes_Group {
	return []*meshpv1.AdvertisedRoutes_Group{{RouteGroupId: "g", Name: "branch", Prefixes: prefixes}}
}

func renderFwd(t *testing.T, groups []*meshpv1.AdvertisedRoutes_Group) string {
	t.Helper()
	script, err := RenderForward("meshp0", groups)
	if err != nil {
		t.Fatalf("RenderForward: %v", err)
	}
	return script
}

// Two things have to be true for a packet to cross, and both must be here: the forward
// chain has to accept it, and the source has to be rewritten — a LAN device replying to
// 100.90.0.2 has no route to it and never will.
func TestForwardingAcceptsAndRewrites(t *testing.T) {
	script := renderFwd(t, carried("192.168.10.0/24"))

	if !strings.Contains(script, `forward iifname "meshp0" ip daddr 192.168.10.0/24 accept`) {
		t.Errorf("nothing accepts traffic out of the tunnel:\n%s", script)
	}
	if !strings.Contains(script, `forward oifname "meshp0" ip saddr 192.168.10.0/24 accept`) {
		t.Errorf("nothing accepts the LAN answering back:\n%s", script)
	}
	if !strings.Contains(script, `postrouting iifname "meshp0" ip daddr 192.168.10.0/24 masquerade`) {
		t.Errorf("the source is not rewritten, so the LAN has no route back:\n%s", script)
	}
	if !strings.Contains(script, "ct state established,related accept") {
		t.Errorf("without conntrack every forwarded connection establishes and hangs:\n%s", script)
	}
	// Its own table: a policy change must not disturb a gateway's forwarding.
	if !strings.Contains(script, "inet meshp_fwd") {
		t.Errorf("forwarding shares the policy table:\n%s", script)
	}
}

// A customer who has allowlisted an outbound IP with a bank depends on it surviving a
// failover, which masquerade cannot promise and snat can.
func TestAStableEgressAddressIsUsedWhenGiven(t *testing.T) {
	groups := carried("192.168.10.0/24")
	groups[0].StableEgressIp = "203.0.113.7"

	script := renderFwd(t, groups)
	if !strings.Contains(script, "snat to 203.0.113.7") {
		t.Errorf("the stable egress address was not used:\n%s", script)
	}
	if strings.Contains(script, "masquerade") {
		t.Errorf("it masquerades anyway, so the allowlisted address would change:\n%s", script)
	}
}

// A device that has stopped carrying must stop forwarding, or it stays a gateway nobody
// knows about.
func TestNoGroupsRemovesTheTable(t *testing.T) {
	script := renderFwd(t, nil)
	if !strings.Contains(script, "delete table inet meshp_fwd") {
		t.Fatalf("nothing removes the forwarding table:\n%s", script)
	}
	if strings.Contains(script, "masquerade") || strings.Contains(script, "add chain") {
		t.Fatalf("it still installs forwarding rules:\n%s", script)
	}
}

// An egress advertiser forwards anything out of the tunnel — that is what being somebody's
// way to the internet means — but a 0.0.0.0/0 daddr match would also catch traffic to this
// host itself, so it is a catch-all on the interface instead.
func TestEgressForwardsEverythingOutOfTheTunnel(t *testing.T) {
	script := renderFwd(t, carried("0.0.0.0/0", "::/0"))

	if !strings.Contains(script, `forward iifname "meshp0" accept`) {
		t.Errorf("an egress advertiser forwards nothing:\n%s", script)
	}
	if !strings.Contains(script, `postrouting iifname "meshp0" oifname != "meshp0" masquerade`) {
		t.Errorf("egress traffic is not masqueraded:\n%s", script)
	}
	if strings.Contains(script, "daddr 0.0.0.0/0") {
		t.Errorf("a default route was matched as a prefix, which also catches this host:\n%s", script)
	}
}

// A chain that somehow ends up empty must not cut this host off from forwarding it was
// already doing for something else — Docker, another VPN, anything.
func TestForwardingFailsOpenForTheHost(t *testing.T) {
	script := renderFwd(t, carried("192.168.10.0/24"))
	if strings.Contains(script, "policy drop") {
		t.Errorf("the forward chain defaults to drop:\n%s", script)
	}
}

func TestForwardingRefusesWhatItCannotParse(t *testing.T) {
	if _, err := RenderForward("meshp0", carried("not-a-prefix")); err == nil {
		t.Error("rendered forwarding for a prefix it could not parse")
	}
	if _, err := RenderForward("meshp0; flush ruleset", carried("192.168.10.0/24")); err == nil {
		t.Error("accepted an interface name that is not one")
	}
	// An unparseable stable address falls back to masquerade rather than reaching the
	// script: forwarding with the wrong source is better than a ruleset that will not load.
	groups := carried("192.168.10.0/24")
	groups[0].StableEgressIp = "; drop"
	script, err := RenderForward("meshp0", groups)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "masquerade") || strings.Contains(script, "drop") {
		t.Errorf("an unparseable egress address reached the script:\n%s", script)
	}
}

func TestForwardRenderingIsDeterministic(t *testing.T) {
	groups := carried("192.168.20.0/24", "192.168.10.0/24", "fd00::/64")
	first := renderFwd(t, groups)
	for range 20 {
		if got := renderFwd(t, groups); got != first {
			t.Fatalf("two renderings differ:\n%s\n---\n%s", first, got)
		}
	}
}
