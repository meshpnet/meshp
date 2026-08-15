package nftables

import (
	"net/netip"
	"strings"
	"testing"
)

func aLock() LockSpec {
	return LockSpec{
		Interface: "meshp0",
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.7:3478"),
			netip.MustParseAddrPort("[2001:db8::1]:443"),
		},
		Excluded: []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("fd00::/64"),
		},
	}
}

func renderLock(t *testing.T, spec LockSpec) string {
	t.Helper()
	script, err := RenderLock(spec)
	if err != nil {
		t.Fatalf("RenderLock: %v", err)
	}
	return script
}

// The whole point: anything not named is refused.
func TestTheLockRefusesWhatItDoesNotName(t *testing.T) {
	script := renderLock(t, aLock())

	if !strings.Contains(script, "policy drop") {
		t.Error("the output chain does not default to dropping; an empty chain would leak")
	}
	if !strings.Contains(script, "output reject") {
		t.Error("nothing refuses the traffic that matched no rule")
	}
}

// Each of these is a way the machine stays usable while it fails closed. Losing one is not a
// degraded lock, it is a device somebody has to physically recover.
func TestTheLockLetsTheMachineKeepWorking(t *testing.T) {
	script := renderLock(t, aLock())

	for _, want := range []struct {
		rule, why string
	}{
		{"output oif lo accept", "loopback, or the agent cannot reach its own socket"},
		{`output oifname "meshp0" accept`, "the tunnel, which is what the traffic is for"},
		{"ip daddr 198.51.100.7 udp dport 3478 accept", "the relay, or the tunnel cannot come up"},
		{"ip6 daddr 2001:db8::1 tcp dport 443 accept", "the control plane, over IPv6"},
		{"ip daddr 192.168.1.0/24 accept", "the local network"},
		{"ip6 daddr fd00::/64 accept", "the local network, over IPv6"},
		{"udp dport { 67, 68, 546, 547 } accept", "DHCP, or the lease expires and the machine falls off"},
		{"meta l4proto ipv6-icmp accept", "neighbour discovery, or IPv6 stops working at once"},
	} {
		if !strings.Contains(script, want.rule) {
			t.Errorf("missing %q\n  needed for: %s\n%s", want.rule, want.why, script)
		}
	}
}

// A connection that was already open when the tunnel dropped is precisely what this exists
// to stop. The forwarding table needs conntrack or connections hang; this must not have it.
func TestTheLockDoesNotSpareEstablishedConnections(t *testing.T) {
	script := renderLock(t, aLock())

	if strings.Contains(script, "ct state established") {
		t.Error("established connections are spared, so a leak in progress continues after the tunnel drops")
	}
}

// Rules that outlive the process are only safe if they can be taken off deliberately.
func TestAnEmptySpecRemovesTheLock(t *testing.T) {
	script := renderLock(t, LockSpec{})

	if !strings.Contains(script, "delete table inet "+LockTableName) {
		t.Fatalf("an empty spec does not remove the table:\n%s", script)
	}
	if strings.Contains(script, "policy drop") {
		t.Errorf("an empty spec still installed a locking chain:\n%s", script)
	}
}

// Removal has to work whether or not a lock is currently installed, because the caller that
// needs it most is an agent starting up with no idea what its previous life did.
func TestRemovalIsIdempotent(t *testing.T) {
	script := renderLock(t, LockSpec{})

	add := strings.Index(script, "add table inet "+LockTableName)
	del := strings.Index(script, "delete table inet "+LockTableName)
	if add < 0 || del < 0 || add > del {
		t.Errorf("removal does not add before deleting, so it fails when no table exists:\n%s", script)
	}
}

// The script runs as root and the endpoints come from the control plane.
func TestTheLockRefusesAnUnusableInterfaceName(t *testing.T) {
	_, err := RenderLock(LockSpec{Interface: "meshp0; rm -rf /"})
	if err == nil {
		t.Fatal("an interface name with a shell metacharacter was accepted")
	}
}

// An exclusion nobody can parse should cost that exclusion, not the whole lock. Refusing to
// render would leave the device with no lock at all, which is the failure that matters.
func TestAnUnusableExclusionDoesNotCostTheLock(t *testing.T) {
	spec := aLock()
	spec.Excluded = append(spec.Excluded, netip.Prefix{})
	script := renderLock(t, spec)

	if !strings.Contains(script, "output reject") {
		t.Error("one bad exclusion removed the lock entirely")
	}
	if !strings.Contains(script, "ip daddr 192.168.1.0/24 accept") {
		t.Error("the usable exclusions were lost with the unusable one")
	}
}

// The same specification has to render the same script, or every reconcile pass reloads a
// ruleset that has not changed and resets its counters.
func TestTheSameSpecRendersTheSameScript(t *testing.T) {
	spec := aLock()
	shuffled := LockSpec{
		Interface: spec.Interface,
		Endpoints: []netip.AddrPort{spec.Endpoints[1], spec.Endpoints[0], spec.Endpoints[1]},
		Excluded:  []netip.Prefix{spec.Excluded[1], spec.Excluded[0]},
	}

	if renderLock(t, spec) != renderLock(t, shuffled) {
		t.Error("the same lock rendered differently depending on the order it was given in")
	}
}

// The hole this closes is the one the carve-out has to leave. The local network is
// permitted so the device keeps its printer and its gateway, and the resolver lives on the
// local network — so a tunnel that is up while queries go to the router discloses every
// name the user looks up to whoever runs that network.
func TestPreventingDNSLeaksRefusesPlaintextDNS(t *testing.T) {
	spec := aLock()
	spec.PreventDNSLeaks = true
	script := renderLock(t, spec)

	for _, want := range []string{"udp dport 53 reject", "tcp dport 53 reject"} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q:\n%s", want, script)
		}
	}
}

// And it has to come first, because refusing DNS after the local network has been permitted
// refuses nothing at all: the resolver is on the local network.
func TestTheDNSRefusalComesBeforeTheCarveout(t *testing.T) {
	spec := aLock()
	spec.PreventDNSLeaks = true
	script := renderLock(t, spec)

	dns := strings.Index(script, "udp dport 53 reject")
	lan := strings.Index(script, "ip daddr 192.168.1.0/24 accept")
	if dns < 0 || lan < 0 {
		t.Fatalf("expected both rules:\n%s", script)
	}
	if dns > lan {
		t.Errorf("the local network is permitted before DNS is refused, so DNS to the "+
			"router is still allowed:\n%s", script)
	}
}

// The tunnel first, or a device that prevented leaks would refuse its own resolver — the
// one it is meant to be using.
func TestDNSThroughTheTunnelIsStillAllowed(t *testing.T) {
	spec := aLock()
	spec.PreventDNSLeaks = true
	script := renderLock(t, spec)

	tunnel := strings.Index(script, `output oifname "meshp0" accept`)
	dns := strings.Index(script, "udp dport 53 reject")
	if tunnel < 0 || dns < 0 {
		t.Fatalf("expected both rules:\n%s", script)
	}
	if tunnel > dns {
		t.Error("DNS is refused before the tunnel is permitted, so the device cannot resolve at all")
	}
	if lo := strings.Index(script, "output oif lo accept"); lo > dns {
		t.Error("DNS is refused before loopback, which breaks a local stub resolver")
	}
}

// Off by default, because it is a policy the network states rather than something a device
// decides for itself.
func TestDNSIsNotRefusedUnlessAsked(t *testing.T) {
	script := renderLock(t, aLock())

	if strings.Contains(script, "dport 53") {
		t.Errorf("DNS was refused without the network asking:\n%s", script)
	}
}
