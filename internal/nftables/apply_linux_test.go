//go:build linux

package nftables

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// sampleFilter is a policy with both families and a port range, so a load exercises more
// of the rendering than a single rule would.
func sampleFilter() *meshpv1.PacketFilter {
	return &meshpv1.PacketFilter{
		DefaultDeny: true,
		Inbound: []*meshpv1.PacketFilter_Rule{{
			SrcPrefixes: []string{"100.90.0.2/32", "fd7c::2/128"},
			DstPrefixes: []string{"100.90.0.1/32", "fd7c::1/128"},
			Protocol:    "tcp", Ports: []string{"22", "8000-8100"}, Allow: true,
		}},
		Outbound: []*meshpv1.PacketFilter_Rule{{
			SrcPrefixes: []string{"100.90.0.1/32"},
			DstPrefixes: []string{"100.90.0.2/32"},
			Protocol:    "any", Allow: true,
		}},
	}
}

// These run against a real kernel and a real nft. A rendering mistake — a missing keyword,
// a malformed set, an expression nft parses differently from how I read the manual — is
// invisible to every test that only inspects the string, and shows up on a customer's host
// as a policy that silently does not load.

func requireNFT(t *testing.T) {
	t.Helper()
	if !Available(context.Background()) {
		t.Skip("nft is unavailable or unusable here; run this in the privileged container")
	}
	t.Cleanup(func() {
		// Never leave meshp's table behind on a host that ran the tests.
		script, err := Render("meshp0", nil)
		if err == nil {
			_ = Apply(context.Background(), script)
		}
	})
}

func listTable(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", TableName).CombinedOutput()
	if err != nil {
		t.Fatalf("listing the table: %v: %s", err, out)
	}
	return string(out)
}

// The one thing string tests cannot answer: does the kernel accept this.
func TestARenderedRulesetLoads(t *testing.T) {
	requireNFT(t)
	ctx := context.Background()

	script, err := Render("meshp0", sampleFilter())
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, script); err != nil {
		t.Fatalf("the kernel refused a ruleset this package rendered: %v", err)
	}

	listed := listTable(t)
	for _, want := range []string{
		`iifname != "meshp0" accept`,
		"ct state established,related accept",
		"100.90.0.2",
		"tcp dport",
		"counter",
		"drop",
	} {
		if !strings.Contains(listed, want) {
			t.Errorf("the loaded table does not contain %q:\n%s", want, listed)
		}
	}
}

// Loading twice must be safe, because the reconciler does exactly that whenever a policy
// changes. A ruleset that appended to the last would accumulate rules from policies nobody
// is enforcing any more.
func TestLoadingReplacesRatherThanAccumulates(t *testing.T) {
	requireNFT(t)
	ctx := context.Background()

	script, err := Render("meshp0", sampleFilter())
	if err != nil {
		t.Fatal(err)
	}

	if err := Apply(ctx, script); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Compared against itself after one load rather than counted, because a rule's addresses
	// legitimately appear in more than one chain — an absolute count would be asserting the
	// shape of the fixture rather than that loading replaces.
	once := listTable(t)

	for range 3 {
		if err := Apply(ctx, script); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}
	if got := listTable(t); got != once {
		t.Errorf("loading the same ruleset again changed the table:\nafter one:\n%s\nafter four:\n%s",
			once, got)
	}
}

// A withdrawn policy has to leave nothing behind, or it goes on denying traffic the network
// no longer denies.
func TestANilFilterRemovesTheTableFromTheKernel(t *testing.T) {
	requireNFT(t)
	ctx := context.Background()

	loaded, err := Render("meshp0", sampleFilter())
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, loaded); err != nil {
		t.Fatal(err)
	}

	empty, err := Render("meshp0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, empty); err != nil {
		t.Fatalf("removing the table: %v", err)
	}

	if out, err := exec.Command("nft", "list", "table", "inet", TableName).CombinedOutput(); err == nil {
		t.Fatalf("meshp's table survived a withdrawn policy:\n%s", out)
	}
}

// Removing a table that was never there is the first thing a fresh host does, so it must
// not be an error.
func TestRemovingATableThatIsNotThere(t *testing.T) {
	requireNFT(t)
	script, err := Render("meshp0", nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := Apply(context.Background(), script); err != nil {
			t.Fatalf("removing an absent table: %v", err)
		}
	}
}

// An empty policy is a table that drops all mesh traffic, and the kernel has to accept that
// as readily as one full of rules.
func TestAnEmptyPolicyLoads(t *testing.T) {
	requireNFT(t)
	script, err := Render("meshp0", &meshpv1.PacketFilter{DefaultDeny: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("the kernel refused an empty policy: %v", err)
	}
	if !strings.Contains(listTable(t), "drop") {
		t.Error("an empty policy loaded without a drop")
	}
}

// A script the kernel refuses must be reported with what nft said, or a rendering mistake
// is undiagnosable.
func TestAMalformedScriptIsReportedWithItsReason(t *testing.T) {
	requireNFT(t)
	err := Apply(context.Background(), "add rule inet meshp nosuchchain accept\n")
	if err == nil {
		t.Fatal("nft accepted a script naming a chain that does not exist")
	}
	if !strings.Contains(err.Error(), "meshp") {
		t.Errorf("the error does not carry nft's complaint: %v", err)
	}
}

// The forwarding ruleset has to load too, and it uses expressions the filter does not — a
// nat hook, masquerade, snat. A mistake in any of them is invisible to a string test.
func TestAForwardingRulesetLoads(t *testing.T) {
	requireNFT(t)
	ctx := context.Background()

	groups := []*meshpv1.AdvertisedRoutes_Group{
		{RouteGroupId: "g", Name: "branch", Prefixes: []string{"192.168.10.0/24", "fd00::/64"}},
	}
	script, err := RenderForward("meshp0", groups)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, script); err != nil {
		t.Fatalf("the kernel refused the forwarding ruleset: %v", err)
	}
	t.Cleanup(func() {
		if empty, err := RenderForward("meshp0", nil); err == nil {
			_ = Apply(context.Background(), empty)
		}
	})

	out, err := exec.Command("nft", "list", "table", "inet", ForwardTableName).CombinedOutput()
	if err != nil {
		t.Fatalf("listing the forwarding table: %v: %s", err, out)
	}
	for _, want := range []string{"masquerade", "192.168.10.0/24", "ct state established,related accept"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the loaded table does not contain %q:\n%s", want, out)
		}
	}
}

// snat is a different expression from masquerade and fails differently if it is wrong.
func TestAStableEgressRulesetLoads(t *testing.T) {
	requireNFT(t)
	groups := []*meshpv1.AdvertisedRoutes_Group{
		{RouteGroupId: "g", Prefixes: []string{"192.168.10.0/24"}, StableEgressIp: "203.0.113.7"},
	}
	script, err := RenderForward("meshp0", groups)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("the kernel refused a stable-egress ruleset: %v", err)
	}
	t.Cleanup(func() {
		if empty, err := RenderForward("meshp0", nil); err == nil {
			_ = Apply(context.Background(), empty)
		}
	})
}

// An egress advertiser's catch-all rules are the ones most likely to be rejected, because
// they match on interface rather than on address.
func TestAnEgressForwardingRulesetLoads(t *testing.T) {
	requireNFT(t)
	groups := []*meshpv1.AdvertisedRoutes_Group{
		{RouteGroupId: "g", Prefixes: []string{"0.0.0.0/0", "::/0"}},
	}
	script, err := RenderForward("meshp0", groups)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("the kernel refused an egress ruleset: %v", err)
	}
	t.Cleanup(func() {
		if empty, err := RenderForward("meshp0", nil); err == nil {
			_ = Apply(context.Background(), empty)
		}
	})
}

// The two tables are separate so a policy change does not disturb a gateway's forwarding.
func TestPolicyAndForwardingDoNotDisturbEachOther(t *testing.T) {
	requireNFT(t)
	ctx := context.Background()

	fwd, err := RenderForward("meshp0", []*meshpv1.AdvertisedRoutes_Group{
		{RouteGroupId: "g", Prefixes: []string{"192.168.10.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, fwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if empty, err := RenderForward("meshp0", nil); err == nil {
			_ = Apply(context.Background(), empty)
		}
	})

	// Now reload the policy, which rebuilds its own table entirely.
	policy, err := Render("meshp0", sampleFilter())
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, policy); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("nft", "list", "table", "inet", ForwardTableName).CombinedOutput()
	if err != nil {
		t.Fatalf("the forwarding table did not survive a policy reload: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "192.168.10.0/24") {
		t.Errorf("forwarding lost its rules when the policy reloaded:\n%s", out)
	}
}

// Enabling forwarding is asymmetric on purpose: never turned off, because a host can be
// forwarding for Docker or another VPN and turning it off would break that silently.
func TestEnablingForwardingIsIdempotent(t *testing.T) {
	requireNFT(t)
	if _, err := EnableForwarding(); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	changed, err := EnableForwarding()
	if err != nil {
		t.Fatalf("EnableForwarding again: %v", err)
	}
	if len(changed) != 0 {
		t.Errorf("reported changing %v on a host where it was already on", changed)
	}
}
