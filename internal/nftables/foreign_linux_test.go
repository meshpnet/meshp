//go:build linux

package nftables

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The parser is tested against captured output; this tests the part that cannot be: asking a
// real nft on a real host and reading what it says back.
//
// Asserted as a difference rather than an absolute. A runner may have anything else in its
// ruleset — this one has Docker — so "finds exactly one refusal" would be a claim about the
// machine. That the table appears when installed and is gone when removed is a claim about
// meshp.
//
// A table of its own rather than changing the host's forward policy. Setting
// `iptables -P FORWARD DROP` would reproduce Docker exactly and would also stop every other
// forwarding test in this package if anything here failed before the policy was put back.
func TestARealForeignDropIsFound(t *testing.T) {
	requireMapRoot(t)
	requireNFT(t)

	const foreign = "othervpn"
	before := refusals(t)
	if slices.ContainsFunc(before, func(r Refusal) bool { return r.Table == foreign }) {
		t.Fatalf("setup: %s is already in the ruleset", foreign)
	}

	// Something else on the host, dropping forwarded packets by default — the shape Docker,
	// firewalld and several VPN clients all leave behind.
	load(t, "add table inet "+foreign+"\n"+
		"add chain inet "+foreign+" forward { type filter hook forward priority filter; policy drop; }\n")
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", foreign).Run() })

	during := refusals(t)
	found := slices.ContainsFunc(during, func(r Refusal) bool {
		return r.Table == foreign && r.Chain == "forward" && r.Family == "inet"
	})
	if !found {
		t.Errorf("a table dropping forwarded packets was not reported: %v", during)
	}

	// And it stops being reported once it is gone, or an operator who cleared the obstacle
	// would go on being told it is there.
	mustRun(t, "nft", "delete", "table", "inet", foreign)
	after := refusals(t)
	if slices.ContainsFunc(after, func(r Refusal) bool { return r.Table == foreign }) {
		t.Errorf("a table that has been removed is still reported: %v", after)
	}
}

// meshp's own forwarding table is installed at the same hook and must never be reported.
// This is the case the exclusion exists for, checked against a real ruleset rather than a
// hand-written chain list.
func TestOurOwnForwardTableIsNotReportedAsAnObstacle(t *testing.T) {
	requireMapRoot(t)
	requireNFT(t)

	script, err := RenderForward("meshp0", branchGroup())
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), script); err != nil {
		t.Fatalf("loading the forwarding ruleset: %v", err)
	}
	t.Cleanup(func() {
		if empty, renderErr := RenderForward("meshp0", nil); renderErr == nil {
			_ = Apply(context.Background(), empty)
		}
	})

	for _, r := range refusals(t) {
		if isOurTable(r.Table) {
			t.Errorf("meshp reported its own table as refusing its traffic: %v", r)
		}
	}
}

func refusals(t *testing.T) []Refusal {
	t.Helper()
	got, err := ForwardRefusals(context.Background())
	if err != nil {
		t.Fatalf("asking nft what is in the way: %v", err)
	}
	return got
}

func load(t *testing.T, script string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejected the ruleset: %v\n%s", err, out)
	}
}
