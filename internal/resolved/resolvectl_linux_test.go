//go:build linux

package resolved

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The claim this package rests on: systemd-resolved really does send this domain to this
// address on this link, and really does put the link back afterwards.
//
// Against the running systemd-resolved, on a link created for the purpose. There is no
// useful way to fake this — the thing being tested is whether a specific daemon accepts a
// specific pair of commands and whether its undo is a real undo, and a fake would only
// assert that resolvectl was invoked with the arguments this file already says it invokes.
//
// A dummy link rather than a real interface, so a failure cannot take DNS away from the
// machine running the test. `resolvectl revert` is what restores it, and if that is broken
// this test is exactly where it should be discovered.
func TestSystemdResolvedTakesTheConfigurationAndGivesItBack(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a link and configure systemd-resolved")
	}
	ctx := context.Background()
	r := New(ctx)
	if r == nil {
		t.Skip("no systemd-resolved on this host")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2 to create the test link")
	}

	const link = "meshpdnstest"
	_ = exec.Command("ip", "link", "del", link).Run()
	if out, err := exec.Command("ip", "link", "add", link, "type", "dummy").CombinedOutput(); err != nil {
		t.Skipf("cannot create a dummy link here: %v (%s)", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", link).Run() })
	if out, err := exec.Command("ip", "link", "set", link, "up").CombinedOutput(); err != nil {
		t.Fatalf("bringing %s up: %v (%s)", link, err, out)
	}

	server := netip.MustParseAddrPort("127.0.0.1:5399")
	if err := r.Configure(ctx, link, server, []string{"acme.internal"}); err != nil {
		t.Fatalf("configuring: %v", err)
	}

	status := resolvectlStatus(t, link)
	if !strings.Contains(status, "127.0.0.1:5399") {
		t.Errorf("resolved does not have the address:\n%s", status)
	}
	// The tilde is what makes it a routing domain rather than a search domain. A search
	// domain would have the stub append acme.internal to every bare name a user typed,
	// which is how a device in two networks silently reaches whichever answers first.
	if !strings.Contains(status, "~acme.internal") {
		t.Errorf("resolved has the domain but not as a routing domain:\n%s", status)
	}

	// Idempotent: the reconciler calls this on every pass.
	if err := r.Configure(ctx, link, server, []string{"acme.internal"}); err != nil {
		t.Fatalf("configuring a second time: %v", err)
	}

	if err := r.Revert(ctx, link); err != nil {
		t.Fatalf("reverting: %v", err)
	}
	after := resolvectlStatus(t, link)
	if strings.Contains(after, "127.0.0.1:5399") || strings.Contains(after, "acme.internal") {
		t.Errorf("revert left meshp's configuration behind:\n%s", after)
	}

	// And reverting a link that was never configured is not an error, because the teardown
	// path calls it without knowing whether there was anything to undo (Invariant 20).
	if err := r.Revert(ctx, link); err != nil {
		t.Errorf("reverting an already-reverted link: %v", err)
	}
}

// An empty domain set reverts rather than configuring nothing, so a device that has left
// every network stops being consulted.
func TestNoDomainsRevertsTheLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a link and configure systemd-resolved")
	}
	ctx := context.Background()
	r := New(ctx)
	if r == nil {
		t.Skip("no systemd-resolved on this host")
	}

	const link = "meshpdnstest2"
	_ = exec.Command("ip", "link", "del", link).Run()
	if out, err := exec.Command("ip", "link", "add", link, "type", "dummy").CombinedOutput(); err != nil {
		t.Skipf("cannot create a dummy link here: %v (%s)", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", link).Run() })
	_ = exec.Command("ip", "link", "set", link, "up").Run()

	server := netip.MustParseAddrPort("127.0.0.1:5399")
	if err := r.Configure(ctx, link, server, []string{"acme.internal"}); err != nil {
		t.Fatalf("configuring: %v", err)
	}
	if err := r.Configure(ctx, link, server, nil); err != nil {
		t.Fatalf("configuring with no domains: %v", err)
	}
	if got := resolvectlStatus(t, link); strings.Contains(got, "acme.internal") {
		t.Errorf("an empty domain set left the link configured:\n%s", got)
	}
}

func resolvectlStatus(t *testing.T, link string) string {
	t.Helper()
	out, err := exec.Command("resolvectl", "status", link).CombinedOutput()
	if err != nil {
		t.Fatalf("resolvectl status %s: %v (%s)", link, err, out)
	}
	return string(out)
}
