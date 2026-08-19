//go:build linux

package nftables

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
)

// ApplyCarry makes this host forward what it advertises even when something else refuses.
//
// Two steps, deliberately separate. The chain is meshp's and is rebuilt every time. The jump
// lives in a chain meshp does not own, so it is read first and added only when it is missing
// — an appended rule cannot be made idempotent by rewriting it, and adding a second one every
// reconcile would grow the host's FORWARD chain without bound.
//
// Does nothing where there is nothing to overcome. A host with no `ip filter` table has no
// foreign policy to survive, and creating that table would mean meshp registering a base
// chain in somebody else's name — a much larger claim on the machine than adding one jump to
// a chain that already exists.
func ApplyCarry(ctx context.Context, iface string, prefixes []netip.Prefix) error {
	if !carryTableExists(ctx) {
		return nil
	}

	script, err := RenderCarry(iface, prefixes)
	if err != nil {
		return err
	}
	if err := Apply(ctx, script); err != nil {
		return err
	}
	if carryJumpPresent(ctx) {
		return nil
	}
	return Apply(ctx, CarryJump())
}

// RemoveCarry takes meshp back out of the host's chain.
//
// The jump first and the chain second, because a chain cannot be deleted while something
// still jumps to it. Both are best-effort in the caller: a device tearing down has already
// removed its interface, so a rule naming an interface that no longer exists matches nothing
// — untidy rather than dangerous.
func RemoveCarry(ctx context.Context) error {
	if !carryTableExists(ctx) {
		return nil
	}
	handle := carryJumpHandle(ctx)
	if handle != "" {
		if err := Apply(ctx, "delete rule "+CarryTable+" FORWARD handle "+handle+"\n"); err != nil {
			return err
		}
	}
	return Apply(ctx, "delete chain "+CarryTable+" "+CarryChainName+"\n")
}

// carryTableExists reports whether the host keeps an iptables-style filter table.
func carryTableExists(ctx context.Context) bool {
	path, err := exec.LookPath("nft")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	return exec.CommandContext(ctx, path, "list", "chain", CarryTable, "FORWARD").Run() == nil
}

// carryJumpPresent reports whether FORWARD already jumps to meshp's chain.
func carryJumpPresent(ctx context.Context) bool {
	return strings.Contains(forwardChain(ctx), "jump "+CarryChainName)
}

// carryJumpHandle finds the handle of that jump, which is what deleting a rule needs.
func carryJumpHandle(ctx context.Context) string {
	for _, line := range strings.Split(forwardChain(ctx), "\n") {
		if !strings.Contains(line, "jump "+CarryChainName) {
			continue
		}
		if i := strings.LastIndex(line, "# handle "); i >= 0 {
			return strings.TrimSpace(line[i+len("# handle "):])
		}
	}
	return ""
}

// forwardChain returns the host's FORWARD chain, with handles, or empty when it cannot be
// read. Empty is treated as "no jump present", which errs towards adding one — a duplicate
// jump is untidy, and a missing one is an advertiser that carries nothing.
func forwardChain(ctx context.Context) string {
	path, err := exec.LookPath("nft")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-a", "list", "chain", CarryTable, "FORWARD").Output()
	if err != nil {
		return ""
	}
	return string(out)
}
