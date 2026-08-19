//go:build linux

package nftables

import (
	"context"
	"os/exec"
)

// ForwardRefusals reports what else on this host will drop forwarded packets.
//
// Asked of nft rather than inferred, for the reason Available is: what a host will do with a
// packet is not something that can be worked out from what meshp installed.
//
// One blind spot, stated because it changes what a clean result means. This sees only the
// nftables ruleset, which on any current distribution includes iptables — `iptables` is
// iptables-nft, and its FORWARD chain appears here as `ip filter FORWARD`. A host still
// running iptables-legacy has a second, entirely separate packet path that nft cannot see,
// and a drop there would be invisible to this. Empty therefore means "nothing found", not
// "nothing there".
//
// Errors are returned rather than swallowed, but a caller that cannot ask is not a caller
// that should stop forwarding: not knowing is the state meshp was already in.
func ForwardRefusals(ctx context.Context) ([]Refusal, error) {
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, "--json", "list", "chains").Output()
	if err != nil {
		return nil, err
	}
	return forwardRefusals(out)
}
