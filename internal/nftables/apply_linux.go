//go:build linux

package nftables

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/meshpnet/meshp/internal/logx"
)

// applyTimeout bounds one nft invocation.
//
// Loading a table is milliseconds of work. A bound exists because this runs on the
// reconcile path: nft blocking forever — on a contended netlink socket, or because
// something else holds the ruleset — would stop the agent converging on anything else.
const applyTimeout = 10 * time.Second

// Available reports whether this host can enforce a packet filter.
//
// The answer decides what the agent claims in its capabilities, and the control plane
// refuses to place a device that cannot enforce into a network whose policy needs
// port-level rules rather than silently degrading (ADR-0007). So this must be honest:
// finding the binary is not enough, since a container can have nft and no permission to
// use it, which fails later and looks like a policy fault. It asks nft to list the
// ruleset, which needs the same access that loading one does.
func Available(ctx context.Context) bool {
	path, err := exec.LookPath("nft")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	return exec.CommandContext(ctx, path, "list", "ruleset").Run() == nil
}

// Apply loads a rendered ruleset.
//
// One nft invocation reading one script, which is what makes the replacement atomic: nft
// applies a whole file as a single netlink transaction, so either the new policy is in
// force or the old one still is. Feeding it rule by rule would leave a window in which
// half a policy applies, and that window is exactly when traffic is permitted that the new
// policy denies.
func Apply(ctx context.Context, script string) error {
	path, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("%w: nft is not installed, so this host cannot enforce a policy", ErrUnsupported)
	}

	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("nftables: nft did not finish within %s", applyTimeout)
		}
		// nft names the offending line, which is the only thing that makes a rendering
		// mistake diagnosable. Passed through rather than summarised, but through logx
		// because it quotes back the script it was given.
		return fmt.Errorf("nftables: loading the ruleset: %w: %s",
			err, logx.Safe(strings.TrimSpace(string(output))))
	}
	return nil
}
