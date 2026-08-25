//go:build linux

package resolved

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/meshpnet/meshp/internal/logx"
)

// callTimeout bounds one resolvectl invocation.
//
// Talking to systemd-resolved over D-Bus is milliseconds of work. A bound exists because
// this runs on the reconcile path: resolvectl blocking — on a busy bus, or a resolved that
// has wedged — would stop the agent converging on anything else, and names are the least
// important thing it does.
const callTimeout = 10 * time.Second

// System configures systemd-resolved.
type System struct{ path string }

// New returns a configurer for this host, or nil where systemd-resolved is not the thing
// answering names.
//
// Nil rather than a stub, following the rule the filter and the egress router use: a
// capability this host does not have must be absent, so the agent reports honestly that
// names will not resolve rather than claiming to have configured something.
//
// Presence of the binary is not enough, for the reason nftables.Available gives: a container
// can have resolvectl and no systemd-resolved to talk to, which fails later and looks like a
// meshp fault. This asks resolved for its status, which needs the same bus access that
// configuring a link does.
func New(ctx context.Context) *System {
	path, err := exec.LookPath("resolvectl")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := exec.CommandContext(ctx, path, "status").Run(); err != nil {
		return nil
	}
	return &System{path: path}
}

// Configure points one interface's queries for these domains at the agent's resolver.
//
// Two calls, and both are needed. `dns` says where to send them; `domain` with a leading
// tilde marks each as a *routing* domain — meaning "send these here" without also adding it
// to the search list. That distinction is the whole of split DNS here: a search domain would
// have the stub append `acme.internal` to every bare name a user typed, which is how a
// device in two networks silently reaches whichever one answers first (ADR-0021).
//
// Idempotent because the reconciler calls it on every pass. resolvectl replaces a link's
// configuration rather than appending to it, so the second call is a no-op in effect.
func (r *System) Configure(ctx context.Context, iface string, server netip.AddrPort, domains []string) error {
	if len(domains) == 0 {
		// Nothing to route here. Reverting rather than configuring an empty set: a link
		// left pointing at this resolver with no domains would still be consulted for
		// anything resolved decided to send it.
		return r.Revert(ctx, iface)
	}

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	// The address carries its port. systemd-resolved accepts `addr:port` for a link's DNS
	// server, which matters because the agent's resolver never gets port 53 — that is
	// almost always taken by resolved itself.
	if out, err := r.run(ctx, "dns", iface, server.String()); err != nil {
		return fmt.Errorf("resolved: pointing %s at %s: %w (%s)", iface, server, err, out)
	}

	args := make([]string, 0, len(domains)+2)
	args = append(args, "domain", iface)
	for _, d := range domains {
		args = append(args, "~"+d)
	}
	if out, err := r.run(ctx, args...); err != nil {
		return fmt.Errorf("resolved: routing %s to %s: %w (%s)", strings.Join(domains, ", "), iface, err, out)
	}
	return nil
}

// Revert puts the interface back as systemd-resolved found it.
//
// The reason this package exists rather than one that edits resolv.conf: there is a real
// undo, so the agent can take its configuration off without holding a copy of somebody
// else's and hoping it is still current (Invariant 20).
func (r *System) Revert(ctx context.Context, iface string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if out, err := r.run(ctx, "revert", iface); err != nil {
		return fmt.Errorf("resolved: reverting %s: %w (%s)", iface, err, out)
	}
	return nil
}

// run invokes resolvectl and returns its output, bounded, for the error message.
func (r *System) run(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, r.path, args...).CombinedOutput()
	return logx.Safe(strings.TrimSpace(string(out))), err
}
