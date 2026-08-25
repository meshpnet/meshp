//go:build darwin

package resolved

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/meshpnet/meshp/internal/logx"
)

// ErrUnsupported means this platform has no resolver meshp knows how to configure safely.
//
// Declared here as well as in the unsupported build because macOS has an implementation and
// still needs the sentinel: New returns nil when scutil cannot be reached, and a caller that
// held one anyway should get a refusal rather than a silent success.
var ErrUnsupported = errors.New("resolved: no supported resolver on this platform")

// callTimeout bounds one scutil invocation, for the reason the Linux implementation gives:
// this runs on the reconcile path, and names are the least important thing the agent does.
const callTimeout = 10 * time.Second

// matchOrder is where meshp's supplemental domains sit relative to anything else claiming
// them.
//
// High, so a corporate resolver that also claims a suffix wins. That is the conservative
// direction: meshp is the newcomer on a machine that was resolving names before it arrived,
// and a tie broken in meshp's favour would silently redirect a name somebody's employer
// owns. If a network's suffix genuinely collides with one the host already resolves, the
// answer is to change the suffix, not to outbid it.
const matchOrder = 200000

// System points macOS's resolver at meshp for the names meshp owns.
//
// Through the SystemConfiguration dynamic store, which is what makes this safe to do at all.
// See the package documentation: the store is keyed per service, so meshp writes an entry
// that is entirely its own and removes it to undo. Nothing of anybody else's is read,
// merged or written back.
type System struct{ path string }

// New returns a configurer for this host, or nil where scutil cannot be reached.
//
// mDNSResponder is not optional on macOS the way systemd-resolved is on Linux, so there is
// no equivalent of asking whether the daemon is running — if scutil answers, the store is
// there. What this does check is that it answers, because a sandbox or a stripped image
// that lacks it should produce a nil here rather than a failure per reconcile.
func New(ctx context.Context) *System {
	path, err := exec.LookPath("scutil")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = strings.NewReader("list State:/Network/Global/DNS\nquit\n")
	if err := cmd.Run(); err != nil {
		return nil
	}
	return &System{path: path}
}

// Configure sends queries for these domains, on this interface, to this address.
//
// Called on every reconcile and idempotent: setting a key that already holds these values
// writes the same values again. Nothing is read back first, matching what the Linux
// implementation does and for the same reason — the operation is declarative, so
// re-asserting is both simpler and self-repairing.
//
// Self-repairing matters more here than it looks. The dynamic store is memory, not a file:
// a reboot empties it, and so does anything that resets the network configuration. A
// version of this that remembered what it had already set would leave names broken until
// the agent restarted, while the interface and the routes healed on the same timer.
func (s *System) Configure(ctx context.Context, iface string, server netip.AddrPort, domains []string) error {
	if len(domains) == 0 {
		return s.Revert(ctx, iface)
	}
	if !server.IsValid() {
		return fmt.Errorf("resolved: %s: no resolver address to point at", iface)
	}

	var script strings.Builder
	script.WriteString("d.init\n")
	fmt.Fprintf(&script, "d.add ServerAddresses * %s\n", server.Addr())

	// The agent listens on a loopback port of its own choosing rather than 53, which is
	// already taken on most machines and needs root besides. macOS carries the port in the
	// same dictionary, so split DNS to a high port is expressible here — which is not true
	// of every platform's resolver and is worth noting before somebody assumes it is.
	fmt.Fprintf(&script, "d.add ServerPort # %d\n", server.Port())

	// The whole of split DNS, in one key. Only these suffixes come to meshp; everything
	// else keeps going wherever it was already going, which ADR-0021 requires and which a
	// resolver claiming the root domain would quietly break on the first laptop that
	// joined a corporate network.
	script.WriteString("d.add SupplementalMatchDomains *")
	for _, domain := range domains {
		if err := validDomain(domain); err != nil {
			return err
		}
		script.WriteString(" " + domain)
	}
	script.WriteString("\n")

	script.WriteString("d.add SupplementalMatchOrders * #")
	for range domains {
		fmt.Fprintf(&script, " %d", matchOrder)
	}
	script.WriteString("\n")

	fmt.Fprintf(&script, "set %s\nquit\n", storeKey(iface))
	return s.run(ctx, script.String(), iface)
}

// Revert puts the resolver back as it was.
//
// Which is a stronger claim on this platform than on Linux, and it is the reason macOS gets
// an implementation at all: there is nothing to put back. meshp's entry is its own key,
// created by meshp and read by nobody else, so removing it leaves the store exactly as it
// would have been had meshp never run. Compare /etc/resolv.conf, where "putting it back"
// means having kept a copy of somebody else's file and hoping it is still current.
//
// Removing a key that is not there is not an error: scutil says so and this ignores it, for
// the same reason the Linux Revert is safe on a link that was never configured — teardown is
// called whenever a membership goes away, including when it never came up.
func (s *System) Revert(ctx context.Context, iface string) error {
	script := fmt.Sprintf("remove %s\nquit\n", storeKey(iface))
	err := s.run(ctx, script, iface)
	if err != nil && strings.Contains(err.Error(), "No such key") {
		return nil
	}
	return err
}

// storeKey is where this interface's resolver configuration lives.
//
// Named for meshp and for the interface, so two networks on one device get one key each and
// do not fight over a single global setting. The identifier does not have to name a real
// network service — macOS collects supplemental domains from every service key it finds —
// and deliberately does not, because a real service is somebody else's to configure.
func storeKey(iface string) string {
	return "State:/Network/Service/meshp-" + iface + "/DNS"
}

// validDomain refuses anything that would end up as another scutil command.
//
// The domains come from a network's DNS suffix, which comes from the control plane, which
// is not this process. scutil reads a script on standard input, so a suffix containing a
// newline would be a line of somebody else's choosing running as root — and one containing
// a space would silently add a domain nobody asked for. Refused rather than escaped: there
// is no escaping syntax here to get right, and a suffix that needs one is not a suffix.
func validDomain(domain string) error {
	if domain == "" {
		return errors.New("resolved: an empty domain cannot be matched")
	}
	if strings.ContainsAny(domain, " \t\r\n\"'\\") {
		return fmt.Errorf("resolved: %q is not a domain name", logx.Safe(domain))
	}
	if strings.HasPrefix(domain, "-") || len(domain) > 253 {
		return fmt.Errorf("resolved: %q is not a domain name", logx.Safe(domain))
	}
	return nil
}

// run feeds a script to scutil and reports what it said when it fails.
func (s *System) run(ctx context.Context, script, iface string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.path)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()

	// The trap in driving scutil: it reports a failed `set` or `remove` on standard output
	// and **still exits zero**. Checking only the exit status would take "Permission
	// denied" for a successful configuration and report that names work — which is the one
	// outcome ADR-0021 rules out, since a host that cannot configure its resolver has to
	// say so rather than leave the agent believing it did.
	//
	// So the rule is that any output at all is a failure. scutil is silent when a script
	// does what it was asked; everything it prints from `set` or `remove` is a complaint.
	// Verified rather than assumed: unprivileged, both commands print "  Permission denied"
	// and exit 0.
	text := strings.TrimSpace(string(out))
	switch {
	case err != nil && text != "":
		return fmt.Errorf("resolved: %s: scutil: %w: %s", iface, err, logx.Safe(text))
	case err != nil:
		return fmt.Errorf("resolved: %s: scutil: %w", iface, err)
	case text != "":
		return fmt.Errorf("resolved: %s: scutil: %s", iface, logx.Safe(text))
	}
	return nil
}
