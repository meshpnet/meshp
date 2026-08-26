//go:build darwin

package pf

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/meshpnet/meshp/internal/logx"
)

// applyTimeout bounds one pfctl invocation.
//
// Loading an anchor is milliseconds of work. A bound exists because this runs on the
// reconcile path: pfctl blocking forever — on a contended /dev/pf, or because something else
// holds the ruleset — would stop the agent converging on anything else.
const applyTimeout = 10 * time.Second

// tokenPath is where the reference this package holds on pf being enabled is remembered.
//
// On disk rather than in memory because the thing it has to survive is this process dying.
// `pfctl -E` increments a count in the kernel and `pfctl -X <token>` decrements it; a token
// that only ever existed in a killed daemon's memory is a reference nothing can ever give
// back, and pf stays enabled until the machine reboots.
//
// Under /var/run because a reference belongs with the running system rather than with the
// agent's saved state — but nothing here relies on that directory being cleared at boot. A
// token is only ever trusted alongside pf actually reporting itself enabled, so a file that
// outlived the enable it names costs a redundant `pfctl -E` and not a silent fail-open.
var tokenPath = filepath.Join("/var/run/meshp", "pf.token")

// Lock refuses egress outside the tunnel through pf. It satisfies tunnel.EgressLock.
type Lock struct{}

// New returns a Lock, or nothing when this host cannot refuse egress.
//
// Nil rather than an error, and checked once at construction rather than on every apply, for
// the reason nftables.New gives: the answer decides what the agent claims it can do, and a
// capability that flapped between reconciles would be worse than one that is simply false.
func New(ctx context.Context) *Lock {
	if !Available(ctx) {
		return nil
	}
	return &Lock{}
}

// Available reports whether this host can refuse egress outside the tunnel.
//
// Two questions, and the second is the one ADR-0026 is about. Finding pfctl is not enough —
// meshp's rules go in an anchor nested under Apple's, and they are evaluated only while the
// main ruleset still references that anchor point. A macOS that renamed it or dropped the
// wildcard would leave the rules loaded and inert, and the device would go on reporting a
// property it no longer has.
//
// Reading the ruleset also needs the same privilege that loading one does, so an agent
// running without it answers false here rather than at apply time, where it would look like
// a policy fault instead of a missing capability.
func Available(ctx context.Context) bool {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return false
	}
	return anchorPointPresent(ctx)
}

// Held reports whether a fail-closed lock is currently installed.
//
// Asked rather than assumed so that removing one can be reported as the event it is: an
// agent that quietly ran a removal on every start would leave no trace of the case that
// matters — a machine whose egress was being refused because a previous run died holding the
// line.
//
// Stdout only. pfctl writes its warnings to stderr, and counting those as rules would report
// a lock on every machine that has none.
func Held(ctx context.Context) bool {
	out, err := pfctlOutput(ctx, "-a", AnchorName, "-s", "rules")
	return err == nil && strings.TrimSpace(out) != ""
}

// ApplyLock makes this device refuse egress that does not go through the tunnel, or stops it
// refusing.
//
// An empty interface name removes the lock. That is the only way it comes off from here —
// the rules are system state and outlive this process on purpose (ADR-0011), so nothing
// about the agent exiting takes them away.
func (l *Lock) ApplyLock(ctx context.Context, iface string, endpoints []netip.AddrPort, excluded []netip.Prefix, preventDNSLeaks bool) error {
	if iface == "" {
		return remove(ctx)
	}
	script, err := RenderLock(LockSpec{
		Interface: iface, Endpoints: endpoints, Excluded: excluded,
		PreventDNSLeaks: preventDNSLeaks,
	})
	if err != nil {
		return err
	}
	return install(ctx, script)
}

// install loads the lock and makes sure pf is running it.
//
// The order is the safety property. Rules are loaded before pf is enabled, so the moment the
// filter turns on the lock is already in force; enabling first would leave a window with pf
// running and nothing of meshp's in it, which is a device that believes it is protected and
// is not.
func install(ctx context.Context, script string) error {
	// Every time, not once at construction. This is the check that turns a silent fail-open
	// into a device saying it cannot enforce, and the thing it guards against — an operating
	// system update rearranging its anchors — happens to a running machine.
	if !anchorPointPresent(ctx) {
		return fmt.Errorf("%w: the main ruleset has no %q anchor point, so rules loaded into %s would never be evaluated",
			ErrUnsupported, anchorPoint, AnchorName)
	}

	wasHeld := Held(ctx)

	if out, err := pfctlCombined(ctx, script, "-a", AnchorName, "-f", "-"); err != nil {
		return fmt.Errorf("pf: loading the lock into %s: %w: %s",
			AnchorName, err, logx.Safe(strings.TrimSpace(out)))
	}

	if err := enable(ctx); err != nil {
		// The rules are loaded and pf is not running them, which is a device that is not
		// failing closed while its anchor says it is. Reported so the caller refuses the
		// default route rather than claiming one behind a lock that is not on.
		return err
	}

	if !wasHeld {
		flushStates(ctx)
	}
	return nil
}

// remove takes the lock off and gives back the reference on pf being enabled.
//
// Idempotent, and it has to be: the reconciler releases on every pass through a state that
// does not want a lock, and `meshp down` releases whether or not one was ever installed.
// Flushing an anchor that holds nothing is not an error.
func remove(ctx context.Context) error {
	if out, err := pfctlCombined(ctx, "", "-a", AnchorName, "-F", "rules"); err != nil {
		return fmt.Errorf("pf: flushing %s: %w: %s",
			AnchorName, err, logx.Safe(strings.TrimSpace(out)))
	}
	release(ctx)
	return nil
}

// enable turns pf on, once, and remembers the reference.
//
// `-E` rather than `-e`, which is the whole point of doing this at all: `-e` enables pf
// outright and `-X` cannot undo it, so a later `pfctl -X` from the application firewall or
// another VPN would turn the filter off underneath meshp — or meshp's own release would turn
// it off underneath theirs. The reference count exists so that several programs can each
// need pf on and none of them can take it away from the others.
//
// Holding a token is not taken as proof that pf is on. Something can still run `pfctl -d`,
// which disables the filter outright and pays no attention to the count, and a token file
// that outlived its enable would look identical. So the state is read back, and a reference
// meshp already holds is trusted only while pf agrees it is running — the same argument the
// anchor-point check rests on, applied to the switch rather than the wiring.
func enable(ctx context.Context) error {
	if _, err := os.Stat(tokenPath); err == nil && enabled(ctx) {
		return nil
	}
	out, err := pfctlCombined(ctx, "", "-E")
	if err != nil {
		return fmt.Errorf("pf: enabling the packet filter: %w: %s", err, logx.Safe(strings.TrimSpace(out)))
	}
	if !enabled(ctx) {
		return fmt.Errorf("%w: pfctl reported no error and the packet filter is not running, "+
			"so the lock is loaded and nothing is evaluating it", ErrUnsupported)
	}

	// And the reference, if pfctl said what it was. A token it did not print is one that can
	// never be given back — a leak rather than a failure, since pf left running with no meshp
	// rules in it refuses nothing — and the lock is installed either way. Written after the
	// state is confirmed, so a failed enable is retried on the next pass rather than skipped
	// because a file says it already happened.
	if token := tokenIn(out); token != "" {
		if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err == nil {
			_ = os.WriteFile(tokenPath, []byte(token), 0o600)
		}
	}
	return nil
}

// release gives back the reference this package holds on pf being enabled.
//
// Errors are deliberately not returned. The contract of removing the lock is that this
// machine is no longer refusing egress, and that is settled by the flush that has already
// happened: pf still enabled with no meshp rules in it blocks nothing. Failing the removal
// here would tell the caller the machine is still locked when it is not, which is the more
// dangerous of the two wrong answers — it is the one that leaves an operator looking for a
// block that is not there.
//
// The token file goes either way. Keeping a token whose release failed would mean holding a
// reference nothing is ever going to give back, and the next lock would take a second one on
// top of it.
func release(ctx context.Context) {
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return
	}
	defer func() { _ = os.Remove(tokenPath) }()
	if trimmed := strings.TrimSpace(string(token)); trimmed != "" {
		_, _ = pfctlCombined(ctx, "", "-X", trimmed)
	}
}

// enabled reports whether the packet filter is actually running.
func enabled(ctx context.Context) bool {
	out, err := pfctlOutput(ctx, "-s", "info")
	if err != nil {
		return false
	}
	return statusEnabledIn(out)
}

// flushStates makes the lock apply to connections that predate it.
//
// pf consults its state table before its rules, so a flow established before the anchor was
// loaded goes on flowing without ever being evaluated against it. That is a silent
// fail-open — the exact failure ADR-0026 says is worse than having no lock — and killing the
// states is the only way to close it.
//
// Machine-wide, because pf's state table is. That sounds worse than it is: this runs only on
// the transition into locked, which is the same moment the device takes a default route
// through the tunnel, and every flow the flush disturbs was about to be broken anyway by
// having its source address change. On the ordinary macOS path it does nothing at all — pf
// ships disabled, so meshp is what turned it on and there were no states to begin with.
//
// Best effort. A lock that is loaded and enforcing new flows is worth having even if the old
// ones could not be cleared, and there is nothing the caller could usefully do about it.
func flushStates(ctx context.Context) {
	_, _ = pfctlCombined(ctx, "", "-F", "states")
}

// anchorPointPresent reports whether the main ruleset still evaluates what is nested under
// Apple's anchor.
//
// The reading is here and the deciding is in anchorPointIn, so what this check actually
// accepts can be tested without a Mac and without root — which matters, because it is the
// one thing standing between an operating-system change and a device that reports it fails
// closed while everything leaks.
func anchorPointPresent(ctx context.Context) bool {
	out, err := pfctlOutput(ctx, "-s", "rules")
	if err != nil {
		return false
	}
	return anchorPointIn(out)
}

// pfctlCombined runs pfctl and returns everything it said.
//
// Combined because pfctl explains its failures on stderr, and that explanation is the only
// thing that makes a rendering mistake diagnosable.
//
// The deadline is checked through the context rather than through the error, which reports
// only that the process was killed: exec.CommandContext cancels by signalling, so a timeout
// and a crash are the same error until the context is asked.
func pfctlCombined(ctx context.Context, stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pfctl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return string(out), fmt.Errorf("pf: pfctl did not finish within %s", applyTimeout)
	}
	return string(out), err
}

// pfctlOutput runs pfctl and returns only what it printed as an answer.
//
// Stdout alone, unlike pfctlCombined: these callers are reading a ruleset and deciding
// something from whether it is empty, and pfctl's advisory noise on stderr would answer for
// them.
func pfctlOutput(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "pfctl", args...).Output()
	return string(out), err
}
