package main

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"time"

	"github.com/meshpnet/meshp/internal/agentapi"
	"github.com/meshpnet/meshp/internal/egresslock"
	"github.com/meshpnet/meshp/internal/wglink"
)

// cmdDoctor explains what meshp is doing to this machine's network.
//
// ADR-0011 asks for it by name and adds the requirement that shapes everything here: it must
// work "on a machine with no internet access". That is not a nice-to-have. The person
// running this is at a console on a host that cannot reach anything, quite possibly because
// meshp refused to let it — so this contacts nothing. It reads the kernel and the local
// socket, and every one of those answers is available on a machine that is completely cut
// off.
//
// The ADR also predicts the support ticket: "There will also be support tickets from users
// whose network broke because a laptop lost its tunnel and correctly refused to leak. That
// is the intended behaviour, and the error message is the product." This command is that
// error message, so it says what is refusing traffic, why, and how to undo it by hand —
// because someone who cannot reach the internet cannot look it up either.
func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp doctor", flag.ContinueOnError)
	socket := fs.String("socket", envOr("MESHP_SOCKET", agentapi.DefaultSocketPath),
		"meshpd's local socket")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	f := findings{}

	// The kernel first, and deliberately before the daemon. What is refusing this machine's
	// traffic is in the kernel whether or not anything is running, and the case that brought
	// someone here is usually the one where nothing is.
	f.locked = egresslock.Held(ctx)
	f.claimed, _ = wglink.EgressHeld()

	// A short timeout: an unresponsive daemon should not make the one command that explains
	// an outage hang for the length of an ordinary status call.
	status, err := agentapi.NewClient(*socket, 3*time.Second).Status(ctx)
	f.daemonUp = err == nil
	if err == nil {
		f.enrolled = status.Enrolled
		for _, m := range status.Memberships {
			if m.Connected {
				f.sessions++
			}
			if m.TunnelUp {
				f.interfaces++
			}
		}
	}

	report(f, *socket)
	if f.strandedEgress() {
		// Non-zero because something is refusing this machine's traffic and nothing is
		// managing it. Anything else — including a healthy full tunnel, which also refuses
		// traffic — is not a fault and must not be reported as one.
		return errStranded
	}
	return nil
}

// errStranded is returned when the machine is refusing traffic with nothing to undo it.
var errStranded = fmt.Errorf("meshp: egress is being refused and meshpd is not running")

// findings is what could be established without reaching anything.
type findings struct {
	locked     bool // a fail-closed lock is installed
	claimed    bool // a default route is claimed through the tunnel
	daemonUp   bool
	enrolled   bool
	sessions   int
	interfaces int
}

// strandedEgress is the situation this command exists for: the kernel is refusing traffic
// and the thing that would undo it is not running.
func (f findings) strandedEgress() bool { return (f.locked || f.claimed) && !f.daemonUp }

// startMeshpdCommand is how meshpd is started on this machine, as something typeable.
//
// The whole of #66. `doctor` told everybody to run `systemctl start meshpd`, which is a
// command two of the three platforms with a data plane do not have — and this is the one
// screen ADR-0011 says has to carry commands that work, because whoever is reading it has no
// network and cannot look anything up.
//
// Every platform that can supervise the agent now names the thing that supervises it: the
// unit under deploy/systemd, the daemon under deploy/launchd, and the service registered with
// the control manager. Anything else gets the binary, which is what is true there.
//
// All three names are load-bearing, and a command naming one wrongly fails for somebody with
// no network reading the one screen ADR-0011 says has to carry commands that work.
// internal/deploycheck reads the unit, the plist and agentapi.WindowsServiceName and holds
// these to them.
func startMeshpdCommand() string {
	switch runtime.GOOS {
	case "linux":
		return "sudo systemctl start meshpd"
	case "darwin":
		// kickstart rather than bootstrap: bootstrap is for a plist not yet loaded and fails
		// with "service already loaded" once it is, which is the state anybody reading this
		// is most likely in. kickstart starts it either way.
		return "sudo launchctl kickstart -k system/net.meshp.meshpd"
	case "windows":
		// sc.exe rather than Start-Service, because this is printed to whatever shell
		// somebody is in and cmd.exe has no PowerShell cmdlets. The trailing space in
		// `start= auto` is sc.exe's own syntax and is not a typo, which is why installing is
		// documented rather than printed here.
		return "sc.exe start " + agentapi.WindowsServiceName
	default:
		return "sudo meshpd"
	}
}

// startMeshpdHint is the same command in a sentence, for the branch that is prose rather
// than a block somebody types.
func startMeshpdHint() string {
	return "Start it with '" + startMeshpdCommand() + "'."
}

func report(f findings, socket string) {
	switch {
	case f.strandedEgress():
		fmt.Println("This machine is refusing network traffic, and meshpd is not running.")
		fmt.Println()
		fmt.Println("meshp was set up to send everything through its tunnel, and to block")
		fmt.Println("traffic that would leave any other way rather than let it out in the")
		fmt.Println("clear. That block is a firewall rule, so it survived meshpd stopping.")
		fmt.Println("It is doing what it was asked to do; there is nothing to reach.")
		fmt.Println()
		fmt.Println("Starting meshpd again removes it:")
		fmt.Println()
		fmt.Println("    " + startMeshpdCommand())
		fmt.Println()
		fmt.Println("If meshpd will not start, undo it by hand:")
		fmt.Println()
		if f.locked {
			// From the platform that installed it, for the reason the routing half below
			// gives. Until macOS grew a lock of its own this said `nft delete table` on
			// every operating system, which is the #156 mistake with a different command.
			for _, command := range egresslock.Undo() {
				fmt.Printf("    %s\n", command)
			}
		}
		if f.claimed {
			// From the platform that made the claim, not written here. A command for the
			// wrong operating system is worse than none, and whoever is reading this is at
			// a console on a machine with no network.
			for _, command := range wglink.EgressUndo() {
				fmt.Printf("    %s\n", command)
			}
		}
		fmt.Println()
		fmt.Println("Starting meshpd and undoing it by hand both restore this machine's")
		fmt.Println("ordinary networking, and every command above is safe to run more than")
		fmt.Println("once. meshpd puts back whatever it needs when it next starts.")

	case f.locked || f.claimed:
		fmt.Println("This machine is sending everything through its tunnel.")
		fmt.Println()
		fmt.Println("Traffic that would leave any other way is refused on purpose, so a")
		fmt.Println("dropped tunnel cannot quietly put your real address back on the wire.")
		fmt.Println("If something cannot connect, that is the reason.")
		fmt.Println()
		fmt.Printf("  meshpd          running, %d live session(s)\n", f.sessions)
		fmt.Printf("  tunnel          %d interface(s) up\n", f.interfaces)
		fmt.Printf("  blocking        %v\n", f.locked)
		fmt.Printf("  default route   %v\n", f.claimed)
		if f.interfaces == 0 {
			fmt.Println()
			fmt.Println("No tunnel is up, so nothing can get out at all. meshpd is running")
			fmt.Println("and will restore it when it can reach its control plane.")
		}

	case !f.daemonUp:
		fmt.Println("meshpd is not running, and it is not blocking anything.")
		fmt.Println()
		fmt.Printf("  socket   %s\n", socket)
		fmt.Println()
		fmt.Println("Whatever is wrong with this machine's network, meshp is not the")
		fmt.Println("cause. " + startMeshpdHint())

	case !f.enrolled:
		fmt.Println("meshpd is running and this device has not joined a network.")
		fmt.Println()
		fmt.Println("Nothing is being blocked or routed. Run 'meshp join <token>'.")

	default:
		fmt.Println("Nothing here is interfering with this machine's networking.")
		fmt.Println()
		fmt.Printf("  meshpd          running, %d live session(s)\n", f.sessions)
		fmt.Printf("  tunnel          %d interface(s) up\n", f.interfaces)
		fmt.Println("  blocking        false")
		fmt.Println("  default route   false")
		fmt.Println()
		fmt.Println("Traffic goes wherever it would have gone without meshp, except for")
		fmt.Println("the addresses inside your network.")
	}
}
