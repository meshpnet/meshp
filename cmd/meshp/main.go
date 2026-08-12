// Command meshp is the user-facing command line interface.
//
// It is unprivileged. Anything that needs to touch the network stack is asked of
// meshpd over a local unix socket, so a user running `meshp status` never needs
// root.
//
// Every command that touches a key or the network stack is a request to meshpd over its
// local socket. Nothing here generates or stores key material: that belongs to the
// privileged process, not to whoever happens to run the CLI.
//
// Command grammar is noun then verb, without exception:
//
//	meshp device list
//	meshp device revoke <id>
//	meshp exit use germany
//
// Admin and end-user commands share one flat namespace. What a caller may do is
// decided by the permissions on their token, not by which subcommand tree they
// found: `meshp device list` shows your own devices as a user and the whole network
// as an admin.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/meshpnet/meshp/internal/agentapi"
	"github.com/meshpnet/meshp/internal/version"
)

const usage = `meshp — private mesh networking

Usage:
  meshp <noun> <verb> [flags]
  meshp <verb>

Session:
  login                    Authenticate against a control plane
  logout                   Discard local credentials
  join <token>             Enrol this device into a network
  up                       Bring the tunnel up
  down                     Take the tunnel down
  status                   Show connection, peers and active routes
  doctor                   Collect a diagnostic bundle for a bug report

Nouns:
  device                   list, show, rename, revoke, approve
  network                  list, create, show, use
  user                     list, invite, suspend
  group                    list, create, add, remove
  acl                      show, edit, test, apply
  dns                      list, add, remove
  route-group              list, create, show, drain, undrain
  exit                     list, use, clear, status
  relay                    list, ping
  token                    create, list, revoke

Run 'meshp <noun> --help' for the verbs a noun supports.

Flags:
  --version                Print build information
  --help                   Show this help
`

// nouns is the authoritative list. Keeping it here means `meshp --help`, completions
// and the docs generator cannot drift apart.
var nouns = []string{
	"device", "network", "user", "group", "acl",
	"dns", "route-group", "exit", "relay", "token",
}

// bareVerbs stand alone, without a noun.
var bareVerbs = []string{
	"login", "logout", "join", "up", "down", "status", "doctor",
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(2)
	}

	switch args[0] {
	case "--version", "-v", "version":
		fmt.Println(version.String("meshp"))
		return
	case "--help", "-h", "help":
		fmt.Print(usage)
		return
	case "join":
		runOrDie(cmdJoin, args[1:])
		return
	case "status":
		runOrDie(cmdStatus, args[1:])
		return
	}

	if contains(bareVerbs, args[0]) {
		fail("%q is not implemented yet — see docs/adr for the design it will follow", args[0])
	}
	if contains(nouns, args[0]) {
		if len(args) < 2 {
			fail("%q needs a verb, e.g. 'meshp %s list'", args[0], args[0])
		}
		fail("%q is not implemented yet", strings.Join(args[:2], " "))
	}

	fail("unknown command %q\n\n%s", args[0], usage)
}

// parseFlags parses flags that may appear before, after or among the positional
// arguments, and returns the positional ones.
//
// The standard library stops at the first non-flag argument, so `meshp join <token>
// --control-url ...` would leave every flag unparsed — and that is the order anyone
// would actually type, with the thing being acted on first. Rather than documenting
// an awkward order nobody will remember, each positional argument is consumed and
// parsing resumes after it.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func runOrDie(fn func(context.Context, []string) error, args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := fn(ctx, args); err != nil {
		fail("%v", err)
	}
}

// cmdJoin asks the daemon to enrol this device.
//
// The CLI no longer generates keys or writes them: that happens in meshpd, which runs
// as root and is where private key material belongs. An unprivileged command holding a
// device's identity key was the shortcut this replaces.
func cmdJoin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp join", flag.ContinueOnError)
	controlURL := fs.String("control-url", envOr("MESHP_CONTROL_URL", "http://localhost:8080"),
		"control plane to enrol against")
	socket := fs.String("socket", envOr("MESHP_SOCKET", agentapi.DefaultSocketPath),
		"meshpd's local socket")
	name := fs.String("name", "", "name for this device (defaults to its hostname)")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: meshp join <token> [--control-url URL]")
	}

	client := agentapi.NewClient(*socket, 2*time.Minute)
	res, err := client.Join(ctx, agentapi.JoinRequest{
		Token:      positional[0],
		ControlURL: *controlURL,
		Name:       *name,
	})
	if err != nil {
		return describeDaemonError(err, *socket)
	}

	fmt.Printf("enrolled in network %s\n", res.NetworkID)
	fmt.Printf("  device      %s\n", res.DeviceID)
	fmt.Printf("  interface   %s\n", res.InterfaceName)
	if res.AddressV4 != "" {
		fmt.Printf("  address     %s\n", res.AddressV4)
	}
	if res.AddressV6 != "" {
		fmt.Printf("              %s\n", res.AddressV6)
	}
	fmt.Println()
	fmt.Println("No tunnel yet: meshpd does not bring up WireGuard in this build.")
	fmt.Println("This device is registered and holds an address; nothing routes to it so far.")
	return nil
}

// cmdStatus reports what the daemon is doing.
func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp status", flag.ContinueOnError)
	socket := fs.String("socket", envOr("MESHP_SOCKET", agentapi.DefaultSocketPath),
		"meshpd's local socket")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	status, err := agentapi.NewClient(*socket, 15*time.Second).Status(ctx)
	if err != nil {
		return describeDaemonError(err, *socket)
	}

	if !status.Enrolled {
		fmt.Println("not enrolled")
		fmt.Println("  run 'meshp join <token>' to join a network")
		return nil
	}

	fmt.Printf("enrolled  %d network(s)\n", len(status.Memberships))
	fmt.Printf("  identity  %s\n", truncate(status.IdentityPublicKey, 20))
	fmt.Printf("  daemon    %s, up since %s\n", status.Version, status.StartedAt.Format(time.RFC3339))

	for _, m := range status.Memberships {
		fmt.Println()
		fmt.Printf("  network   %s\n", m.NetworkID)
		fmt.Printf("    control     %s\n", m.ControlURL)

		// Two different things, reported separately on purpose. A control-channel session
		// says configuration is arriving; it says nothing about whether traffic can flow.
		if m.Connected {
			fmt.Printf("    session     connected since %s\n", m.ConnectedSince.Format(time.RFC3339))
		} else {
			fmt.Printf("    session     not connected\n")
		}
		fmt.Printf("    applied     version %d\n", m.AppliedStateVersion)
		if m.LastError != "" {
			fmt.Printf("    last error  %s\n", m.LastError)
		}

		tunnel := "not up"
		if m.TunnelUp {
			tunnel = "up"
		}
		fmt.Printf("    interface   %s (%s)\n", m.InterfaceName, tunnel)
		if m.AddressV4 != "" {
			fmt.Printf("    address     %s\n", m.AddressV4)
		}
		if m.AddressV6 != "" {
			fmt.Printf("                %s\n", m.AddressV6)
		}
		fmt.Printf("    wg key      %s\n", truncate(m.WireGuardPublicKey, 20))
		fmt.Printf("    joined      %s\n", m.JoinedAt.Format(time.RFC3339))
	}
	return nil
}

// describeDaemonError turns a socket failure into an instruction.
//
// "connection refused" is not an answer anyone can act on. Whether meshpd is not
// running, or is running and will not talk to this user, leads to entirely different
// next steps, so they are named separately.
func describeDaemonError(err error, socket string) error {
	switch {
	case errors.Is(err, agentapi.ErrNoDaemon):
		return fmt.Errorf("meshpd is not running (socket %s)\n"+
			"  start it with: sudo meshpd", socket)
	case errors.Is(err, agentapi.ErrPermission):
		return fmt.Errorf("not permitted to talk to meshpd on %s\n"+
			"  run this with sudo, or start meshpd with --socket-group to allow a group", socket)
	default:
		return err
	}
}

// truncate shortens a key for display. Public keys are not secret, but a terminal
// full of base64 is unreadable.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "meshp: "+format+"\n", args...)
	os.Exit(1)
}
