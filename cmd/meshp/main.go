// Command meshp is the user-facing command line interface.
//
// It is unprivileged. Anything that needs to touch the network stack is asked of
// meshpd over a local unix socket, so a user running `meshp status` never needs
// root.
//
// `meshp join` is the exception, for now: it generates the device's keys and writes
// them to the agent's state directory itself, because meshpd does not yet expose a
// socket to ask. That makes it the one command needing write access to the state
// directory, and it moves behind the daemon in A3 — private keys belong to the
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
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/meshpnet/meshp/internal/agentstate"
	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/keys"
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

// cmdJoin enrols this device into a network.
func cmdJoin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp join", flag.ContinueOnError)
	controlURL := fs.String("control-url", envOr("MESHP_CONTROL_URL", "http://localhost:8080"),
		"control plane to enrol against")
	stateDir := fs.String("state-dir", defaultStateDir(), "where to keep this device's keys")
	name := fs.String("name", "", "name for this device (defaults to its hostname)")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: meshp join <token> [--control-url URL]")
	}
	token := positional[0]

	// An existing identity is reused, which is what lets one device hold memberships
	// in several networks under one name (ADR-0004). A fresh one is generated only if
	// this device has never enrolled anywhere.
	state, err := agentstate.Load(*stateDir)
	switch {
	case errors.Is(err, agentstate.ErrNotEnrolled):
		state = &agentstate.State{}
		identity, err := keys.NewIdentity()
		if err != nil {
			return err
		}
		state.SetIdentity(identity)
	case err != nil:
		return err
	}

	identity, err := state.Identity()
	if err != nil {
		return err
	}

	// A fresh WireGuard keypair per membership, never shared between them, so two
	// networks cannot recognise this device by its key (Invariant 19).
	wg, err := keys.NewWireGuardPair()
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	deviceName := *name
	if deviceName == "" {
		deviceName = hostname
	}

	joinCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	res, err := enrollclient.New(*controlURL, nil).Join(joinCtx, enrollclient.JoinRequest{
		Token:        token,
		Identity:     identity,
		WireGuard:    wg,
		Name:         deviceName,
		Hostname:     hostname,
		OS:           runtime.GOOS,
		OSVersion:    osVersion(),
		AgentVersion: version.Version(),
	})
	if err != nil {
		return err
	}

	membership := agentstate.Membership{
		MembershipID:        res.MembershipID,
		NetworkID:           res.NetworkID,
		DeviceID:            res.DeviceID,
		ControlURL:          *controlURL,
		InterfaceName:       res.InterfaceName,
		WireGuardPrivateKey: wg.Private.String(),
		WireGuardPublicKey:  wg.Public.String(),
		AppliedStateVersion: 0,
		JoinedAt:            time.Now().UTC(),
	}
	if res.AddressV4 != nil {
		membership.AddressV4 = res.AddressV4.String()
	}
	if res.AddressV6 != nil {
		membership.AddressV6 = res.AddressV6.String()
	}
	state.AddMembership(membership)

	if err := agentstate.Save(*stateDir, state); err != nil {
		// The enrolment succeeded server-side but the keys could not be kept, which
		// leaves a device registered that cannot prove who it is. Say so plainly
		// rather than reporting success.
		return fmt.Errorf("enrolled, but could not save this device's keys: %w\n"+
			"  the device now exists in the network and must be revoked, then enrolled again\n"+
			"  try a writable --state-dir, or run with sudo", err)
	}

	fmt.Printf("enrolled in network %s\n", res.NetworkID)
	fmt.Printf("  device      %s\n", res.DeviceID)
	fmt.Printf("  interface   %s\n", res.InterfaceName)
	if res.AddressV4 != nil {
		fmt.Printf("  address     %s\n", res.AddressV4)
	}
	if res.AddressV6 != nil {
		fmt.Printf("              %s\n", res.AddressV6)
	}
	fmt.Printf("  keys        %s\n", agentstate.Path(*stateDir))
	fmt.Println()
	fmt.Println("No tunnel yet: meshpd does not bring up WireGuard in this build.")
	fmt.Println("This device is registered and holds an address; nothing routes to it so far.")
	return nil
}

// cmdStatus reports what this device knows locally.
//
// Local state only, deliberately. It has to work when the control plane is
// unreachable (Invariant 15), which is exactly when somebody wants to run it.
func cmdStatus(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp status", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "where this device's keys are kept")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	state, err := agentstate.Load(*stateDir)
	if errors.Is(err, agentstate.ErrNotEnrolled) {
		fmt.Println("not enrolled")
		fmt.Printf("  run 'meshp join <token>' to join a network (state dir: %s)\n", *stateDir)
		return nil
	}
	if err != nil {
		return err
	}

	fmt.Printf("enrolled  %d network(s)\n", len(state.Memberships))
	fmt.Printf("  identity  %s\n", truncate(state.IdentityPublicKey, 20))
	for _, m := range state.Memberships {
		fmt.Println()
		fmt.Printf("  network   %s\n", m.NetworkID)
		fmt.Printf("    control     %s\n", m.ControlURL)
		fmt.Printf("    interface   %s (not up)\n", m.InterfaceName)
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

// truncate shortens a key for display. Public keys are not secret, but a terminal
// full of base64 is unreadable.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func osVersion() string {
	// Reading the real version means per-platform work that belongs in meshpd, which
	// is where posture reporting will live. Reporting the architecture is honest and
	// useful in the meantime.
	return runtime.GOARCH
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

// defaultStateDir mirrors meshpd's, because they share the file.
func defaultStateDir() string {
	if v := os.Getenv("MESHP_STATE_DIR"); v != "" {
		return v
	}
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\meshp`
	case "darwin":
		return "/Library/Application Support/meshp"
	default:
		return "/var/lib/meshp"
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "meshp: "+format+"\n", args...)
	os.Exit(1)
}
