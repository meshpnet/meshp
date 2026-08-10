// Command meshp is the user-facing command line interface.
//
// It is unprivileged. Anything that needs to touch the network stack is asked
// of meshpd over a local unix socket, so a user running `meshp status` never
// needs root.
//
// Command grammar is noun then verb, without exception:
//
//	meshp device list
//	meshp device revoke <id>
//	meshp exit use germany
//
// Admin and end-user commands share one flat namespace. What a caller may do
// is decided by the permissions on their token, not by which subcommand tree
// they found: `meshp device list` shows your own devices as a user and the
// whole network as an admin.
package main

import (
	"fmt"
	"os"
	"strings"

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

// nouns is the authoritative list. Keeping it here means `meshp --help`,
// completions and the docs generator cannot drift apart.
var nouns = []string{
	"device", "network", "user", "group", "acl",
	"dns", "route-group", "exit", "relay", "token",
}

// verbs that stand alone, without a noun.
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

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "meshp: "+format+"\n", args...)
	os.Exit(1)
}
