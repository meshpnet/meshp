package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/meshpnet/meshp/internal/agentapi"
)

// cmdDown takes this device off the mesh until somebody puts it back.
//
// It releases the fail-closed lock, which is the part worth being explicit about. ADR-0011
// installs that lock so a device whose tunnel drops stops passing traffic rather than
// putting the user's real address back on the wire — but that protects against a failure.
// This is somebody saying they want their ordinary network back, and a command called
// "down" that left a machine unable to reach anything would manufacture the support ticket
// that ADR describes out of a deliberate act.
//
// So it says what it did. Traffic is not going through the mesh any more, and whoever ran
// this should know that rather than remember it.
func cmdDown(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp down", flag.ContinueOnError)
	socket := fs.String("socket", envOr("MESHP_SOCKET", agentapi.DefaultSocketPath), "meshpd's local socket")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	status, err := agentapi.NewClient(*socket, 30*time.Second).SetRunning(ctx, false)
	if err != nil {
		// The same explanation status gives. Somebody who runs this and is told only
		// "connection refused" has to work out that meshpd is a thing that runs.
		return describeDaemonError(err, *socket)
	}
	if !status.Enrolled {
		fmt.Println("This device is not in any network, so there was nothing to take down.")
		return nil
	}

	fmt.Println("Tunnels are down.")
	fmt.Println()
	fmt.Println("Traffic is using this machine's ordinary network again, including anything")
	fmt.Println("that was going through a full tunnel. Nothing is being carried over the mesh.")
	fmt.Println()
	fmt.Println("    sudo meshp up")
	fmt.Println()
	fmt.Println("This survives a reboot: the device stays off the mesh until you put it back.")
	return nil
}

// cmdUp puts it back.
func cmdUp(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp up", flag.ContinueOnError)
	socket := fs.String("socket", envOr("MESHP_SOCKET", agentapi.DefaultSocketPath), "meshpd's local socket")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	status, err := agentapi.NewClient(*socket, 30*time.Second).SetRunning(ctx, true)
	if err != nil {
		return describeDaemonError(err, *socket)
	}
	if !status.Enrolled {
		fmt.Println("This device is not in any network yet. Join one first:")
		fmt.Println()
		fmt.Println("    sudo meshp join <token>")
		return nil
	}

	// Deliberately not "you are connected". Bringing sessions up is asynchronous — the
	// daemon has started them, and whether they reached a control plane is a different
	// question, answered by the command that asks.
	fmt.Println("Tunnels are coming back up; run 'meshp status' to see whether they did.")
	return nil
}
