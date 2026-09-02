package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/meshpnet/meshp/internal/cliapi"
	"github.com/meshpnet/meshp/internal/clicred"
)

// The second noun (ADR-0032), and the one that makes the first pleasant: `meshp device
// list` needed --network on every invocation for anybody who can see more than one.
//
// `use` is the only verb here with no endpoint behind it. Which network somebody is working
// on is not a fact about the deployment — two people signed into the same control plane are
// each looking at their own — so it belongs beside their credential and not in the database.

func cmdNetwork(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: meshp network <list|show|use|create>")
	}
	switch args[0] {
	case "list":
		return cmdNetworkList(ctx, args[1:])
	case "show":
		return cmdNetworkShow(ctx, args[1:])
	case "use":
		return cmdNetworkUse(ctx, args[1:])
	case "create":
		return cmdNetworkCreate(ctx, args[1:])
	default:
		return fmt.Errorf("unknown verb %q; meshp network takes list, show, use or create", args[0])
	}
}

// allNetworks reads what this account can see.
func allNetworks(ctx context.Context, client *cliapi.Client) ([]network, error) {
	var body struct {
		Networks []network `json:"networks"`
	}
	err := client.Do(ctx, "GET", "/api/v1/networks", nil, &body)
	sort.Slice(body.Networks, func(i, j int) bool {
		return body.Networks[i].qualified() < body.Networks[j].qualified()
	})
	return body.Networks, err
}

func cmdNetworkList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp network list", flag.ContinueOnError)
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	networks, err := allNetworks(ctx, client)
	if err != nil {
		return err
	}
	if len(networks) == 0 {
		fmt.Println("This account can see no networks.")
		return nil
	}

	// The chosen one is marked rather than listed apart, so the list stays in one order and
	// somebody can see at a glance which of these `meshp device list` would act on.
	chosen, _ := chooseNetwork(ctx, client, "", cred.Network)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "\tNETWORK\tNAME\tDEVICES")
	for _, n := range networks {
		mark := " "
		if n.ID == chosen.ID {
			mark = "*"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", mark, n.qualified(), n.Name, n.ActiveDeviceCount)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if chosen.ID != "" {
		fmt.Printf("\n* is what commands use here. Change it with 'meshp network use <name>'.\n")
	}
	return nil
}

func cmdNetworkShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp network show", flag.ContinueOnError)
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	want := ""
	if len(rest) == 1 {
		want = rest[0]
	} else if len(rest) > 1 {
		return errors.New("usage: meshp network show [<name>]")
	}

	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	net, err := chooseNetwork(ctx, client, want, cred.Network)
	if err != nil {
		return err
	}

	var body struct {
		Network struct {
			StateVersion int64 `json:"state_version"`
		} `json:"network"`
		Devices []struct {
			State string `json:"state"`
		} `json:"devices"`
		RouteGroups []struct {
			Slug        string   `json:"slug"`
			Kind        string   `json:"kind"`
			Prefixes    []string `json:"prefixes"`
			Advertisers []struct {
				DeviceName string `json:"device_name"`
				Health     string `json:"health"`
			} `json:"advertisers"`
		} `json:"route_groups"`
		FaultCount int `json:"fault_count"`
	}
	if err := client.Do(ctx, "GET", "/api/v1/networks/"+net.ID+"/overview", nil, &body); err != nil {
		return err
	}

	active := 0
	for _, d := range body.Devices {
		if d.State == "active" {
			active++
		}
	}

	fmt.Printf("%s  %s\n", net.qualified(), net.Name)
	fmt.Printf("  version   %d\n", body.Network.StateVersion)
	fmt.Printf("  devices   %d active, %d listed\n", active, len(body.Devices))
	// Said even when it is zero. "faults 0" is an answer; a line that appears only when
	// something is wrong makes its absence ambiguous with not having looked.
	fmt.Printf("  faults    %d\n", body.FaultCount)

	if len(body.RouteGroups) == 0 {
		fmt.Println("  routes    none")
		return nil
	}
	fmt.Println("  routes")
	for _, g := range body.RouteGroups {
		carried := strings.Join(g.Prefixes, ", ")
		if carried == "" {
			carried = "no prefixes"
		}
		fmt.Printf("    %-14s %-8s %s\n", g.Slug, g.Kind, carried)
		for _, a := range g.Advertisers {
			// Which advertiser is *chosen* is not shown, and cannot be: desired state
			// carries an ordered list of candidates and the agent decides which is alive
			// (ADR-0003), so no such fact exists server-side. The page has the same rule.
			fmt.Printf("      %-12s %s\n", a.DeviceName, a.Health)
		}
	}
	return nil
}

func cmdNetworkUse(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp network use", flag.ContinueOnError)
	clear := fs.Bool("clear", false, "Forget the choice, and go back to being asked")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}

	cred, err := clicred.Load()
	if errors.Is(err, clicred.ErrNotSignedIn) {
		return errors.New("not signed in; run 'meshp login'")
	}
	if err != nil {
		return err
	}

	if *clear {
		cred.Network = ""
		if err := clicred.Save(cred); err != nil {
			return err
		}
		fmt.Println("Forgotten. Commands will ask again where there is more than one network.")
		return nil
	}

	if len(rest) == 0 {
		if cred.Network == "" {
			fmt.Println("No network chosen. Pick one with 'meshp network use <name>'.")
			return nil
		}
		fmt.Println(cred.Network)
		return nil
	}
	if len(rest) != 1 {
		return errors.New("usage: meshp network use [<name>] [--clear]")
	}

	client, _, err := signedIn()
	if err != nil {
		return err
	}
	// Resolved before it is stored, so a typo fails here rather than on the next command
	// that tries to use it.
	net, err := chooseNetwork(ctx, client, rest[0], "")
	if err != nil {
		return err
	}
	cred.Network = rest[0]
	if err := clicred.Save(cred); err != nil {
		return err
	}
	fmt.Printf("Using %s. Commands here act on it unless --network says otherwise.\n", net.qualified())
	return nil
}

func cmdNetworkCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp network create", flag.ContinueOnError)
	name := fs.String("name", "", "What people read; defaults to the slug")
	pools := fs.String("pool", "", "Address pools devices are given addresses from, comma separated")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: meshp network create <slug> --pool 10.90.0.0/16 [--name x]")
	}
	if *pools == "" {
		// Refused rather than defaulted. An address pool decides what every device in this
		// network is numbered from and what it will collide with elsewhere (ADR-0005), and
		// picking one on somebody's behalf is picking it for years.
		return errors.New("--pool is needed: a network with no address pool can give no device an address")
	}

	client, _, err := signedIn()
	if err != nil {
		return err
	}

	var me struct {
		OrganizationID string `json:"organization_id"`
	}
	if err := client.Do(ctx, "GET", "/api/v1/me", nil, &me); err != nil {
		return err
	}
	if me.OrganizationID == "" {
		return errors.New("this credential belongs to no organisation, so there is nothing to create a network in")
	}

	var pool []string
	for _, p := range strings.Split(*pools, ",") {
		if p = strings.TrimSpace(p); p != "" {
			pool = append(pool, p)
		}
	}
	title := *name
	if title == "" {
		title = rest[0]
	}

	body := map[string]any{
		"organization_id": me.OrganizationID,
		"slug":            rest[0],
		"name":            title,
		"address_pools":   pool,
	}
	var out network
	if err := client.Do(ctx, "POST", "/api/v1/networks", body, &out); err != nil {
		return err
	}
	fmt.Printf("Created %s. Add a device with 'meshp device list --network %s' once one has joined.\n",
		rest[0], rest[0])
	return nil
}
