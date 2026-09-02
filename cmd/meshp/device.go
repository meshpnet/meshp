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
	"time"

	"golang.org/x/term"

	"github.com/meshpnet/meshp/internal/cliapi"
	"github.com/meshpnet/meshp/internal/clicred"
)

// The first noun (ADR-0032). Nothing here is new server behaviour: `GET
// /networks/{id}/devices` has listed memberships since #113, revoking has been a route since
// #28 and erasing since #218, and the page has done all three for a while. What was missing
// was a way to do them without a browser, which is half of what parity means.
//
// Reading these routes rather than adding to them is deliberate. A verb that needed an
// endpoint shaped for it would be a verb defining the API, and ADR-0009 makes the API the
// contract that three clients share.

// network is one row of GET /api/v1/networks.
type network struct {
	ID                string `json:"id"`
	Slug              string `json:"slug"`
	Name              string `json:"name"`
	OrganizationID    string `json:"organization_id"`
	OrganizationSlug  string `json:"organization_slug"`
	ActiveDeviceCount int    `json:"active_device_count"`
}

// qualified is how a network is named to a person: organisation and slug, because a slug
// alone is only unique within one and an MSP's whole point is holding several.
func (n network) qualified() string { return n.OrganizationSlug + "/" + n.Slug }

// membership is one row of GET /api/v1/networks/{id}/devices.
type membership struct {
	MembershipID string     `json:"membership_id"`
	DeviceID     string     `json:"device_id"`
	DeviceName   string     `json:"device_name"`
	State        string     `json:"state"`
	AddressV4    string     `json:"address_v4"`
	AddressV6    string     `json:"address_v6"`
	JoinedAt     time.Time  `json:"joined_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
}

// signedIn builds a client from the stored credential.
func signedIn() (*cliapi.Client, clicred.Credential, error) {
	cred, err := clicred.Load()
	if errors.Is(err, clicred.ErrNotSignedIn) {
		return nil, cred, errors.New("not signed in; run 'meshp login'")
	}
	if err != nil {
		return nil, cred, err
	}
	client, err := cliapi.New(cred.ControlURL, cred.Token)
	return client, cred, err
}

// chooseNetwork resolves which network a command is about.
//
// Three sources, in this order: what the command said, what `meshp network use` chose, and
// — only when there is exactly one — inference. Guessing among several would put the blast
// radius of `device revoke` on whichever network happened to sort first.
//
// A remembered choice that no longer resolves is an error rather than a fallback to
// inference. It names a network somebody deliberately selected, and quietly acting on a
// different one because that selection went stale is the failure this ordering exists to
// prevent.
func chooseNetwork(ctx context.Context, client *cliapi.Client, want, remembered string) (network, error) {
	var body struct {
		Networks []network `json:"networks"`
	}
	if err := client.Do(ctx, "GET", "/api/v1/networks", nil, &body); err != nil {
		return network{}, err
	}
	if len(body.Networks) == 0 {
		return network{}, errors.New("this account can see no networks")
	}

	if want == "" {
		want = remembered
	}
	if want == "" {
		if len(body.Networks) == 1 {
			return body.Networks[0], nil
		}
		names := make([]string, 0, len(body.Networks))
		for _, n := range body.Networks {
			names = append(names, n.OrganizationSlug+"/"+n.Slug)
		}
		sort.Strings(names)
		return network{}, fmt.Errorf(
			"this account can see %d networks, so --network or 'meshp network use' is needed: %s",
			len(body.Networks), strings.Join(names, ", "))
	}

	for _, n := range body.Networks {
		if n.ID == want || n.Slug == want || n.qualified() == want {
			return n, nil
		}
	}
	if want == remembered {
		return network{}, fmt.Errorf(
			"'meshp network use' chose %q and there is no such network now; "+
				"pick another with 'meshp network use', or 'meshp network use --clear'", want)
	}
	return network{}, fmt.Errorf("no network called %q", want)
}

// findDevice resolves an argument that is either an id or a name.
//
// Names because that is what a person has: the id is a UUID nobody has memorised, and every
// other way of naming a device here — the page, an audit line — shows the name. Ambiguity is
// refused rather than resolved, because picking one of two devices called "laptop" to revoke
// is the wrong kind of helpful.
func findDevice(devices []membership, want string) (membership, error) {
	var byName []membership
	for _, d := range devices {
		if d.MembershipID == want || d.DeviceID == want {
			return d, nil
		}
		if strings.EqualFold(d.DeviceName, want) {
			byName = append(byName, d)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return membership{}, fmt.Errorf("no device called %q in this network", want)
	default:
		return membership{}, fmt.Errorf(
			"%d devices are called %q; name one by its id instead", len(byName), want)
	}
}

// listDevices reads a network's memberships.
func listDevices(ctx context.Context, client *cliapi.Client, networkID string) ([]membership, error) {
	var body struct {
		Devices []membership `json:"devices"`
	}
	err := client.Do(ctx, "GET", "/api/v1/networks/"+networkID+"/devices", nil, &body)
	return body.Devices, err
}

func cmdDevice(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: meshp device <list|revoke|forget>")
	}
	switch args[0] {
	case "list":
		return cmdDeviceList(ctx, args[1:])
	case "revoke":
		return cmdDeviceRevoke(ctx, args[1:])
	case "forget":
		return cmdDeviceForget(ctx, args[1:])
	default:
		return fmt.Errorf("unknown verb %q; meshp device takes list, revoke or forget", args[0])
	}
}

func cmdDeviceList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp device list", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network, by slug or id")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	net, err := chooseNetwork(ctx, client, *wantNetwork, cred.Network)
	if err != nil {
		return err
	}
	devices, err := listDevices(ctx, client, net.ID)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		fmt.Printf("No devices in %s/%s.\n", net.OrganizationSlug, net.Slug)
		return nil
	}

	// Revoked memberships are shown, as the API sends them and the page draws them: an
	// administrator checking that a device really is out needs to see that it is out.
	// Discarded explicitly: a tabwriter buffers, so nothing here can fail until Flush, and
	// Flush is the one whose error is returned.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tADDRESS\tSTATE\tDEVICE ID")
	for _, d := range devices {
		address := d.AddressV4
		if address == "" {
			address = d.AddressV6
		}
		if address == "" {
			address = "—"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.DeviceName, address, d.State, d.DeviceID)
	}
	return w.Flush()
}

func cmdDeviceRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp device revoke", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network, by slug or id")
	reason := fs.String("reason", "", "Recorded in the audit trail, and sent to the device")
	yes := fs.Bool("yes", false, "Do not ask")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: meshp device revoke <name|id> [--network n] [--reason why]")
	}

	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	net, err := chooseNetwork(ctx, client, *wantNetwork, cred.Network)
	if err != nil {
		return err
	}
	devices, err := listDevices(ctx, client, net.ID)
	if err != nil {
		return err
	}
	target, err := findDevice(devices, rest[0])
	if err != nil {
		return err
	}
	if target.State == "revoked" {
		fmt.Printf("%s is already revoked in %s/%s.\n", target.DeviceName, net.OrganizationSlug, net.Slug)
		return nil
	}

	if err := confirm(*yes, fmt.Sprintf(
		"Revoke %s from %s/%s? It loses access immediately and must enrol again.",
		target.DeviceName, net.OrganizationSlug, net.Slug)); err != nil {
		return err
	}

	body := map[string]any{"reason": *reason}
	if err := client.Do(ctx, "DELETE",
		"/api/v1/networks/"+net.ID+"/devices/"+target.MembershipID, body, nil); err != nil {
		return err
	}
	// What actually happened, rather than "done": the device keeps its key and its address,
	// and what changed is that nobody else will accept it (ADR-0007's shape).
	fmt.Printf("Revoked %s. Every other device in %s/%s has been told to drop its key.\n",
		target.DeviceName, net.OrganizationSlug, net.Slug)
	return nil
}

func cmdDeviceForget(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp device forget", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network to find the device in")
	yes := fs.Bool("yes", false, "Do not ask")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: meshp device forget <name|id> [--network n]")
	}

	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	net, err := chooseNetwork(ctx, client, *wantNetwork, cred.Network)
	if err != nil {
		return err
	}
	devices, err := listDevices(ctx, client, net.ID)
	if err != nil {
		return err
	}
	target, err := findDevice(devices, rest[0])
	if err != nil {
		return err
	}

	// Offered on a device that has not been revoked, which the page does not do.
	//
	// Not a divergence in what the two clients may do — the API allows it either way, and
	// parity is measured against the API (ADR-0032 §1). The page hides it because a button
	// beside a device still carrying traffic is one mis-click from erasing it; a command
	// somebody typed in full and then confirmed is not that. Forgetting emits the peer
	// removals regardless, so the key is dropped whether or not a revoke came first.
	//
	// Erasing is organisation-scoped and reaches every network at once, so the confirmation
	// says that rather than naming the network the device was found in.
	if err := confirm(*yes, fmt.Sprintf(
		"Forget %s? This erases the device, its keys and its memberships in every network. "+
			"It cannot be undone, and the audit trail is all that will be left of it.",
		target.DeviceName)); err != nil {
		return err
	}

	var out struct {
		Name     string   `json:"name"`
		Networks []string `json:"networks"`
	}
	if err := client.Do(ctx, "DELETE",
		"/api/v1/organizations/"+net.OrganizationID+"/devices/"+target.DeviceID, nil, &out); err != nil {
		return err
	}
	fmt.Printf("Forgot %s, which was in %d network(s). The audit trail keeps what it did.\n",
		out.Name, len(out.Networks))
	return nil
}

// confirm asks before something irreversible, unless told not to.
//
// A script has no terminal to answer with, so it must pass --yes rather than hang. Refusing
// is the default for the same reason the page uses window.confirm on these two: they are the
// most consequential things either client can do.
func confirm(skip bool, question string) error {
	if skip {
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("no terminal to confirm at; pass --yes if you mean it")
	}
	fmt.Printf("%s [y/N]: ", question)
	var line string
	_, _ = fmt.Scanln(&line)
	if !strings.EqualFold(strings.TrimSpace(line), "y") {
		return errors.New("not confirmed")
	}
	return nil
}
