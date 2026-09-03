package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/meshpnet/meshp/internal/cliapi"
)

// The names an administrator writes down (ADR-0021 §2).
//
// Nothing derives these from the peer list: a device's own name resolves already, and these
// are the extra ones somebody chose — `db.hq.meshp.internal` pointing at whichever machine
// is the database this month. So they are edited, and this is where.

type dnsRecord struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	FQDN  string `json:"fqdn"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl_seconds"`
}

func cmdDNS(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: meshp dns <list|add|remove>")
	}
	switch args[0] {
	case "list":
		return cmdDNSList(ctx, args[1:])
	case "add":
		return cmdDNSAdd(ctx, args[1:])
	case "remove":
		return cmdDNSRemove(ctx, args[1:])
	default:
		return fmt.Errorf("unknown verb %q; meshp dns takes list, add or remove", args[0])
	}
}

// dnsRecords reads a network's records.
func dnsRecords(ctx context.Context, client *cliapi.Client, networkID string) ([]dnsRecord, error) {
	var body struct {
		Records []dnsRecord `json:"records"`
	}
	err := client.Do(ctx, "GET", "/api/v1/networks/"+networkID+"/dns-records", nil, &body)
	return body.Records, err
}

func cmdDNSList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp dns list", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network, by slug or id")
	// One name can carry several records, and then a name is not enough to remove one. Off
	// by default because a column of UUIDs is noise for the reading this command is mostly
	// for; named in the error that needs it.
	ids := fs.Bool("ids", false, "Show record ids, which 'dns remove' takes when a name is ambiguous")
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
	records, err := dnsRecords(ctx, client, net.ID)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Printf("%s has no names beyond the ones devices resolve for themselves.\n", net.qualified())
		return nil
	}

	// The fully qualified name, because that is what somebody types into a browser — the
	// short name is what they typed into `dns add` and is only half the answer.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if *ids {
		_, _ = fmt.Fprintln(w, "NAME\tTYPE\tVALUE\tTTL\tID")
	} else {
		_, _ = fmt.Fprintln(w, "NAME\tTYPE\tVALUE\tTTL")
	}
	for _, r := range records {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%ds", r.FQDN, r.Type, r.Value, r.TTL)
		if *ids {
			_, _ = fmt.Fprintf(w, "\t%s", r.ID)
		}
		_, _ = fmt.Fprintln(w)
	}
	return w.Flush()
}

func cmdDNSAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp dns add", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network, by slug or id")
	recordType := fs.String("type", "A", "A, AAAA or CNAME")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 2 {
		return errors.New("usage: meshp dns add <name> <value> [--type A] [--network n]")
	}

	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	net, err := chooseNetwork(ctx, client, *wantNetwork, cred.Network)
	if err != nil {
		return err
	}

	var out dnsRecord
	body := map[string]any{
		"name":  rest[0],
		"type":  strings.ToUpper(*recordType),
		"value": rest[1],
	}
	if err := client.Do(ctx, "POST",
		"/api/v1/networks/"+net.ID+"/dns-records", body, &out); err != nil {
		return err
	}
	fmt.Printf("%s resolves to %s. Every device in %s is being told.\n",
		out.FQDN, out.Value, net.qualified())
	return nil
}

func cmdDNSRemove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp dns remove", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network, by slug or id")
	yes := fs.Bool("yes", false, "Do not ask")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: meshp dns remove <name> [--network n]")
	}

	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	net, err := chooseNetwork(ctx, client, *wantNetwork, cred.Network)
	if err != nil {
		return err
	}
	records, err := dnsRecords(ctx, client, net.ID)
	if err != nil {
		return err
	}
	target, err := findRecord(records, rest[0])
	if err != nil {
		return err
	}

	if err := confirm(*yes, fmt.Sprintf(
		"Remove %s, which resolves to %s? Devices stop resolving it immediately.",
		target.FQDN, target.Value)); err != nil {
		return err
	}
	if err := client.Do(ctx, "DELETE",
		"/api/v1/networks/"+net.ID+"/dns-records/"+target.ID, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Removed %s.\n", target.FQDN)
	return nil
}

// findRecord resolves a name that may be short, fully qualified, or an id.
//
// Both forms, because `dns list` prints the long one and `dns add` took the short one, and
// requiring somebody to convert between two things the tool showed them is the sort of
// friction that makes a command line worse than the curl it replaced.
func findRecord(records []dnsRecord, want string) (dnsRecord, error) {
	var matched []dnsRecord
	for _, r := range records {
		if r.ID == want {
			return r, nil
		}
		if strings.EqualFold(r.Name, want) || strings.EqualFold(r.FQDN, want) {
			matched = append(matched, r)
		}
	}
	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		return dnsRecord{}, fmt.Errorf("no name %q in this network", want)
	default:
		// One name can carry several records — two A records for a pair of machines is the
		// ordinary way to say "either of these". Removing whichever came back first would
		// take away half an answer.
		return dnsRecord{}, fmt.Errorf(
			"%q has %d records; name one by its id, which 'meshp dns list --ids' prints",
			want, len(matched))
	}
}
