package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/meshpnet/meshp/internal/acl"
	"github.com/meshpnet/meshp/internal/cliapi"
)

// The access policy, as a document rather than a form (ADR-0032 §3).
//
// That section is about the page and applies here for the same reason: a policy is text
// somebody composes, and the failure worth designing against is publishing one that is
// subtly not what was meant. So the document is edited as itself, parsed before it can be
// sent, and shown as a diff against what is live — three things `curl` does not do, which
// is the bar §3 set for replacing it.
//
// `acl test` asks the control plane rather than compiling here. A faithful dry-run has to
// resolve the policy against store.PolicyDevices — which decides who a policy applies to,
// excluding the revoked, the suspended and the addressless — and the tags selectors match
// on are not on the devices endpoint at all. Compiling locally would be a second
// implementation of a rule that must not drift (ADR-0023) answering with confidence it has
// not earned.

// policyDoc is what GET /networks/{id}/acl answers.
type policyDoc struct {
	Version   int             `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	Document  json.RawMessage `json:"document"`
}

func cmdACL(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: meshp acl <show|edit|test|apply|versions>")
	}
	switch args[0] {
	case "show":
		return cmdACLShow(ctx, args[1:])
	case "edit":
		return cmdACLEdit(ctx, args[1:])
	case "apply":
		return cmdACLApply(ctx, args[1:])
	case "versions":
		return cmdACLVersions(ctx, args[1:])
	case "test":
		return cmdACLTest(ctx, args[1:])
	default:
		return fmt.Errorf("unknown verb %q; meshp acl takes show, edit, test, apply or versions", args[0])
	}
}

// livePolicy reads the document in force, and says so when there is none.
//
// A network with no policy is unfiltered rather than closed, which is a fact worth stating
// plainly every time: somebody who reads "not found" and assumes the default is deny has
// the network backwards.
func livePolicy(ctx context.Context, client *cliapi.Client, networkID string) (policyDoc, bool, error) {
	var out policyDoc
	err := client.Do(ctx, "GET", "/api/v1/networks/"+networkID+"/acl", nil, &out)
	var apiErr *cliapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == "no_policy" {
		return policyDoc{}, false, nil
	}
	if err != nil {
		return policyDoc{}, false, err
	}
	return out, true, nil
}

// indented is the document as somebody would want to edit it.
func indented(raw json.RawMessage) ([]byte, error) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		return nil, fmt.Errorf("the control plane sent a document that will not re-indent: %w", err)
	}
	return append(pretty.Bytes(), '\n'), nil
}

// canonical renders a parsed document the way the control plane will hand it back, so that
// a diff shows what changed rather than how it was typed.
func canonical(doc acl.Document) ([]byte, error) {
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("re-encoding the policy: %w", err)
	}
	return append(encoded, '\n'), nil
}

// starterPolicy is what `acl edit` offers a network that has none.
//
// Deny-nothing, written out, rather than an empty file. A person editing from blank has to
// know the schema before they can start; a person editing from this has to change one line,
// and the one they change is the one that decides what is allowed.
const starterPolicy = `{
  "version": 1,
  "comment": "Every device may reach every other. Narrow this.",
  "rules": [
    { "src": ["*"], "dst": ["*"], "protocol": "any" }
  ]
}
`

func cmdACLShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp acl show", flag.ContinueOnError)
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
	policy, exists, err := livePolicy(ctx, client, net.ID)
	if err != nil {
		return err
	}
	if !exists {
		fmt.Printf("%s has no policy, so every device may reach every other.\n", net.qualified())
		return nil
	}
	pretty, err := indented(policy.Document)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "# %s, version %d, published %s\n",
		net.qualified(), policy.Version, policy.CreatedAt.Format(time.RFC3339))
	_, err = os.Stdout.Write(pretty)
	return err
}

func cmdACLVersions(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp acl versions", flag.ContinueOnError)
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
	var body struct {
		Policies []struct {
			Version   int       `json:"version"`
			Active    bool      `json:"active"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"policies"`
	}
	if err := client.Do(ctx, "GET", "/api/v1/networks/"+net.ID+"/acl/versions", nil, &body); err != nil {
		return err
	}
	if len(body.Policies) == 0 {
		fmt.Printf("%s has never had a policy.\n", net.qualified())
		return nil
	}
	for _, p := range body.Policies {
		mark := " "
		if p.Active {
			mark = "*"
		}
		fmt.Printf("%s %-4d %s\n", mark, p.Version, p.CreatedAt.Format(time.RFC3339))
	}
	return nil
}

func cmdACLApply(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp acl apply", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network, by slug or id")
	yes := fs.Bool("yes", false, "Do not ask")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: meshp acl apply <file> [--network n]")
	}

	proposed, err := os.ReadFile(rest[0])
	if err != nil {
		return fmt.Errorf("reading %s: %w", rest[0], err)
	}

	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	net, err := chooseNetwork(ctx, client, *wantNetwork, cred.Network)
	if err != nil {
		return err
	}
	return publishPolicy(ctx, client, net, proposed, *yes)
}

func cmdACLEdit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp acl edit", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network, by slug or id")
	yes := fs.Bool("yes", false, "Do not ask before publishing")
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
	policy, exists, err := livePolicy(ctx, client, net.ID)
	if err != nil {
		return err
	}

	before := []byte(starterPolicy)
	if exists {
		if before, err = indented(policy.Document); err != nil {
			return err
		}
	}

	edited, err := editInEditor(ctx, before, net.qualified())
	if err != nil {
		return err
	}
	if string(edited) == string(before) {
		fmt.Println("Unchanged. Nothing published.")
		return nil
	}
	return publishPolicy(ctx, client, net, edited, *yes)
}

// publishPolicy validates, shows what changes, asks, and sends.
func publishPolicy(ctx context.Context, client *cliapi.Client, net network, proposed []byte, yes bool) error {
	// Parsed here as well as by the control plane, which will reject it anyway. Locally is
	// where the author is: a malformed document should cost a message, not a round trip and
	// a 400 whose body somebody has to go and read.
	if len(proposed) > maxPolicyBytes {
		return fmt.Errorf(
			"that policy is %d bytes and this control plane accepts %d; nothing was sent",
			len(proposed), maxPolicyBytes)
	}
	doc, err := acl.Parse(proposed)
	if err != nil {
		return fmt.Errorf("that document is not a policy: %w", err)
	}

	// Compared in the form the control plane keeps, not the form it was written in.
	//
	// A policy is stored parsed, so what comes back is canonical JSON however it was typed.
	// Diffing a hand-written file against that shows every line as changed the moment the
	// two disagree about whitespace — applying a byte-identical file a second time produced
	// a twenty-line diff, which is a diff nobody can read for what actually moved.
	after, err := canonical(doc)
	if err != nil {
		return err
	}

	live, exists, err := livePolicy(ctx, client, net.ID)
	if err != nil {
		return err
	}
	var before []byte
	if exists {
		if before, err = indented(live.Document); err != nil {
			return err
		}
	}

	if string(before) == string(after) {
		// Refused rather than published. An identical policy would be a new version with
		// the same content, and a history where half the entries changed nothing is one
		// nobody can read backwards to find when something did.
		fmt.Printf("%s already has exactly this policy. Nothing published.\n", net.qualified())
		return nil
	}

	// The change, not the new blob. Publishing an access policy by looking at the whole
	// document means reading it for what somebody meant to change, and that is how a rule
	// nobody intended goes live.
	fmt.Print(diff(string(before), string(after)))
	if !exists {
		fmt.Printf("\n%s has no policy today, so this is the first: everything not permitted below stops being reachable.\n",
			net.qualified())
	}
	if err := confirm(yes, fmt.Sprintf("Publish this to %s?", net.qualified())); err != nil {
		return err
	}

	var out struct {
		Version int `json:"version"`
	}
	if err := client.Do(ctx, "PUT", "/api/v1/networks/"+net.ID+"/acl", json.RawMessage(after), &out); err != nil {
		return err
	}
	fmt.Printf("Published version %d to %s. Every device in it is being told.\n", out.Version, net.qualified())
	return nil
}

// editInEditor writes the document to a file, opens $EDITOR on it, and reads it back.
func editInEditor(ctx context.Context, current []byte, label string) ([]byte, error) {
	editor := os.Getenv("MESHP_EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		return nil, errors.New("no editor: set EDITOR, or use 'meshp acl apply <file>'")
	}

	dir, err := os.MkdirTemp("", "meshp-acl")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// Named for the network, because an editor tab saying `policy.json` is one somebody can
	// publish to the wrong place.
	path := filepath.Join(dir, strings.ReplaceAll(label, "/", "-")+".acl.json")
	if err := os.WriteFile(path, current, 0o600); err != nil {
		return nil, err
	}

	// Through a shell, so EDITOR can carry arguments the way it does everywhere else.
	cmd := exec.CommandContext(ctx, "sh", "-c", editor+" \"$1\"", "sh", path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s exited without saving: %w", editor, err)
	}
	return os.ReadFile(path)
}

// maxPolicyBytes is what the control plane accepts (internal/api/policy.go), refused here
// as well. Locally is where the author is: a document too large to publish should cost a
// message rather than a round trip and a 413.
const maxPolicyBytes = 1 << 20

// maxDiffLines bounds the part of a document compared line by line.
//
// The subsequence below is O(n*m) in time and memory, and its input is a file somebody
// named on the command line. Trimming the common prefix and suffix first means a policy
// edit — a rule changed, a rule added — compares only the handful of lines around the
// change however long the document is, so this cap is reached only by two documents that
// genuinely differ almost everywhere. Then a summary is more use than ten thousand marked
// lines nobody will read.
const maxDiffLines = 2000

// diff renders a line diff, marking what goes and what arrives.
//
// Its own rather than shelling out to diff(1): this runs on Windows too, and a policy is
// small enough that the simplest thing that shows the change is enough.
func diff(before, after string) string {
	old, next := lines(before), lines(after)

	// The shared ends, which for an edited policy is nearly all of it. Done first so the
	// expensive part below sees only what actually differs.
	var head, tail []string
	for len(old) > 0 && len(next) > 0 && old[0] == next[0] {
		head = append(head, old[0])
		old, next = old[1:], next[1:]
	}
	for len(old) > 0 && len(next) > 0 && old[len(old)-1] == next[len(next)-1] {
		tail = append([]string{old[len(old)-1]}, tail...)
		old, next = old[:len(old)-1], next[:len(next)-1]
	}

	var b strings.Builder
	for _, line := range head {
		fmt.Fprintf(&b, "  %s\n", line)
	}

	if len(old) > maxDiffLines || len(next) > maxDiffLines {
		// Bounded rather than attempted. Two documents differing over this many lines are
		// not being reviewed line by line by anybody.
		fmt.Fprintf(&b, "… %d lines replaced by %d, which is too much to show as a diff\n",
			len(old), len(next))
	} else {
		for _, line := range middle(old, next) {
			b.WriteString(line)
		}
	}

	for _, line := range tail {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	return b.String()
}

// middle renders the part that differs, matching what it can by subsequence.
func middle(old, next []string) []string {
	common := longestCommon(old, next)

	var out []string
	i, j := 0, 0
	for _, line := range common {
		for i < len(old) && old[i] != line {
			out = append(out, fmt.Sprintf("- %s\n", old[i]))
			i++
		}
		for j < len(next) && next[j] != line {
			out = append(out, fmt.Sprintf("+ %s\n", next[j]))
			j++
		}
		out = append(out, fmt.Sprintf("  %s\n", line))
		i++
		j++
	}
	for ; i < len(old); i++ {
		out = append(out, fmt.Sprintf("- %s\n", old[i]))
	}
	for ; j < len(next); j++ {
		out = append(out, fmt.Sprintf("+ %s\n", next[j]))
	}
	return out
}

// lines splits a document, without inventing a final empty one.
func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// longestCommon is the longest common subsequence of two line lists.
//
// Callers bound the input; see maxDiffLines. int32 rather than int because the table is the
// product of two lengths and the counts it holds cannot exceed either of them.
func longestCommon(a, b []string) []string {
	table := make([][]int32, len(a)+1)
	for i := range table {
		table[i] = make([]int32, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}
	var out []string
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			i++
		default:
			j++
		}
	}
	return out
}

// cmdACLTest asks what a device would enforce.
func cmdACLTest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp acl test", flag.ContinueOnError)
	wantNetwork := fs.String("network", "", "Which network, by slug or id")
	file := fs.String("file", "", "Test this document instead of the one in force")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: meshp acl test <device> [--file p.json] [--network n]")
	}

	client, cred, err := signedIn()
	if err != nil {
		return err
	}
	net, err := chooseNetwork(ctx, client, *wantNetwork, cred.Network)
	if err != nil {
		return err
	}

	body := map[string]any{"device": rest[0]}
	if *file != "" {
		proposed, err := os.ReadFile(*file)
		if err != nil {
			return fmt.Errorf("reading %s: %w", *file, err)
		}
		// Parsed here first, for the reason publishing gives: the author is here, and a
		// malformed document should cost a message rather than a round trip.
		if _, err := acl.Parse(proposed); err != nil {
			return fmt.Errorf("that document is not a policy: %w", err)
		}
		body["document"] = json.RawMessage(proposed)
	}

	var out struct {
		Device      string `json:"device"`
		DefaultDeny bool   `json:"default_deny"`
		Filter      struct {
			Inbound  []filterRule `json:"inbound"`
			Outbound []filterRule `json:"outbound"`
		} `json:"filter"`
	}
	if err := client.Do(ctx, "POST", "/api/v1/networks/"+net.ID+"/acl/test", body, &out); err != nil {
		return err
	}

	source := "the policy in force"
	if *file != "" {
		source = *file
	}
	fmt.Printf("%s in %s, under %s:\n", out.Device, net.qualified(), source)
	if out.DefaultDeny {
		fmt.Println("  everything not listed below is refused")
	} else {
		fmt.Println("  everything is permitted; the rules below add nothing")
	}
	printRules("inbound", out.Filter.Inbound)
	printRules("outbound", out.Filter.Outbound)
	return nil
}

// filterRule is one rule of a compiled packet filter.
type filterRule struct {
	Src      []string `json:"src_prefixes"`
	Dst      []string `json:"dst_prefixes"`
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
	Allow    bool     `json:"allow"`
}

// printRules renders one direction of a filter, in prefixes rather than in selectors.
//
// Prefixes because that is what the device enforces. A dry-run that echoed the tags back
// would be showing the document again, and the whole question is what the document turned
// into.
func printRules(direction string, rules []filterRule) {
	if len(rules) == 0 {
		fmt.Printf("  %s: nothing\n", direction)
		return
	}
	fmt.Printf("  %s:\n", direction)
	for _, r := range rules {
		verb := "allow"
		if !r.Allow {
			verb = "deny"
		}
		ports := ""
		if len(r.Ports) > 0 {
			ports = " ports " + strings.Join(r.Ports, ",")
		}
		fmt.Printf("    %-5s %-8s %s -> %s%s\n",
			verb, r.Protocol, orAny(r.Src), orAny(r.Dst), ports)
	}
}

func orAny(prefixes []string) string {
	if len(prefixes) == 0 {
		return "anywhere"
	}
	return strings.Join(prefixes, ",")
}
