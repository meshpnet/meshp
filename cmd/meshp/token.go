package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/meshpnet/meshp/internal/cliapi"
	"github.com/meshpnet/meshp/internal/clicred"
)

// API tokens: the credential a machine holds, and the one this CLI signs in with.
//
// Not enrolment tokens, which are the one-time secret a device redeems to join a network.
// They share a word and nothing else — one is a person acting through a machine (ADR-0024
// §2), the other is a device proving it was invited — and `meshp login` mints the kind this
// noun manages, which is what settles which one `meshp token` should mean.
//
// **Every verb here signs in with a password rather than using the stored token.** That is
// not a choice this file made: `/api/v1/me/tokens` is behind guardSignedIn, and the control
// plane says why when a token tries it —
//
//	an API token cannot do this on its owner's behalf; a token that could mint a token
//	would survive its own revocation
//
// which is the property worth having. So these commands do what `meshp login` does: open a
// session, act, close it. It costs a password prompt, and the alternative is a credential
// that cannot be taken away from whoever holds it.

// withSession runs something as the signed-in person rather than as the stored token.
func withSession(ctx context.Context, run func(*session) error) error {
	cred, err := clicred.Load()
	if errors.Is(err, clicred.ErrNotSignedIn) {
		return errors.New("not signed in; run 'meshp login'")
	}
	if err != nil {
		return err
	}
	client, err := cliapi.New(cred.ControlURL, "")
	if err != nil {
		return err
	}

	email := cred.Email
	if email == "" {
		// A credential from `login --token` before #227 knew who it belonged to.
		if email, err = askFor("Email", ""); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "Signing in as %s to manage tokens.\n", email)
	password, err := askForPassword(
		"and an API token cannot manage tokens, so there is no scripted way to do this")
	if err != nil {
		return err
	}
	sess, err := openSession(ctx, client, email, password)
	if err != nil {
		return err
	}
	defer func() { _ = sess.close(ctx) }()
	return run(sess)
}

type apiToken struct {
	ID         string     `json:"token_id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	Owner      string     `json:"owner"`
	Revoked    bool       `json:"revoked"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

func cmdToken(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: meshp token <list|create|revoke>")
	}
	switch args[0] {
	case "list":
		return cmdTokenList(ctx, args[1:])
	case "create":
		return cmdTokenCreate(ctx, args[1:])
	case "revoke":
		return cmdTokenRevoke(ctx, args[1:])
	default:
		return fmt.Errorf("unknown verb %q; meshp token takes list, create or revoke", args[0])
	}
}

func cmdTokenList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp token list", flag.ContinueOnError)
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	cred, _ := clicred.Load()
	var body struct {
		Tokens []apiToken `json:"tokens"`
	}
	if err := withSession(ctx, func(s *session) error {
		return s.client.DoWithCookie(ctx, "GET", "/api/v1/me/tokens", s.cookie, nil, &body)
	}); err != nil {
		return err
	}
	if len(body.Tokens) == 0 {
		fmt.Println("You hold no API tokens.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "\tNAME\tSCOPE\tLAST USED\tEXPIRES")
	for _, t := range body.Tokens {
		// The one this command is running on is marked, because revoking it is the one
		// mistake here that locks somebody out of the thing they are using to fix it.
		mark := " "
		if t.ID == cred.TokenID {
			mark = "*"
		}
		state := t.ExpiresAt.Format("2006-01-02")
		if t.Revoked {
			state = "revoked"
		} else if time.Now().After(t.ExpiresAt) {
			state = "expired"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", mark, t.Name, t.Scope, lastUsed(t.LastUsedAt), state)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if cred.TokenID != "" {
		fmt.Println("\n* is the one this command signed in with.")
	}
	return nil
}

// lastUsed says how long ago, or that it never was.
//
// Coarse on purpose: the column exists to answer "is anything still using this", and a
// timestamp to the second invites reading it as a precise fact when the control plane
// records it only when it has drifted by more than a minute.
func lastUsed(at *time.Time) string {
	if at == nil {
		return "never"
	}
	d := time.Since(*at)
	switch {
	case d < time.Hour:
		return "within the hour"
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func cmdTokenCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp token create", flag.ContinueOnError)
	name := fs.String("name", "", "What to call it, so a list of tokens can be pruned")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if *name == "" && len(rest) == 1 {
		*name = rest[0]
	}
	if *name == "" {
		return errors.New("usage: meshp token create <name>")
	}

	// The whole catalogue, intersected per request with what the owner actually holds
	// (ADR-0024 §2). Asking for everything and receiving what the person has is what stops
	// a token being narrower than the person driving it for no reason they chose.
	var out struct {
		ID    string `json:"token_id"`
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := withSession(ctx, func(s *session) error {
		scope, err := s.permissions(ctx)
		if err != nil {
			return err
		}
		body := map[string]any{"name": *name, "permissions": scope}
		return s.client.DoWithCookie(ctx, "POST", "/api/v1/me/tokens", s.cookie, body, &out)
	}); err != nil {
		return err
	}

	// Once, and to stdout alone, so `meshp token create ci > token` gives a file holding
	// the secret and nothing else. The control plane keeps a hash; this is the only moment
	// the value exists.
	fmt.Fprintf(os.Stderr, "%s. This is the only time it is shown.\n", out.Name)
	fmt.Println(out.Token)
	return nil
}

func cmdTokenRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp token revoke", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "Do not ask")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: meshp token revoke <name|id>")
	}

	cred, _ := clicred.Load()
	var body struct {
		Tokens []apiToken `json:"tokens"`
	}
	var target apiToken
	if err := withSession(ctx, func(s *session) error {
		if err := s.client.DoWithCookie(ctx, "GET", "/api/v1/me/tokens", s.cookie, nil, &body); err != nil {
			return err
		}
		found, err := findToken(body.Tokens, rest[0])
		if err != nil {
			return err
		}
		target = found
		if target.Revoked {
			return nil
		}

		question := fmt.Sprintf("Revoke %s? Anything using it stops working immediately.", target.Name)
		if target.ID == cred.TokenID {
			// The one thing here that locks somebody out of the tool they would fix it with.
			question = fmt.Sprintf(
				"%s is the token this machine signed in with. Revoking it signs you out "+
					"here, and you will need 'meshp login' again. Continue?", target.Name)
		}
		if err := confirm(*yes, question); err != nil {
			return err
		}
		return s.client.DoWithCookie(ctx, "DELETE", "/api/v1/me/tokens/"+target.ID, s.cookie, nil, nil)
	}); err != nil {
		return err
	}
	if target.Revoked {
		fmt.Printf("%s is already revoked.\n", target.Name)
		return nil
	}
	fmt.Printf("Revoked %s.\n", target.Name)

	if target.ID == cred.TokenID {
		// The stored credential is now a secret that opens nothing. Left behind it would
		// make the next command fail with a refusal rather than with "not signed in".
		if err := clicred.Forget(); err != nil {
			return fmt.Errorf("revoked, but the local credential could not be removed: %w", err)
		}
		fmt.Println("Signed out here. Run 'meshp login' to sign in again.")
	}
	return nil
}

// findToken resolves a name or an id, and refuses a name that names two.
func findToken(tokens []apiToken, want string) (apiToken, error) {
	var matched []apiToken
	for _, t := range tokens {
		if t.ID == want {
			return t, nil
		}
		if strings.EqualFold(t.Name, want) {
			matched = append(matched, t)
		}
	}
	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		return apiToken{}, fmt.Errorf("you hold no token called %q", want)
	default:
		// Names are unique per person among tokens that are live, so this is a live one and
		// its revoked namesakes (migration 0016).
		var live []apiToken
		for _, t := range matched {
			if !t.Revoked {
				live = append(live, t)
			}
		}
		if len(live) == 1 {
			return live[0], nil
		}
		return apiToken{}, fmt.Errorf("%q names %d tokens; name one by its id", want, len(matched))
	}
}
