package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/meshpnet/meshp/internal/cliapi"
	"github.com/meshpnet/meshp/internal/clicred"
)

// cmdLogin signs a person in and keeps a token.
//
// It opens a session the way the page does, uses it once to mint an API token, and ends it.
// What is stored is the token: a password on disk is not revocable without changing it
// everywhere, and it is the one credential that also opens the page (ADR-0031 §1).
func cmdLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp login", flag.ContinueOnError)
	controlURL := fs.String("control-url", envOr("MESHP_CONTROL_URL", ""),
		"the control plane to sign in to")
	email := fs.String("email", "", "your email address; asked for if not given")
	token := fs.String("token", "",
		"an API token to use instead of signing in; for CI, where nobody can type a password")
	name := fs.String("name", "", "what to call this token; defaults to this machine's name")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	if *controlURL == "" {
		return errors.New("usage: meshp login --control-url https://control.example.com")
	}

	// A token given outright is stored as it is. Nothing to mint and nobody to ask.
	if *token != "" {
		return signInWithToken(ctx, *controlURL, *token)
	}

	address, err := askFor("Email", *email)
	if err != nil {
		return err
	}
	password, err := askForPassword()
	if err != nil {
		return err
	}

	client, err := cliapi.New(*controlURL, "")
	if err != nil {
		return err
	}

	// The session exists for the length of this command. It is not what gets stored.
	session, err := openSession(ctx, client, address, password)
	if err != nil {
		return err
	}
	defer func() { _ = session.close(ctx) }()

	minted, err := session.mintToken(ctx, tokenName(*name))
	if err != nil {
		return err
	}

	if err := clicred.Save(clicred.Credential{
		ControlURL: *controlURL,
		Token:      minted.Token,
		TokenID:    minted.ID,
		Email:      address,
	}); err != nil {
		return err
	}

	path, _ := clicred.Path()
	fmt.Printf("Signed in to %s as %s.\n\n", *controlURL, address)
	fmt.Printf("  token     %s\n", minted.Name)
	fmt.Printf("  kept in   %s\n\n", path)
	fmt.Println("It is an API token, not your password, and it can be taken away without")
	fmt.Println("changing one. 'meshp logout' forgets it here and offers to revoke it there,")
	fmt.Println("which asks for your password again: a token may not revoke itself.")
	return nil
}

// cmdLogout removes the credential here, and offers to revoke it there.
//
// The local half always happens, first, and cannot fail for anything the network does: a
// laptop being handed on is exactly when there is no connection, and "signed out" has to mean
// signed out.
//
// The other half needs a password, and that is not an oversight in this command. A token may
// not revoke itself — the control plane refuses it in those words: "a token that could mint a
// token would survive its own revocation" — so taking one away is something only the person
// can do. Asking is the honest consequence of a property worth having.
func cmdLogout(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshp logout", flag.ContinueOnError)
	local := fs.Bool("local", false,
		"only forget the credential here; leave it valid on the control plane until it expires")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	cred, err := clicred.Load()
	if errors.Is(err, clicred.ErrNotSignedIn) {
		fmt.Println("Not signed in.")
		return nil
	}
	if err != nil {
		return err
	}

	if err := clicred.Forget(); err != nil {
		return err
	}
	fmt.Println("Signed out here.")

	if *local {
		remainsValid(cred)
		return nil
	}
	if cred.TokenID == "" || cred.Email == "" {
		// Nothing to revoke by, and nothing to sign in as. Said rather than attempted.
		remainsValid(cred)
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println("\nThe token is still valid on the control plane. Revoking it needs a")
		fmt.Println("password, and there is no terminal to ask on.")
		remainsValid(cred)
		return nil
	}

	fmt.Printf("\nThe token is still valid on %s. Revoking it needs your password,\n", cred.ControlURL)
	fmt.Println("because a token may not revoke itself.")
	fmt.Println("Press enter to skip.")

	password, err := askForPassword()
	if err != nil || password == "" {
		remainsValid(cred)
		return nil
	}

	client, err := cliapi.New(cred.ControlURL, "")
	if err != nil {
		return err
	}
	session, err := openSession(ctx, client, cred.Email, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nCould not sign in to revoke it: %v\n", err)
		remainsValid(cred)
		return nil
	}
	defer func() { _ = session.close(ctx) }()

	if err := session.revokeToken(ctx, cred.TokenID); err != nil {
		fmt.Fprintf(os.Stderr, "\nCould not revoke it: %v\n", err)
		remainsValid(cred)
		return nil
	}
	fmt.Printf("\nRevoked it on %s.\n", cred.ControlURL)
	return nil
}

// remainsValid says what is still out there, and where to take it away.
//
// Names the API rather than a command, because `meshp token revoke` does not exist. Promising
// one is the thing #213 is about, and writing a new instance of it into the message that
// explains a leftover credential would be its own small joke.
func remainsValid(cred clicred.Credential) {
	fmt.Printf("\nThe token is still valid until it expires. It is listed at\n")
	fmt.Printf("  %s/api/v1/me/tokens\n", cred.ControlURL)
	if cred.TokenID != "" {
		fmt.Printf("and can be removed with a DELETE to that path plus /%s.\n", cred.TokenID)
	}
}

// signInWithToken stores a token somebody already has, checking it first.
//
// Checked rather than trusted, because the failure it prevents is a CI job that reports a
// successful login and then fails on its next command with something less clear.
func signInWithToken(ctx context.Context, controlURL, token string) error {
	client, err := cliapi.New(controlURL, token)
	if err != nil {
		return err
	}
	// Both names, because this endpoint answers with different ones depending on what is
	// asking: a session is a person and carries `email`, a token is a person acting through
	// a machine and carries `owner` (internal/api/usersession.go). Reading only `email` is
	// not an error when a token is used — it is an empty string, which is how `meshp login
	// --token` came to report "Signed in to … as " with nobody named. The same trap the
	// token id fell into in ADR-0031's implementation.
	var me struct {
		Email string `json:"email"`
		Owner string `json:"owner"`
	}
	if err := client.Do(ctx, http.MethodGet, "/api/v1/me", nil, &me); err != nil {
		// A refusal and an unanswered call are different things, and only one of them is
		// about the token. Telling somebody their credential was rejected when the host
		// never answered sends them to rotate a token that is fine.
		var apiErr *cliapi.Error
		if errors.As(err, &apiErr) {
			return fmt.Errorf("%s refused that token: %w", controlURL, err)
		}
		return err
	}
	who := me.Email
	if who == "" {
		who = me.Owner
	}
	if err := clicred.Save(clicred.Credential{
		ControlURL: controlURL, Token: token, Email: who,
	}); err != nil {
		return err
	}
	fmt.Printf("Signed in to %s as %s with the token given.\n", controlURL, who)
	return nil
}

// askFor reads a line, or returns what was already supplied.
func askFor(label, given string) (string, error) {
	if given != "" {
		return given, nil
	}
	fmt.Printf("%s: ", label)
	var line string
	if _, err := fmt.Scanln(&line); err != nil {
		return "", fmt.Errorf("reading your %s: %w", strings.ToLower(label), err)
	}
	return strings.TrimSpace(line), nil
}

// askForPassword reads without echoing.
func askForPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal to ask for a password; use --token for a script")
	}
	fmt.Print("Password: ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading your password: %w", err)
	}
	return string(raw), nil
}

// tokenName is what the token is called on the control plane.
//
// The machine's name, so that a person looking at a list of their tokens can tell which
// laptop to revoke. A token called "cli" on five machines is a list nobody can act on.
func tokenName(given string) string {
	if given != "" {
		return given
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "meshp cli"
	}
	return "meshp cli on " + host
}
