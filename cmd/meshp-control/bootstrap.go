package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/meshpnet/meshp/internal/store"
)

// bootstrapOptions is what --bootstrap needs.
type bootstrapOptions struct {
	Organization string
	Name         string
	Email        string

	// TokenPermissions is what an API token minted here may do. Empty mints no token.
	//
	// No default, deliberately. A credential minted without saying what it is for ends up
	// being used for everything, and this is the one moment somebody is thinking about the
	// question — which is exactly the argument MintToken makes for requiring it over HTTP.
	// A convenient default here would undo that on the path everybody takes.
	TokenPermissions []string
}

// bootstrap creates a deployment's organisation and its first account.
//
// Against the database, the way migrations run, and for the reason this exists at all: over
// HTTP the same thing takes an organisation call, a user call, a sign-in that stores a
// cookie, and a token mint that needs an Origin header because it authenticates with that
// cookie (ADR-0022 §5, as rewritten). Every one of those is correct and none of them is
// something a person standing a deployment up for the first time should have to understand.
//
// What it removes is larger than the typing. The first two of those calls need
// MESHP_ADMIN_TOKEN, so a deployment could not have an account without first having a shared
// secret that can do everything. It can now, and ADR-0024 §5's "it creates the first user,
// which is the only way a fresh deployment can have one" stops being true — which is a
// simplification worth having made deliberately rather than fallen into.
func bootstrap(ctx context.Context, st *store.Store, opts bootstrapOptions, in io.Reader, out io.Writer) error {
	if opts.Organization == "" {
		return errors.New("--organisation names the tenant your networks belong to")
	}
	if opts.Email == "" {
		return errors.New("--email names the person who will own this deployment")
	}

	// Refused rather than adding a second owner. Somebody running this twice is almost
	// always somebody who has forgotten they ran it, and quietly making another account
	// that can do everything is not the way to find out.
	//
	// Asked of the whole deployment rather than of this organisation: the question is
	// whether there is anybody who could do this over the API instead, and there is as soon
	// as one account exists anywhere.
	accounts, err := st.AnyUsers(ctx)
	if err != nil {
		return fmt.Errorf("checking for existing accounts: %w", err)
	}
	if accounts {
		orgs, err := st.ListOrganizations(ctx)
		if err != nil {
			return fmt.Errorf("reading organisations: %w", err)
		}
		names := make([]string, 0, len(orgs))
		for _, org := range orgs {
			names = append(names, org.Slug)
		}
		return fmt.Errorf("this deployment already has accounts (organisations: %s); "+
			"sign in and add people through the API rather than bootstrapping again",
			strings.Join(names, ", "))
	}

	password, err := readPassword(in, out)
	if err != nil {
		return err
	}

	org, adopted, err := organizationFor(ctx, st, opts)
	if err != nil {
		return err
	}

	// The first person in an organisation becomes its owner, which CreateUser decides and
	// this does not override: somebody has to be able to grant a role and on a fresh
	// organisation there is nobody who can.
	user, binding, err := st.CreateUser(ctx, store.CreateUserRequest{
		Organization: org.ID,
		Email:        opts.Email,
		Password:     password,
		// Named as itself in the audit trail rather than as the bootstrap secret, which is
		// the whole point: this deployment may never have one.
		Actor: store.Actor{Kind: "system", Label: "meshp-control --bootstrap"},
	})
	if err != nil {
		return fmt.Errorf("creating the first account: %w", err)
	}

	// One write, one error to check, following printRelayKeypair — and the reason it gives
	// applies harder here. This prints a token that is shown once and stored nowhere: an
	// output that failed half way through, having reported success, would leave somebody
	// holding an account whose credential scrolled past into a broken pipe.
	var report strings.Builder
	if adopted {
		fmt.Fprintf(&report, "\nusing the organisation %q, which already existed\n", org.Slug)
	}
	fmt.Fprintf(&report, "\norganisation  %s\n", org.Slug)
	fmt.Fprintf(&report, "account       %s (%s)\n", user.Email, binding.RoleSlug)

	if len(opts.TokenPermissions) > 0 {
		minted, err := st.MintToken(ctx, store.MintTokenRequest{
			Organization: org.ID,
			Owner:        user.ID,
			Name:         "bootstrap",
			Scope:        opts.TokenPermissions,
			Actor:        store.UserActor(user),
		})
		if err != nil {
			// The account exists and is usable, so this is reported rather than fatal:
			// failing the whole command over a token would leave somebody thinking they
			// have to start again, when what they have is the important half.
			fmt.Fprintf(&report, "\nthe account was created and the token was not: %v\n", err)
			report.WriteString("mint one at POST /api/v1/me/tokens once you have signed in.\n")
		} else {
			fmt.Fprintf(&report, "token         %s\n", minted.Plaintext)
			report.WriteString("\nThat token is shown once. It carries only the permissions you named,\n")
			report.WriteString("and never more than its owner holds at the time it is used.\n")
		}
	}

	report.WriteString("\nSign in at this control plane's address with that email and password.\n")
	report.WriteString("MESHP_ADMIN_TOKEN is not needed for any of this; leave it unset unless you\n")
	report.WriteString("want a way back in when nobody can sign in.\n")

	_, err = io.WriteString(out, report.String())
	return err
}

// organizationFor makes the organisation, or adopts the one that is already there.
//
// Adopting rather than refusing, because "an organisation exists and nobody can sign in" is
// a real state with a boring cause: it is what the old sequence produced, where the
// organisation was created over the API and the account came second. Somebody in that
// position running this wants an account, and being told their organisation is in the way
// would be true and useless.
//
// Said out loud in the output, because silently using something that was already there is
// how a person ends up with an account in a tenant they did not mean.
func organizationFor(ctx context.Context, st *store.Store, opts bootstrapOptions) (store.Organization, bool, error) {
	org, err := st.CreateOrganization(ctx, opts.Organization, displayName(opts.Organization, opts.Name))
	if err == nil {
		return org, false, nil
	}
	if !errors.Is(err, store.ErrOrganizationExists) {
		return store.Organization{}, false, fmt.Errorf("creating the organisation: %w", err)
	}

	existing, err := st.ListOrganizations(ctx)
	if err != nil {
		return store.Organization{}, false, fmt.Errorf("reading organisations: %w", err)
	}
	for _, candidate := range existing {
		if candidate.Slug == opts.Organization {
			return candidate, true, nil
		}
	}
	// Unreachable unless the organisation was deleted between the two calls, which is not
	// a race worth handling beyond not pretending it cannot happen.
	return store.Organization{}, false, fmt.Errorf("organisation %q exists and could not be read",
		opts.Organization)
}

// displayName is what people read, defaulting to the slug when nobody said.
//
// CreateOrganization refuses an empty name on the grounds that a display name and a URL-safe
// identifier are different things — which is right for an API, where the caller is a program
// that can be told. Here the caller is a person at a prompt, and making them type "acme"
// twice to get started is friction with nothing behind it.
func displayName(slug, name string) string {
	if name != "" {
		return name
	}
	return slug
}

// readPassword asks twice, without echo.
//
// Not a flag. A password in --password is a password in the shell's history file and in the
// output of ps, where it is readable by every other process on the machine for as long as
// the command runs.
//
// Twice because there is no way back: this password is the only credential for the account
// that owns the deployment, and a typo discovered later means having nothing to sign in
// with. Compared rather than trusted for the same reason a password change asks for the
// current one.
func readPassword(in io.Reader, out io.Writer) (string, error) {
	// A terminal reads without echo. Anything else — a pipe in a test, a script somebody
	// insisted on — reads a line, which is honest about what it is doing rather than
	// pretending the input was hidden.
	file, isFile := in.(*os.File)
	if isFile && term.IsTerminal(int(file.Fd())) {
		// A failed prompt is not worth reporting: the person is looking at the terminal it
		// failed to reach, and what matters is whether the password was read.
		ask := func(prompt string) ([]byte, error) {
			_, _ = io.WriteString(out, prompt)
			typed, err := term.ReadPassword(int(file.Fd()))
			_, _ = io.WriteString(out, "\n")
			return typed, err
		}

		first, err := ask("Password for the owner account: ")
		if err != nil {
			return "", fmt.Errorf("reading the password: %w", err)
		}
		second, err := ask("Again: ")
		if err != nil {
			return "", fmt.Errorf("reading the password: %w", err)
		}
		if string(first) != string(second) {
			return "", errors.New("those did not match")
		}
		return string(first), nil
	}

	line, err := io.ReadAll(in)
	if err != nil {
		return "", fmt.Errorf("reading the password: %w", err)
	}
	password := strings.TrimRight(string(line), "\r\n")
	if password == "" {
		return "", errors.New("no password given; run this on a terminal, or pipe one in")
	}
	return password, nil
}

// runBootstrap opens a store, brings the schema up to date, and bootstraps.
//
// Migrating here rather than requiring the control plane to have been started first: the
// order that would otherwise be needed — start it, let it migrate, stop it, bootstrap — is
// one nobody would guess and everybody would get wrong the first time.
func runBootstrap(ctx context.Context, log *slog.Logger, cfg runConfig, opts bootstrapOptions) error {
	st, err := open(ctx, log, cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	return bootstrap(ctx, st, opts, os.Stdin, os.Stdout)
}

// splitPermissions reads a comma-separated list, ignoring the empty entries a trailing comma
// leaves behind.
func splitPermissions(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
