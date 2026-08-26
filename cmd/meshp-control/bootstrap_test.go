package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/store"
	"github.com/meshpnet/meshp/internal/testdb"
	"github.com/meshpnet/meshp/migrations"
)

func bootstrapStore(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	url := testdb.URL(t, "bootstrap")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	st, err := store.Open(ctx, store.DefaultConfig(url), migrations.FS, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)

	rows, err := st.Pool().Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		if _, err := st.Pool().Exec(ctx, `DROP TABLE IF EXISTS "`+n+`" CASCADE`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		t.Fatal(err)
	}
	return st, ctx
}

// One command produces an organisation and an owner who can sign in.
//
// The whole of #161. Over HTTP this is an organisation call, a user call, a sign-in that
// stores a cookie and a token mint that needs an Origin header — every one correct, and none
// of it something a person standing a deployment up for the first time should have to
// understand.
func TestBootstrapCreatesAnOrganisationAndAnOwner(t *testing.T) {
	st, ctx := bootstrapStore(t)
	var out bytes.Buffer

	err := bootstrap(ctx, st, bootstrapOptions{
		Organization: "acme",
		Email:        "you@example.com",
	}, strings.NewReader("correct horse battery staple\n"), &out)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	if !strings.Contains(out.String(), "owner") {
		t.Errorf("the output does not say the account is an owner:\n%s", out.String())
	}

	// The account can actually sign in, which is the only thing that matters and is not
	// implied by the rows existing.
	session, err := st.SignIn(ctx, store.SignInRequest{
		Email: "you@example.com", Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("the account bootstrap created cannot sign in: %v", err)
	}

	// And holds the permissions an owner holds, which needs the built-in roles to have been
	// reconciled — the failure mode if they had not is an owner who can do nothing.
	held, err := st.PermissionsInOrganization(ctx, session.User.OrganizationID, session.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if held.Empty() {
		t.Error("the owner holds no permissions, so bootstrap made an account that can do nothing")
	}
}

// No MESHP_ADMIN_TOKEN anywhere in this, which is the larger half of what it removes.
//
// Creating the first account over the API needs the bootstrap secret, so before this a
// deployment could not have an account without first having a shared secret that can do
// everything. ADR-0024 §5's "it creates the first user, which is the only way a fresh
// deployment can have one" stops being true here, and that is worth a test rather than a
// sentence: somebody reintroducing the dependency should have to delete this.
func TestBootstrapNeedsNoAdministrativeToken(t *testing.T) {
	st, ctx := bootstrapStore(t)
	t.Setenv("MESHP_ADMIN_TOKEN", "")

	if err := bootstrap(ctx, st, bootstrapOptions{
		Organization: "acme", Email: "you@example.com",
	}, strings.NewReader("correct horse battery staple\n"), &bytes.Buffer{}); err != nil {
		t.Fatalf("bootstrap needed something it should not: %v", err)
	}
}

// Running it twice does not quietly make a second owner.
//
// Somebody running this again is almost always somebody who has forgotten they ran it, and
// a second account that can do everything is not the way to find that out.
func TestBootstrapRefusesOnADeploymentThatHasAccounts(t *testing.T) {
	st, ctx := bootstrapStore(t)

	if err := bootstrap(ctx, st, bootstrapOptions{
		Organization: "acme", Email: "you@example.com",
	}, strings.NewReader("correct horse battery staple\n"), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	err := bootstrap(ctx, st, bootstrapOptions{
		Organization: "globex", Email: "someone@example.com",
	}, strings.NewReader("correct horse battery staple\n"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("bootstrapping twice made a second owner")
	}
	// And says what is already there, so the person reading knows what they are looking at
	// rather than only that they cannot proceed.
	if !strings.Contains(err.Error(), "acme") {
		t.Errorf("the refusal does not name the organisation that exists: %v", err)
	}
}

// A token is minted only when somebody says what it is for.
//
// No default, deliberately: a credential minted without a stated purpose ends up being used
// for everything, which is the argument MintToken makes over HTTP and which a convenient
// default here would undo on the path everybody takes.
func TestBootstrapMintsATokenOnlyWhenAsked(t *testing.T) {
	t.Run("not asked", func(t *testing.T) {
		st, ctx := bootstrapStore(t)
		var out bytes.Buffer
		if err := bootstrap(ctx, st, bootstrapOptions{
			Organization: "acme", Email: "you@example.com",
		}, strings.NewReader("correct horse battery staple\n"), &out); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "meshp_api_") {
			t.Error("a token was minted without anybody saying what it was for")
		}
	})

	t.Run("asked", func(t *testing.T) {
		st, ctx := bootstrapStore(t)
		var out bytes.Buffer
		if err := bootstrap(ctx, st, bootstrapOptions{
			Organization: "acme", Email: "you@example.com",
			TokenPermissions: []string{"organization.networks.create", "network.read"},
		}, strings.NewReader("correct horse battery staple\n"), &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "meshp_api_") {
			t.Errorf("no token was printed when one was asked for:\n%s", out.String())
		}
	})
}

// A password is never a flag, so it is never in a shell history or in ps. Piped input is
// read as a line; a terminal reads without echo, which no test can exercise.
func TestBootstrapReadsAPasswordRatherThanTakingOne(t *testing.T) {
	if _, err := readPassword(strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Error("an empty password was accepted")
	}
	got, err := readPassword(strings.NewReader("a passphrase\n"), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "a passphrase" {
		t.Errorf("password = %q, want the line without its newline", got)
	}
}

// What it refuses before touching anything, so a typo costs a message rather than half a
// deployment.
func TestBootstrapRefusesAnIncompleteRequest(t *testing.T) {
	st, ctx := bootstrapStore(t)
	for _, tc := range []struct {
		name string
		opts bootstrapOptions
	}{
		{"no organisation", bootstrapOptions{Email: "you@example.com"}},
		{"no email", bootstrapOptions{Organization: "acme"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := bootstrap(ctx, st, tc.opts,
				strings.NewReader("correct horse battery staple\n"), &bytes.Buffer{}); err == nil {
				t.Error("accepted an incomplete request")
			}
		})
	}
	if _, err := os.Stat("."); err != nil {
		t.Fatal(err)
	}
}

// An organisation that already exists is adopted, not refused.
//
// Found by running the documented command against a database that had been through the old
// sequence, where the organisation was created over the API and the account came second. A
// deployment in that state has an organisation and nobody who can sign in, which is exactly
// the situation this command is for — and it failed with "an organisation with that name
// already exists", which is true and useless.
func TestBootstrapAdoptsAnOrganisationThatAlreadyExists(t *testing.T) {
	st, ctx := bootstrapStore(t)

	// What the old sequence left behind: an organisation, and no accounts at all.
	if _, err := st.CreateOrganization(ctx, "acme", "Acme"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := bootstrap(ctx, st, bootstrapOptions{
		Organization: "acme", Email: "you@example.com",
	}, strings.NewReader("correct horse battery staple\n"), &out); err != nil {
		t.Fatalf("bootstrapping into an existing organisation: %v", err)
	}

	// Said out loud, because silently using something that was already there is how a
	// person ends up with an account in a tenant they did not mean.
	if !strings.Contains(out.String(), "already existed") {
		t.Errorf("the output does not say the organisation was adopted:\n%s", out.String())
	}

	// And there is one organisation, not two.
	orgs, err := st.ListOrganizations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 1 {
		t.Errorf("%d organisations after adopting one, want 1", len(orgs))
	}
}
