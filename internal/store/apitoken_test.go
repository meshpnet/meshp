package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/authz"
)

// mintFor is a token owned by the fixture's person, scoped to what the test cares about.
func (f *roleFixture) mintFor(t *testing.T, name string, scope []authz.Permission, network *uuid.UUID) MintedToken {
	t.Helper()
	names := make([]string, 0, len(scope))
	for _, p := range scope {
		names = append(names, string(p))
	}
	token, err := f.store.MintToken(f.ctx, MintTokenRequest{
		Organization: f.org, Owner: f.user.ID, Name: name,
		Scope: names, Network: network, Actor: UserActor(f.user),
	})
	if err != nil {
		t.Fatalf("minting %q: %v", name, err)
	}
	return token
}

// What is stored is a hash of what the holder was shown, and presenting it back finds it.
func TestAMintedTokenIsFoundByWhatWasShown(t *testing.T) {
	f := newRoleFixture(t)
	minted := f.mintFor(t, "ci", []authz.Permission{authz.NetworkRead}, nil)

	if !strings.HasPrefix(minted.Plaintext, APITokenPrefix) {
		t.Errorf("token %q does not carry the API prefix", minted.Plaintext)
	}

	// The plaintext is not in the database. A backup must not hand somebody a live
	// credential, which is the entire reason to store a hash.
	var stored int
	if err := f.store.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM api_tokens WHERE token_hash = $1::bytea`,
		[]byte(minted.Plaintext)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Error("the plaintext token is in the database")
	}

	found, err := f.store.FindToken(f.ctx, minted.Plaintext)
	if err != nil {
		t.Fatalf("presenting a freshly minted token: %v", err)
	}
	if found.ID != minted.ID || found.Owner != f.user.ID || found.OwnerEmail != f.user.Email {
		t.Errorf("found %+v, want the token that was minted, owned by its owner", found)
	}
}

// The intersection is live, and this is the whole design.
//
// A token whose permissions were frozen at creation would keep working after its owner was
// demoted — which is the exact failure the intersection exists to prevent. Nothing about the
// token changes here; the owner does.
func TestATokenLosesWhatItsOwnerLoses(t *testing.T) {
	f := newRoleFixture(t)
	minted := f.mintFor(t, "ci", []authz.Permission{authz.NetworkACLWrite, authz.NetworkRead}, nil)

	token, err := f.store.FindToken(f.ctx, minted.Plaintext)
	if err != nil {
		t.Fatal(err)
	}

	before, err := f.store.TokenPermissions(f.ctx, token, &f.netA)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Allows(authz.NetworkACLWrite) {
		t.Fatal("a token minted by an owner cannot publish a policy")
	}

	// The owner becomes a reader. The token is untouched.
	clearBindings(t, f, f.user.ID)
	if _, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: f.user.ID, Role: authz.RoleReader, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	after, err := f.store.TokenPermissions(f.ctx, token, &f.netA)
	if err != nil {
		t.Fatal(err)
	}
	if after.Allows(authz.NetworkACLWrite) {
		t.Error("the token still publishes policies after its owner was demoted to reader")
	}
	if !after.Allows(authz.NetworkRead) {
		t.Error("the token lost a permission its owner still holds")
	}
}

// And the other direction: a scope is a ceiling, not a grant. An owner who gains a
// permission does not thereby widen every token they ever minted.
func TestATokenDoesNotGainWhatItsOwnerGains(t *testing.T) {
	f := newRoleFixture(t)

	// Start the owner as a reader, so the token can only be minted for reads.
	clearBindings(t, f, f.user.ID)
	if _, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: f.user.ID, Role: authz.RoleReader, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}
	minted := f.mintFor(t, "watcher", []authz.Permission{authz.NetworkRead}, nil)

	// The owner is promoted back.
	if _, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: f.user.ID, Role: authz.RoleOwner, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	token, err := f.store.FindToken(f.ctx, minted.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.store.TokenPermissions(f.ctx, token, &f.netA)
	if err != nil {
		t.Fatal(err)
	}
	if held.Allows(authz.NetworkACLWrite) {
		t.Error("a token minted for reads gained a write when its owner was promoted")
	}
	if !held.Allows(authz.NetworkRead) {
		t.Error("the token lost what it was minted for")
	}
}

// A token narrowed to one network reaches that network and nothing else — including the
// organisation as a whole, which is where an `organization.` permission would be checked.
func TestATokenNarrowedToOneNetworkReachesNoOther(t *testing.T) {
	f := newRoleFixture(t)
	network := f.netA
	minted := f.mintFor(t, "branch-ci",
		[]authz.Permission{authz.NetworkRead, authz.OrganizationUsersRead}, &network)

	token, err := f.store.FindToken(f.ctx, minted.Plaintext)
	if err != nil {
		t.Fatal(err)
	}

	inA, err := f.store.TokenPermissions(f.ctx, token, &f.netA)
	if err != nil {
		t.Fatal(err)
	}
	if !inA.Allows(authz.NetworkRead) {
		t.Error("the token cannot read the network it was minted for")
	}

	inB, err := f.store.TokenPermissions(f.ctx, token, &f.netB)
	if err != nil {
		t.Fatal(err)
	}
	if !inB.Empty() {
		t.Errorf("the token holds %v on another network", inB.Sorted())
	}

	across, err := f.store.TokenPermissions(f.ctx, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !across.Empty() {
		t.Errorf("a token narrowed to one network holds %v across the organisation", across.Sorted())
	}
}

// Every way a token stops working reads the same to whoever presents it.
func TestADeadTokenIsNotRecognised(t *testing.T) {
	f := newRoleFixture(t)

	t.Run("revoked", func(t *testing.T) {
		minted := f.mintFor(t, "revoked-one", []authz.Permission{authz.NetworkRead}, nil)
		if err := f.store.RevokeToken(f.ctx, RevokeTokenRequest{
			Organization: f.org, Token: minted.ID, Actor: UserActor(f.user),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.FindToken(f.ctx, minted.Plaintext); !errors.Is(err, ErrNoSuchToken) {
			t.Errorf("a revoked token = %v, want ErrNoSuchToken", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		minted := f.mintFor(t, "expired-one", []authz.Permission{authz.NetworkRead}, nil)
		if _, err := f.store.pool.Exec(f.ctx,
			`UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`,
			minted.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.FindToken(f.ctx, minted.Plaintext); !errors.Is(err, ErrNoSuchToken) {
			t.Errorf("an expired token = %v, want ErrNoSuchToken", err)
		}
	})

	t.Run("owner suspended", func(t *testing.T) {
		minted := f.mintFor(t, "suspended-owner", []authz.Permission{authz.NetworkRead}, nil)
		if err := f.store.SetUserSuspended(f.ctx, f.org, f.user.ID, true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.store.SetUserSuspended(f.ctx, f.org, f.user.ID, false) })

		// Suspending somebody has to stop their machines too. A suspension that left a
		// credential of theirs working would be a decision the system agreed with and did
		// not act on.
		if _, err := f.store.FindToken(f.ctx, minted.Plaintext); !errors.Is(err, ErrNoSuchToken) {
			t.Errorf("a suspended owner's token = %v, want ErrNoSuchToken", err)
		}
	})

	t.Run("never existed", func(t *testing.T) {
		if _, err := f.store.FindToken(f.ctx, APITokenPrefix+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrNoSuchToken) {
			t.Errorf("an unknown token = %v, want ErrNoSuchToken", err)
		}
	})

	t.Run("not a token at all", func(t *testing.T) {
		// Refused on shape, before any lookup, so rubbish costs a parse rather than a query.
		if _, err := f.store.FindToken(f.ctx, "not-a-token"); !errors.Is(err, ErrNoSuchToken) {
			t.Errorf("nonsense = %v, want ErrNoSuchToken", err)
		}
	})
}

// You cannot mint a token for a permission you do not hold. The live intersection would make
// it useless anyway; being told at creation is the difference between a mistake caught now
// and a 403 from a machine at three in the morning.
func TestATokenCannotBeMintedBeyondItsOwner(t *testing.T) {
	f := newRoleFixture(t)
	clearBindings(t, f, f.user.ID)
	if _, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: f.user.ID, Role: authz.RoleReader, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	_, err := f.store.MintToken(f.ctx, MintTokenRequest{
		Organization: f.org, Owner: f.user.ID, Name: "too-much",
		Scope: []string{string(authz.NetworkACLWrite)}, Actor: UserActor(f.user),
	})
	var inv *InvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("minting beyond the owner = %v, want a refusal a caller can be shown", err)
	}
	if !strings.Contains(inv.Message, string(authz.NetworkACLWrite)) {
		t.Errorf("message = %q, want it to name the permission", inv.Message)
	}
}

// A credential minted without saying what it is for ends up being used for everything, and
// creation is the only moment somebody is thinking about the question.
func TestAScopeAndANameAreRequired(t *testing.T) {
	f := newRoleFixture(t)

	for _, tc := range []struct {
		name string
		req  MintTokenRequest
	}{
		{"no name", MintTokenRequest{Scope: []string{string(authz.NetworkRead)}}},
		{"no scope", MintTokenRequest{Name: "nameless"}},
		{"a permission that does not exist", MintTokenRequest{
			Name: "typo", Scope: []string{"network.telepathy"}}},
		{"longer than the ceiling", MintTokenRequest{
			Name: "forever", Scope: []string{string(authz.NetworkRead)},
			ExpiresIn: MaxTokenLife + time.Hour}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			req.Organization, req.Owner, req.Actor = f.org, f.user.ID, UserActor(f.user)
			_, err := f.store.MintToken(f.ctx, req)
			var inv *InvalidError
			if !errors.As(err, &inv) {
				t.Errorf("err = %v, want a refusal a caller can be shown", err)
			}
		})
	}
}

// The default life is finite. There is no unexpiring token, on purpose: a bearer secret that
// never expires outlives the reason it was made and usually the memory of what it was for.
func TestATokenAlwaysExpires(t *testing.T) {
	f := newRoleFixture(t)
	minted := f.mintFor(t, "default-life", []authz.Permission{authz.NetworkRead}, nil)

	life := time.Until(minted.ExpiresAt)
	if life <= 0 || life > MaxTokenLife {
		t.Errorf("a token minted with no expiry lives %v, want a finite life within the ceiling", life)
	}
	if delta := life - DefaultTokenLife; delta > time.Minute || delta < -time.Minute {
		t.Errorf("default life = %v, want about %v", life, DefaultTokenLife)
	}
}

// Recording that a credential was used must not turn a read into a write per request. A
// machine polling once a second would otherwise keep this table permanently hot for a column
// nobody reads more than once a day.
func TestUsingATokenDoesNotWriteEveryTime(t *testing.T) {
	f := newRoleFixture(t)
	minted := f.mintFor(t, "busy", []authz.Permission{authz.NetworkRead}, nil)

	if _, err := f.store.FindToken(f.ctx, minted.Plaintext); err != nil {
		t.Fatal(err)
	}
	var first time.Time
	if err := f.store.pool.QueryRow(f.ctx,
		`SELECT last_used_at FROM api_tokens WHERE id = $1`, minted.ID).Scan(&first); err != nil {
		t.Fatalf("the first use recorded nothing: %v", err)
	}

	for range 5 {
		if _, err := f.store.FindToken(f.ctx, minted.Plaintext); err != nil {
			t.Fatal(err)
		}
	}
	var latest time.Time
	if err := f.store.pool.QueryRow(f.ctx,
		`SELECT last_used_at FROM api_tokens WHERE id = $1`, minted.ID).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if !latest.Equal(first) {
		t.Errorf("last_used_at moved from %v to %v within the interval; every request is writing",
			first, latest)
	}

	// And it does move once it has gone stale, or the column would say nothing at all.
	if _, err := f.store.pool.Exec(f.ctx,
		`UPDATE api_tokens SET last_used_at = now() - interval '1 hour' WHERE id = $1`,
		minted.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.FindToken(f.ctx, minted.Plaintext); err != nil {
		t.Fatal(err)
	}
	var moved time.Time
	if err := f.store.pool.QueryRow(f.ctx,
		`SELECT last_used_at FROM api_tokens WHERE id = $1`, minted.ID).Scan(&moved); err != nil {
		t.Fatal(err)
	}
	if !moved.After(latest) {
		t.Error("last_used_at did not move after the interval had passed")
	}
}

// Somebody pruning their own tokens cannot reach a colleague's by guessing an id. Not found
// rather than forbidden: they have no business learning that the id belongs to anyone.
func TestPruningYourOwnTokensDoesNotReachAColleaguesUsingOwn(t *testing.T) {
	f := newRoleFixture(t)
	minted := f.mintFor(t, "alices", []authz.Permission{authz.NetworkRead}, nil)

	other := f.newUser(t, "other@example.com")
	err := f.store.RevokeToken(f.ctx, RevokeTokenRequest{
		Organization: f.org, Token: minted.ID, Owner: &other.ID, Actor: UserActor(other),
	})
	if !errors.Is(err, ErrNoSuchToken) {
		t.Errorf("revoking somebody else's token as your own = %v, want ErrNoSuchToken", err)
	}

	// Still alive, which is the point.
	if _, err := f.store.FindToken(f.ctx, minted.Plaintext); err != nil {
		t.Errorf("the token was revoked by somebody who should not have reached it: %v", err)
	}
}

// Two tokens by the same name are how a list becomes unprunable. Two people each having a
// token called 'ci' is not.
func TestATokenNameIsUniquePerPersonAndNotPerOrganisation(t *testing.T) {
	f := newRoleFixture(t)
	f.mintFor(t, "ci", []authz.Permission{authz.NetworkRead}, nil)

	_, err := f.store.MintToken(f.ctx, MintTokenRequest{
		Organization: f.org, Owner: f.user.ID, Name: "ci",
		Scope: []string{string(authz.NetworkRead)}, Actor: UserActor(f.user),
	})
	if !errors.Is(err, ErrTokenNameTaken) {
		t.Errorf("a second token called ci = %v, want ErrTokenNameTaken", err)
	}

	colleague := f.newUser(t, "colleague@example.com")
	if _, err := f.store.MintToken(f.ctx, MintTokenRequest{
		Organization: f.org, Owner: colleague.ID, Name: "ci",
		Scope: []string{string(authz.NetworkRead)}, Actor: UserActor(colleague),
	}); err != nil {
		t.Errorf("a colleague's token called ci was refused: %v", err)
	}
}

// Minting and revoking a credential are audited, and the trail names the person who did it.
func TestMintingAndRevokingATokenAreAudited(t *testing.T) {
	f := newRoleFixture(t)
	minted := f.mintFor(t, "audited", []authz.Permission{authz.NetworkRead}, nil)
	if err := f.store.RevokeToken(f.ctx, RevokeTokenRequest{
		Organization: f.org, Token: minted.ID, Actor: UserActor(f.user),
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := f.store.pool.Query(f.ctx,
		`SELECT action, actor_kind, actor_label, metadata->>'name' FROM audit_events
		 WHERE resource_id = $1 ORDER BY id`, minted.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var seen []string
	for rows.Next() {
		var action, kind, label string
		var name *string
		if err := rows.Scan(&action, &kind, &label, &name); err != nil {
			t.Fatal(err)
		}
		if kind != "user" || label != f.user.Email {
			t.Errorf("%s was recorded as %s/%q, want the person who did it", action, kind, label)
		}
		seen = append(seen, action)
	}
	if len(seen) != 2 || seen[0] != "api_token.minted" || seen[1] != "api_token.revoked" {
		t.Errorf("audit trail = %v, want [api_token.minted api_token.revoked]", seen)
	}
}

// Revoking a credential twice is somebody making sure, not an error — and it does not write
// a second audit event saying it happened again.
func TestRevokingATokenTwiceIsMakingSure(t *testing.T) {
	f := newRoleFixture(t)
	minted := f.mintFor(t, "twice", []authz.Permission{authz.NetworkRead}, nil)

	for range 2 {
		if err := f.store.RevokeToken(f.ctx, RevokeTokenRequest{
			Organization: f.org, Token: minted.ID, Actor: UserActor(f.user),
		}); err != nil {
			t.Fatalf("revoking: %v", err)
		}
	}

	var events int
	if err := f.store.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'api_token.revoked'`,
		minted.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("%d revocation events, want 1", events)
	}
}
