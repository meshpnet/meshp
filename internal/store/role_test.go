package store

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/authz"
	"github.com/meshpnet/meshp/migrations"
)

// roleFixture is an organisation, two networks in it, and a person.
type roleFixture struct {
	store *Store
	ctx   context.Context
	org   uuid.UUID
	netA  uuid.UUID
	netB  uuid.UUID
	user  User
}

func newRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	s := freshStore(t)
	ctx := testContext(t)
	if err := s.EnsureBuiltinRoles(ctx); err != nil {
		t.Fatalf("EnsureBuiltinRoles: %v", err)
	}

	org, err := s.CreateOrganization(ctx, "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	f := &roleFixture{store: s, ctx: ctx, org: org.ID}
	f.netA = f.network(t, "hq", "HQ")
	f.netB = f.network(t, "branch", "Branch")

	user, _, err := s.CreateUser(ctx, CreateUserRequest{
		Organization: org.ID, Email: "first@example.com", Name: "First",
		Password: "correct horse battery staple", Actor: BootstrapActor(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.user = user
	return f
}

func (f *roleFixture) network(t *testing.T, slug, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.store.pool.QueryRow(f.ctx,
		`INSERT INTO networks (organization_id, slug, name) VALUES ($1,$2,$3) RETURNING id`,
		f.org, slug, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *roleFixture) newUser(t *testing.T, email string) User {
	t.Helper()
	user, _, err := f.store.CreateUser(f.ctx, CreateUserRequest{
		Organization: f.org, Email: email, Name: email,
		Password: "correct horse battery staple", Actor: BootstrapActor(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// The built-in roles are a projection of the permission catalogue, and migration 0011
// deliberately creates their rows empty. If this reconciliation is ever not run, every
// signed-in person holds a role that grants nothing — which is the safe direction to fail
// in, and is exactly why the failure has to be visible here rather than as a support ticket.
func TestTheBuiltinRolesAreReconciledFromTheCatalogue(t *testing.T) {
	f := newRoleFixture(t)

	roles, err := f.store.ListRoles(f.ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][]string{}
	for _, role := range roles {
		if role.Builtin {
			found[role.Slug] = role.Permissions
		}
	}
	if len(found) != len(authz.Builtins()) {
		t.Fatalf("%d built-in roles, want %d", len(found), len(authz.Builtins()))
	}
	if got := len(found[authz.RoleOwner]); got != len(authz.Catalogue) {
		t.Errorf("owner holds %d permissions, want the whole catalogue of %d", got, len(authz.Catalogue))
	}
	if len(found[authz.RoleReader]) == 0 {
		t.Error("a reader holds nothing, so reconciliation did not happen")
	}
}

// Running it twice changes nothing, which is what makes it safe on every boot.
func TestReconcilingTwiceIsTheSameAsOnce(t *testing.T) {
	f := newRoleFixture(t)
	if err := f.store.EnsureBuiltinRoles(f.ctx); err != nil {
		t.Fatal(err)
	}
	roles, err := f.store.ListRoles(f.ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	builtins := 0
	for _, role := range roles {
		if role.Builtin {
			builtins++
		}
	}
	if builtins != len(authz.Builtins()) {
		t.Errorf("%d built-in roles after two reconciliations, want %d", builtins, len(authz.Builtins()))
	}
}

// The first person in an organisation owns it, and the next one does not.
//
// Somebody has to be able to grant a role and on a fresh organisation there is nobody who
// can, so the first account gets the role that can. Making every account after it an owner
// too is how a permission system ends up meaning nothing.
func TestTheFirstPersonInAnOrganisationOwnsIt(t *testing.T) {
	f := newRoleFixture(t)

	first, err := f.store.ListBindings(f.ctx, f.org, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].RoleSlug != authz.RoleOwner {
		t.Fatalf("the first person holds %v, want one owner binding", first)
	}

	second := f.newUser(t, "second@example.com")
	held, err := f.store.ListBindings(f.ctx, f.org, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0].RoleSlug != authz.RoleAdministrator {
		t.Fatalf("the second person holds %v, want one administrator binding", held)
	}
}

// The MSP case, and the reason role_bindings has a network_id at all.
//
// A technician who looks after one customer's network holds their role there and holds
// nothing next door. This is the property the whole slice exists for, so it is asserted
// directly rather than inferred from a route returning 403.
func TestAGrantNarrowedToOneNetworkReachesNoOther(t *testing.T) {
	f := newRoleFixture(t)
	tech := f.newUser(t, "tech@example.com")

	// Start from nothing: the account was created as an administrator, and this is about
	// what a narrowed grant adds rather than what a default gave.
	clearBindings(t, f, tech.ID)

	network := f.netA
	if _, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: tech.ID, Role: authz.RoleOperator,
		Network: &network, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	inA, err := f.store.PermissionsInNetwork(f.ctx, f.netA, tech.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !inA.Allows(authz.NetworkDevicesRevoke) {
		t.Error("the technician cannot revoke a device on the network they look after")
	}

	inB, err := f.store.PermissionsInNetwork(f.ctx, f.netB, tech.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !inB.Empty() {
		t.Errorf("the technician holds %v on somebody else's network", inB.Sorted())
	}
}

// The other half of the same rule, and the one that is easy to get wrong.
//
// A grant narrowed to one network must not carry an organisation-wide permission. Getting
// this wrong means a technician given a role inside one customer's network can create
// accounts across the whole organisation — and the mistake looks like nothing, because the
// permission is one the role legitimately contains.
func TestANarrowedGrantCarriesNoOrganisationPermission(t *testing.T) {
	f := newRoleFixture(t)
	tech := f.newUser(t, "tech@example.com")
	clearBindings(t, f, tech.ID)

	network := f.netA
	if _, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: tech.ID, Role: authz.RoleOwner,
		Network: &network, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}

	// An owner, narrowed to one network. Everything a network can hold:
	inA, err := f.store.PermissionsInNetwork(f.ctx, f.netA, tech.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !inA.Allows(authz.NetworkACLWrite) {
		t.Error("an owner narrowed to a network cannot publish that network's policy")
	}

	// And nothing at all across the organisation:
	across, err := f.store.PermissionsInOrganization(f.ctx, f.org, tech.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !across.Empty() {
		t.Errorf("a grant narrowed to one network reached the organisation: %v", across.Sorted())
	}
}

// A role granted in one organisation is not held in another. The lookup joins through the
// network's own row, so a network id from another tenant finds no bindings — which is also
// how "no such network" and "not yours" become the same answer.
func TestARoleDoesNotCrossTenants(t *testing.T) {
	f := newRoleFixture(t)

	other, err := f.store.CreateOrganization(f.ctx, "globex", "Globex")
	if err != nil {
		t.Fatal(err)
	}
	var otherNet uuid.UUID
	if err := f.store.pool.QueryRow(f.ctx,
		`INSERT INTO networks (organization_id, slug, name) VALUES ($1,'theirs','Theirs') RETURNING id`,
		other.ID).Scan(&otherNet); err != nil {
		t.Fatal(err)
	}

	// f.user is an owner of Acme.
	held, err := f.store.PermissionsInNetwork(f.ctx, otherNet, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !held.Empty() {
		t.Errorf("an owner of one organisation holds %v in another", held.Sorted())
	}

	across, err := f.store.PermissionsInOrganization(f.ctx, other.ID, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !across.Empty() {
		t.Errorf("an owner of one organisation holds %v across another", across.Sorted())
	}
}

// A grant cannot be narrowed to a network in somebody else's organisation. It would grant
// nothing — the lookup joins through the network's own organisation — but it would sit in a
// list looking like a grant somebody made on purpose.
func TestAGrantCannotNameAnotherTenantsNetwork(t *testing.T) {
	f := newRoleFixture(t)
	other, err := f.store.CreateOrganization(f.ctx, "globex", "Globex")
	if err != nil {
		t.Fatal(err)
	}
	var otherNet uuid.UUID
	if err := f.store.pool.QueryRow(f.ctx,
		`INSERT INTO networks (organization_id, slug, name) VALUES ($1,'theirs','Theirs') RETURNING id`,
		other.ID).Scan(&otherNet); err != nil {
		t.Fatal(err)
	}

	_, err = f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: f.user.ID, Role: authz.RoleReader,
		Network: &otherNet, Actor: BootstrapActor(),
	})
	if err == nil {
		t.Fatal("a grant was scoped to another organisation's network")
	}
	var inv *InvalidError
	if !errors.As(err, &inv) {
		t.Errorf("error = %v, want one whose text a caller can be shown", err)
	}
}

// Granting the same role twice is somebody making sure, not an error — and it does not
// produce two grants to revoke. The table's own unique constraint does not see an
// organisation-wide binding, because its network_id is NULL and PostgreSQL treats NULLs as
// distinct; a partial index in migration 0011 is what makes this true.
func TestGrantingTheSameRoleTwiceLeavesOneGrant(t *testing.T) {
	f := newRoleFixture(t)
	other := f.newUser(t, "other@example.com")

	for range 2 {
		if _, err := f.store.BindRole(f.ctx, BindRequest{
			Organization: f.org, User: other.ID, Role: authz.RoleReader,
			Actor: BootstrapActor(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	held, err := f.store.ListBindings(f.ctx, f.org, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	readers := 0
	for _, b := range held {
		if b.RoleSlug == authz.RoleReader {
			readers++
		}
	}
	if readers != 1 {
		t.Errorf("%d reader grants after granting it twice, want 1", readers)
	}
}

// An organisation keeps at least one owner. Recoverable either way — the administrative
// token is still a way back in — but recovering with the deployment's root credential
// because somebody removed their own last role is a worse afternoon than being told no.
func TestTheLastOwnerKeepsTheirRole(t *testing.T) {
	f := newRoleFixture(t)

	held, err := f.store.ListBindings(f.ctx, f.org, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 {
		t.Fatalf("the only person holds %d grants, want 1", len(held))
	}

	err = f.store.UnbindRole(f.ctx, UnbindRequest{
		Organization: f.org, Binding: held[0].ID, Actor: BootstrapActor(),
	})
	if !errors.Is(err, ErrLastOwner) {
		t.Fatalf("removing the last owner = %v, want ErrLastOwner", err)
	}

	// With a second owner it comes away, which is what makes the refusal a guard rather
	// than a rule that owners cannot be changed.
	second := f.newUser(t, "second@example.com")
	if _, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: second.ID, Role: authz.RoleOwner, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UnbindRole(f.ctx, UnbindRequest{
		Organization: f.org, Binding: held[0].ID, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatalf("removing an owner with another in place: %v", err)
	}
}

// Granting and revoking a role are audited, because deciding who may act is the thing an
// audit trail is most often read to answer.
func TestGrantingARoleIsAudited(t *testing.T) {
	f := newRoleFixture(t)
	other := f.newUser(t, "other@example.com")

	binding, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: other.ID, Role: authz.RoleReader,
		Actor: UserActor(f.user),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.UnbindRole(f.ctx, UnbindRequest{
		Organization: f.org, Binding: binding.ID, Actor: UserActor(f.user),
	}); err != nil {
		t.Fatal(err)
	}

	// Scoped to this one grant. The fixture creates accounts, and creating an account
	// grants a role, so the trail also holds the defaults those produced.
	rows, err := f.store.pool.Query(f.ctx,
		`SELECT action, actor_kind, actor_label, metadata->>'role' FROM audit_events
		 WHERE resource_id = $1 ORDER BY id`, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var seen []string
	for rows.Next() {
		var action, kind, label, role string
		if err := rows.Scan(&action, &kind, &label, &role); err != nil {
			t.Fatal(err)
		}
		if kind != "user" || label != f.user.Email {
			t.Errorf("%s was recorded as %s/%q, want the person who did it", action, kind, label)
		}
		if role != authz.RoleReader {
			t.Errorf("%s recorded the role as %q, want reader", action, role)
		}
		seen = append(seen, action)
	}
	if len(seen) != 2 || seen[0] != "role.granted" || seen[1] != "role.revoked" {
		t.Errorf("audit trail = %v, want [role.granted role.revoked]", seen)
	}
}

// An action that does not say who granted the role is refused, the same as every other
// audited action (see actor_test.go). Worth asserting here too: this is the newest audited
// write and the guard is only useful if new call sites go through it.
func TestGrantingWithoutAnActorIsRefused(t *testing.T) {
	f := newRoleFixture(t)
	other := f.newUser(t, "other@example.com")

	_, err := f.store.BindRole(f.ctx, BindRequest{
		Organization: f.org, User: other.ID, Role: authz.RoleReader,
	})
	if !errors.Is(err, ErrNoActor) {
		t.Errorf("granting a role anonymously = %v, want ErrNoActor", err)
	}
}

func clearBindings(t *testing.T, f *roleFixture, user uuid.UUID) {
	t.Helper()
	if _, err := f.store.pool.Exec(f.ctx, `DELETE FROM role_bindings WHERE user_id = $1`, user); err != nil {
		t.Fatal(err)
	}
}

// Upgrading does not lock anybody out.
//
// Before migration 0011 every authenticated user could do everything, because there was
// nothing to limit them with. Making permissions real without a backfill turns that into
// every authenticated user being able to do nothing — an upgrade that silently locks a
// deployment's people out of their own control plane, with the administrative token as the
// only way back and nothing to say why.
//
// The backfill is taken out of the migration file rather than restated here, so this tests
// the SQL that actually ships.
func TestUpgradingLeavesExistingPeopleAbleToWork(t *testing.T) {
	f := newRoleFixture(t)

	// The state a database migrated from 0010 is in: people, and no bindings at all.
	if _, err := f.store.pool.Exec(f.ctx, `DELETE FROM role_bindings`); err != nil {
		t.Fatal(err)
	}
	before, err := f.store.PermissionsInNetwork(f.ctx, f.netA, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Empty() {
		t.Fatal("the fixture did not reach the state this is testing from")
	}

	if _, err := f.store.pool.Exec(f.ctx, backfillFromMigration(t)); err != nil {
		t.Fatalf("running the backfill: %v", err)
	}

	after, err := f.store.PermissionsInNetwork(f.ctx, f.netA, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Allows(authz.NetworkACLWrite) || !after.Allows(authz.OrganizationRolesBind) {
		t.Errorf("after the backfill an existing account holds %v; it was able to do "+
			"everything before the upgrade and must still be able to grant a role", after.Sorted())
	}
}

// backfillFromMigration is the role_bindings INSERT out of migration 0011.
func backfillFromMigration(t *testing.T) string {
	t.Helper()
	body, err := fs.ReadFile(migrations.FS, "0011_permissions.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, _, _ := strings.Cut(string(body), "-- +goose Down")
	for _, statement := range strings.Split(up, ";") {
		if strings.Contains(statement, "INSERT INTO role_bindings") {
			return statement + ";"
		}
	}
	t.Fatal("migration 0011 no longer contains a role_bindings backfill")
	return ""
}
