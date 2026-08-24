package authz

import (
	"strings"
	"testing"
)

// Every permission is `<family>.<...>.<action>`, and the family decides how it is checked
// rather than only how it reads. A permission in neither family would be checked by nothing.
func TestEveryPermissionBelongsToAFamily(t *testing.T) {
	for _, e := range Catalogue {
		name := string(e.Name)
		if !strings.HasPrefix(name, "network.") && !strings.HasPrefix(name, "organization.") {
			t.Errorf("%q is in neither family, so no middleware would ever check it", name)
		}
		if e.Description == "" {
			t.Errorf("%q has no description; it is served over the API and a bare string is a guess", name)
		}
		if strings.Count(name, ".") < 1 || strings.HasSuffix(name, ".") {
			t.Errorf("%q is not <resource>.<action>", name)
		}
	}
}

// No duplicates, because a duplicated entry means one of the two is being maintained and the
// other is not.
func TestTheCatalogueHasNoRepeats(t *testing.T) {
	seen := map[Permission]bool{}
	for _, e := range Catalogue {
		if seen[e.Name] {
			t.Errorf("%q appears twice", e.Name)
		}
		seen[e.Name] = true
	}
}

// The built-in roles nest, and each rung adds something.
//
// Nesting on its own is not worth asserting — each role here is built by appending to the one
// below, so it holds by construction. Strictness is the part that can fail: two built-in
// roles that grant the same set are two names for one thing, and the second is a choice
// somebody makes wrongly because they assume it means something.
func TestEachBuiltinRoleAddsSomethingToTheOneBelow(t *testing.T) {
	order := []string{RoleReader, RoleOperator, RoleAdministrator, RoleOwner}
	for i := 1; i < len(order); i++ {
		lower, higher := setFor(t, order[i-1]), setFor(t, order[i])
		for _, p := range lower.Sorted() {
			if !higher.Allows(Permission(p)) {
				t.Errorf("%s holds %q and %s does not, so the ladder has a rung out of order",
					order[i-1], p, order[i])
			}
		}
		if len(higher.Sorted()) <= len(lower.Sorted()) {
			t.Errorf("%s grants no more than %s, so they are two names for one role",
				order[i], order[i-1])
		}
	}
}

// The descriptions are shipped over the API and are how somebody picks a role. These assert
// that each one is true, because a role whose description is wrong is worse than one with no
// description: it is chosen on purpose for something it does not do.
func TestTheBuiltinDescriptionsAreTrue(t *testing.T) {
	// "Sees everything this control plane shows ... and changes nothing."
	for _, p := range setFor(t, RoleReader).Sorted() {
		if !IsRead(Permission(p)) {
			t.Errorf("reader holds %q, which is not a read", p)
		}
	}

	// "Adds and removes devices, and moves traffic between advertisers. Cannot change the
	// access policy, DNS, or which routes exist."
	operator := setFor(t, RoleOperator)
	for _, p := range []Permission{NetworkDevicesRevoke, NetworkEnrollmentTokensWrite, NetworkRoutesFailover} {
		if !operator.Allows(p) {
			t.Errorf("an operator cannot %q, which their description promises", p)
		}
	}
	for _, p := range []Permission{NetworkACLWrite, NetworkDNSWrite, NetworkRoutesWrite, NetworkEgressWrite} {
		if operator.Allows(p) {
			t.Errorf("an operator holds %q, which their description says they do not", p)
		}
	}

	// "Configures networks completely. Cannot create accounts or grant roles."
	administrator := setFor(t, RoleAdministrator)
	for _, p := range []Permission{NetworkACLWrite, NetworkDNSWrite, NetworkRoutesWrite, NetworkEgressWrite} {
		if !administrator.Allows(p) {
			t.Errorf("an administrator cannot %q, which is configuring a network", p)
		}
	}
	for _, p := range []Permission{OrganizationUsersWrite, OrganizationRolesBind, OrganizationTokensWrite} {
		if administrator.Allows(p) {
			t.Errorf("an administrator holds %q, which their description says they do not", p)
		}
	}
}

func setFor(t *testing.T, slug string) Set {
	t.Helper()
	for _, b := range Builtins() {
		if b.Slug != slug {
			continue
		}
		names := make([]string, 0, len(b.Permissions))
		for _, p := range b.Permissions {
			names = append(names, string(p))
		}
		return NewSet(names)
	}
	t.Fatalf("no built-in role %q", slug)
	return Set{}
}

// Every built-in role names permissions that exist.
//
// NewSet silently drops what it does not recognise — deliberately, because the strings come
// from a table an operator may have edited — so a typo in this file would produce a role
// that grants one thing fewer than it says, and nothing would fail.
func TestBuiltinRolesNameRealPermissions(t *testing.T) {
	for _, b := range Builtins() {
		for _, p := range b.Permissions {
			if !Known(string(p)) {
				t.Errorf("built-in role %q names %q, which is not in the catalogue", b.Slug, p)
			}
		}
		if b.Name == "" || b.Description == "" {
			t.Errorf("built-in role %q has no name or description", b.Slug)
		}
	}
}

// An owner holds everything, and holds it by being built from the catalogue rather than from
// a list. A permission added tomorrow reaches an owner without anybody remembering.
func TestAnOwnerHoldsTheWholeCatalogue(t *testing.T) {
	var owner Builtin
	for _, b := range Builtins() {
		if b.Slug == RoleOwner {
			owner = b
		}
	}
	if len(owner.Permissions) != len(Catalogue) {
		t.Fatalf("owner holds %d permissions and the catalogue has %d",
			len(owner.Permissions), len(Catalogue))
	}
}

// A caller holding everything holds what has not been invented yet. The bootstrap secret is
// the deployment's root credential and a list would describe it wrongly the moment the
// catalogue grew.
func TestEverythingIncludesWhatDoesNotExistYet(t *testing.T) {
	all := All()
	if !all.Allows(Permission("network.something.invented.later")) {
		t.Error("a caller holding everything was refused a permission added later")
	}
	if all.Empty() {
		t.Error("a caller holding everything reads as holding nothing")
	}
	if len(all.Sorted()) != 0 {
		t.Error("a caller holding everything produced a list, which no list describes honestly")
	}
}

// A permission string nobody recognises grants nothing, and does not stop the rest working.
// Roles are rows an operator can write into, so this is the ordinary case for a deployment
// that kept a role after a permission was renamed.
func TestAnUnknownPermissionGrantsNothingAndBreaksNothing(t *testing.T) {
	s := NewSet([]string{"network.read", "network.telepathy", ""})
	if !s.Allows(NetworkRead) {
		t.Error("a real permission was lost because an unrecognised one travelled with it")
	}
	if s.Allows(Permission("network.telepathy")) {
		t.Error("an unrecognised permission was granted")
	}
	if got := s.Sorted(); len(got) != 1 || got[0] != "network.read" {
		t.Errorf("Sorted() = %v, want just the recognised one", got)
	}
}

// Someone signed in with no role holds nothing, which is a different problem from holding
// the wrong thing: the fix is to be given a role rather than a different one.
func TestNoBindingsIsEmptyRatherThanWrong(t *testing.T) {
	if !NewSet(nil).Empty() {
		t.Error("a caller with no permissions did not read as empty")
	}
	if NewSet([]string{"network.read"}).Empty() {
		t.Error("a caller with a permission read as empty")
	}
}
