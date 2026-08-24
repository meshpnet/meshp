package authz

// The built-in roles.
//
// Four, and they differ along one axis each rather than by degree, so that choosing between
// them is a question somebody can answer without reading a permission list:
//
//   - a reader sees — everything readable, which is more than a network: bound over a whole
//     organisation, a reader can see who else has an account. Bound to a single network,
//     they cannot, because no `organization.` permission is ever granted by a binding
//     narrowed to one network. The two families are what makes that true;
//   - an operator acts within the rules — onboards a laptop, throws one off, moves traffic
//     to the other advertiser when a link dies;
//   - an administrator decides what the rules are — the access policy, DNS, whether egress
//     fails closed, which route groups exist;
//   - an owner decides who may act.
//
// They nest: everything a reader may do an operator may do, and so on up. That is asserted
// rather than assumed, because a ladder with a rung out of order is the kind of thing that
// is discovered by somebody being unable to do their job.
//
// These are rows in `roles` with a NULL organization_id, shared by every organisation, and
// they are reconciled from this file at startup rather than seeded once by a migration. The
// alternative — permission arrays written into SQL — means a migration every time a route is
// added, and two homes for the same list that drift the first time somebody updates one.
type Builtin struct {
	Slug        string
	Name        string
	Description string
	Permissions []Permission
}

// BuiltinSlugs, in the order they are offered. Least to most, so a list read top to bottom
// reads as increasing power.
const (
	RoleReader        = "reader"
	RoleOperator      = "operator"
	RoleAdministrator = "administrator"
	RoleOwner         = "owner"
)

// readerPermissions is every permission that only reads. Defined from the catalogue rather
// than listed, so a new read permission reaches a reader without anybody remembering to add
// it — which is the failure a listed set would have, and it would show up as somebody who
// can see most of a page.
func readerPermissions() []Permission {
	var out []Permission
	for _, e := range Catalogue {
		if IsRead(e.Name) {
			out = append(out, e.Name)
		}
	}
	return out
}

// Builtins is the four, built from each other so the ladder is a property of the code rather
// than of four lists somebody keeps in step.
func Builtins() []Builtin {
	reader := readerPermissions()

	operator := append(append([]Permission{}, reader...),
		NetworkDevicesRevoke,
		NetworkEnrollmentTokensWrite,
		NetworkRoutesFailover,
	)

	administrator := append(append([]Permission{}, operator...),
		NetworkDNSWrite,
		NetworkACLWrite,
		NetworkEgressWrite,
		NetworkRoutesWrite,
		OrganizationNetworksCreate,
	)

	// Everything, taken from the catalogue rather than listed: an owner who did not
	// automatically hold a newly added permission would be an owner in name only, and
	// nobody would notice until the permission was needed.
	owner := make([]Permission, 0, len(Catalogue))
	for _, e := range Catalogue {
		owner = append(owner, e.Name)
	}

	return []Builtin{
		{
			Slug: RoleReader, Name: "Reader",
			Description: "Sees everything this control plane shows, including who else has " +
				"an account, and changes nothing.",
			Permissions: reader,
		},
		{
			Slug: RoleOperator, Name: "Operator",
			Description: "Adds and removes devices, and moves traffic between advertisers. " +
				"Cannot change the access policy, DNS, or which routes exist.",
			Permissions: operator,
		},
		{
			Slug: RoleAdministrator, Name: "Administrator",
			Description: "Configures networks completely. Cannot create accounts, grant roles, " +
				"or revoke anybody else's credentials.",
			Permissions: administrator,
		},
		{
			Slug: RoleOwner, Name: "Owner",
			Description: "Everything, including deciding who may act.",
			Permissions: owner,
		},
	}
}

// IsBuiltinSlug reports whether a slug names one of the four.
func IsBuiltinSlug(slug string) bool {
	for _, b := range Builtins() {
		if b.Slug == slug {
			return true
		}
	}
	return false
}
