// Package authz is what a caller is allowed to do.
//
// A permission is a string, `<resource>.<action>`, and a role is a bag of them. Behaviour is
// never keyed off a role's name — the schema has said so since the first migration, and it
// is the difference between a role system and a hardcoded list of names with a table in
// front of it. Every check in this codebase asks whether a permission is held, never which
// role holds it.
//
// The catalogue below is public API. ADR-0009 makes the commercial layer a consumer of this
// one, and ADR-0023 records that shared surface cannot be reshaped freely afterwards:
// renaming a permission later breaks whatever keyed an alert or a role assignment on it. So
// a string here is chosen once. Adding one is cheap; changing one is not.
package authz

import (
	"sort"
	"strings"
)

// Permission is one thing a caller may do.
type Permission string

// Two families, and the difference decides how a permission is checked rather than only how
// it is named.
//
// A `network.` permission is held against one network, so a binding narrowed to a single
// network can grant it — that narrowing is what an MSP needs and it is the whole reason
// role_bindings has a network_id.
//
// An `organization.` permission is held over a whole tenant, and a binding narrowed to one
// network never grants one. A technician who works on a single customer's network must not
// be able to create accounts across the organisation because they were given a role
// somewhere inside it.
const (
	// Reading a network. The overview endpoint, which is the one thing the page needs.
	NetworkRead Permission = "network.read"

	// Reading the audit trail for a network. Separate from network.read because a trail
	// says who did what, and somebody who may watch a dashboard is not automatically
	// somebody who may see the names of everyone who touched it.
	NetworkAuditRead Permission = "network.audit.read"

	NetworkDevicesRead Permission = "network.devices.read"

	// Throwing a device off the network. Named `.revoke` rather than `.write` because it
	// is the destructive half of device management and nothing else in that family
	// deserves to travel with it.
	NetworkDevicesRevoke Permission = "network.devices.revoke"

	NetworkEnrollmentTokensRead  Permission = "network.enrollment_tokens.read"
	NetworkEnrollmentTokensWrite Permission = "network.enrollment_tokens.write"

	NetworkDNSRead  Permission = "network.dns.read"
	NetworkDNSWrite Permission = "network.dns.write"

	NetworkACLRead  Permission = "network.acl.read"
	NetworkACLWrite Permission = "network.acl.write"

	NetworkEgressRead  Permission = "network.egress.read"
	NetworkEgressWrite Permission = "network.egress.write"

	NetworkRoutesRead  Permission = "network.routes.read"
	NetworkRoutesWrite Permission = "network.routes.write"

	// Steering traffic between advertisers of a route. Its own permission, and the one
	// place this catalogue splits a resource three ways rather than two: changing which
	// advertiser carries a prefix is what somebody does at two in the morning when a link
	// is down, and changing which prefixes exist is not. An operator needs the first and
	// should not have the second.
	NetworkRoutesFailover Permission = "network.routes.failover"

	OrganizationNetworksRead   Permission = "organization.networks.read"
	OrganizationNetworksCreate Permission = "organization.networks.create"

	OrganizationUsersRead  Permission = "organization.users.read"
	OrganizationUsersWrite Permission = "organization.users.write"

	OrganizationRolesRead Permission = "organization.roles.read"

	// Reading and revoking the API tokens in an organisation. Somebody's own tokens are
	// not behind either of these — you mint and prune your own without needing a
	// permission, the same way you change your own password — so these are about
	// everybody else's, which is what somebody needs when a person leaves.
	OrganizationTokensRead  Permission = "organization.tokens.read"
	OrganizationTokensWrite Permission = "organization.tokens.write"

	// Granting and removing a role. The permission that decides who may act, kept apart
	// from every other so that "can change the network" and "can change who may change the
	// network" are different answers.
	OrganizationRolesBind Permission = "organization.roles.bind"
)

// Entry is a permission and what it means.
//
// The description is carried because the catalogue is served over the API: a consumer
// choosing which permissions a role should hold is choosing from this list, and a list of
// bare strings makes that a guess.
type Entry struct {
	Name        Permission
	Description string
}

// Catalogue is every permission this control plane recognises.
//
// One entry per thing a route does. A permission that no route requires is one nobody can
// use, and a route requiring a permission that is not here is one nobody can reach — both
// are failures, and both are tested for rather than reviewed for.
var Catalogue = []Entry{
	{NetworkRead, "See a network: its devices, their addresses, and what is wrong"},
	{NetworkAuditRead, "Read a network's audit trail"},
	{NetworkDevicesRead, "List the devices enrolled in a network"},
	{NetworkDevicesRevoke, "Remove a device from a network"},
	{NetworkEnrollmentTokensRead, "List a network's enrolment tokens"},
	{NetworkEnrollmentTokensWrite, "Mint and revoke enrolment tokens"},
	{NetworkDNSRead, "Read a network's DNS records"},
	{NetworkDNSWrite, "Add and remove DNS records"},
	{NetworkACLRead, "Read a network's access policy and its history"},
	{NetworkACLWrite, "Publish a new access policy"},
	{NetworkEgressRead, "Read whether a network fails closed on egress"},
	{NetworkEgressWrite, "Change whether a network fails closed on egress"},
	{NetworkRoutesRead, "Read a network's route groups and who advertises them"},
	{NetworkRoutesWrite, "Create and remove route groups and advertisers"},
	{NetworkRoutesFailover, "Choose which advertiser carries a route"},
	{OrganizationNetworksRead, "List the networks in an organisation"},
	{OrganizationNetworksCreate, "Create a network"},
	{OrganizationUsersRead, "List the people in an organisation"},
	{OrganizationUsersWrite, "Create, suspend, delete people and set their passwords"},
	{OrganizationRolesRead, "Read the roles an organisation has and who holds them"},
	{OrganizationTokensRead, "List the API tokens in an organisation and whose they are"},
	{OrganizationTokensWrite, "Revoke somebody else's API token"},
	{OrganizationRolesBind, "Grant and remove roles"},
}

// Known reports whether a string names a permission this control plane recognises.
//
// Used where a permission arrives from outside — a custom role in the database, a request
// body — so an unrecognised string is refused at the edge rather than stored and silently
// never matching anything.
func Known(name string) bool {
	for _, e := range Catalogue {
		if string(e.Name) == name {
			return true
		}
	}
	return false
}

// IsRead reports whether a permission only reads.
//
// Decided from the name, which is the reason the catalogue's names end in an action rather
// than starting with one. The browser session derived from the administrative token holds
// exactly these (see ReadOnly), so this predicate is what keeps that credential strictly
// weaker than the secret it came from.
func IsRead(p Permission) bool {
	return strings.HasSuffix(string(p), ".read")
}

// Set is what one caller may do.
type Set struct {
	// all is a caller that holds everything, present and future: the bootstrap secret,
	// which is the deployment's root credential and is not usefully described by a list.
	//
	// Deliberately not spelled as a wildcard permission in the database. A '*' stored in a
	// role would make every list of permissions a lie by omission, and would mean the
	// answer to "what can this role do" required knowing how to expand it.
	all bool

	have map[Permission]struct{}
}

// All is every permission, including ones that do not exist yet.
func All() Set { return Set{all: true} }

// ReadOnly is every permission that only reads.
//
// What the browser session minted from the administrative token holds (ADR-0022 §5). It is
// derived from a credential that can do everything and is strictly weaker than it, which is
// the entire argument for having shipped a page before accounts existed. Once a deployment
// signs people in with their own accounts this stops being reached.
func ReadOnly() Set {
	s := Set{have: make(map[Permission]struct{}, len(Catalogue))}
	for _, e := range Catalogue {
		if IsRead(e.Name) {
			s.have[e.Name] = struct{}{}
		}
	}
	return s
}

// NewSet collects permissions, ignoring any string this control plane does not recognise.
//
// Ignored rather than refused, because the strings come from a table an operator may have
// written into. A role naming a permission that no longer exists should grant nothing by
// that name, not stop its holder from signing in.
func NewSet(names []string) Set {
	s := Set{have: make(map[Permission]struct{}, len(names))}
	for _, name := range names {
		if Known(name) {
			s.have[Permission(name)] = struct{}{}
		}
	}
	return s
}

// Allows reports whether this caller holds a permission.
func (s Set) Allows(p Permission) bool {
	if s.all {
		return true
	}
	_, ok := s.have[p]
	return ok
}

// Empty reports whether this caller holds nothing at all.
//
// The shape of a signed-in person with no role binding: authenticated, and allowed nothing.
// Worth telling apart from a wrong permission, because the fix is different — somebody has
// to be given a role, rather than a different one.
func (s Set) Empty() bool { return !s.all && len(s.have) == 0 }

// Sorted is what this caller holds, for an API response. Empty for a caller holding
// everything, which no list describes honestly.
func (s Set) Sorted() []string {
	out := make([]string, 0, len(s.have))
	for p := range s.have {
		out = append(out, string(p))
	}
	sort.Strings(out)
	return out
}
