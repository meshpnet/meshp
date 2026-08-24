package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/authz"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// What a caller is allowed to tell apart.
var (
	// ErrNoSuchRole means no role by that slug exists for this organisation.
	ErrNoSuchRole = errors.New("store: no such role")

	// ErrNoSuchBinding means that grant is not this organisation's to remove.
	ErrNoSuchBinding = errors.New("store: no such role binding")

	// ErrLastOwner means removing this grant would leave the organisation with nobody who
	// can grant one.
	//
	// Refused rather than warned about. The administrative token is still a way back in
	// (ADR-0024 §5), so this is recoverable — but needing the deployment's root credential
	// because somebody removed their own last role is a bad afternoon, and the check that
	// prevents it costs one count.
	ErrLastOwner = errors.New("store: that is the last owner of this organisation")
)

// Role is a bag of permissions somebody can be granted.
type Role struct {
	ID   uuid.UUID
	Slug string
	Name string

	// Permissions as stored. Not filtered against the catalogue here: this is what the row
	// says, and a caller rendering it should be able to see a permission that no longer
	// exists rather than have it quietly disappear from a list somebody is trying to fix.
	Permissions []string

	// Builtin marks the four this control plane defines and reconciles at startup. An
	// organisation may add its own; it may not edit these, because they would be rewritten
	// on the next boot.
	Builtin bool

	// Organization is nil for a built-in, which every organisation shares.
	Organization *uuid.UUID
}

// Binding is one grant: a role, held by a person, within an organisation, optionally
// narrowed to a single network.
type Binding struct {
	ID   uuid.UUID
	User uuid.UUID

	RoleID   uuid.UUID
	RoleSlug string
	RoleName string

	// Network is nil for a grant that applies across the organisation. When it is set, the
	// grant reaches that network and nothing else — and in particular grants no
	// `organization.` permission at all.
	Network     *uuid.UUID
	NetworkSlug string
	NetworkName string

	Permissions []string
	CreatedAt   time.Time
}

// EnsureBuiltinRoles makes the four built-in roles say what internal/authz says.
//
// Called at startup, every startup. The permission list has one home — the catalogue — and
// these rows are a projection of it, so a route added in this release reaches an owner on
// the next boot without a migration. Migration 0011 creates the rows with no permissions at
// all, which is the safe direction to be wrong in if this never runs.
//
// An organisation's own roles are never touched. Only the shared rows, which is what
// `is_builtin` means: it is built in, so edit a copy.
func (s *Store) EnsureBuiltinRoles(ctx context.Context) error {
	for _, b := range authz.Builtins() {
		names := make([]string, 0, len(b.Permissions))
		for _, p := range b.Permissions {
			names = append(names, string(p))
		}
		if _, err := s.Queries().UpsertBuiltinRole(ctx, dbgen.UpsertBuiltinRoleParams{
			Slug: b.Slug, Name: b.Name, Permissions: names,
		}); err != nil {
			return fmt.Errorf("store: reconciling the %q role: %w", b.Slug, err)
		}
	}
	return nil
}

// PermissionsInNetwork is what this person may do in this network.
//
// One query per request, and per request on purpose: baking permissions into a session at
// sign-in would leave somebody who has just been demoted holding their old powers until they
// happened to sign out, which is the one thing a permission system must not do.
//
// An empty set is the answer for a person with no roles here, for a network that does not
// exist, and for a network in another organisation. The caller refuses all three the same
// way — telling them apart would answer "does this network exist" for somebody who cannot
// see it.
func (s *Store) PermissionsInNetwork(ctx context.Context, networkID, userID uuid.UUID) (authz.Set, error) {
	rows, err := s.Queries().ListPermissionsInNetwork(ctx, dbgen.ListPermissionsInNetworkParams{
		ID: networkID, UserID: userID,
	})
	if err != nil {
		return authz.Set{}, fmt.Errorf("store: reading permissions for a network: %w", err)
	}
	return authz.NewSet(flatten(rows)), nil
}

// PermissionsInOrganization is what this person may do across this organisation.
//
// Organisation-wide bindings only. Somebody who looks after one customer's network holds
// their role there and does not hold it over the organisation that network sits in — which
// is the whole point of a binding being narrowable, and is decided in the query rather than
// by every caller remembering.
func (s *Store) PermissionsInOrganization(ctx context.Context, orgID, userID uuid.UUID) (authz.Set, error) {
	rows, err := s.Queries().ListPermissionsInOrganization(ctx, dbgen.ListPermissionsInOrganizationParams{
		UserID: userID, OrganizationID: orgID,
	})
	if err != nil {
		return authz.Set{}, fmt.Errorf("store: reading permissions for an organisation: %w", err)
	}
	return authz.NewSet(flatten(rows)), nil
}

func flatten(rows [][]string) []string {
	var out []string
	for _, row := range rows {
		out = append(out, row...)
	}
	return out
}

// ListRoles returns what this organisation can grant: the built-ins, plus its own.
func (s *Store) ListRoles(ctx context.Context, orgID uuid.UUID) ([]Role, error) {
	rows, err := s.Queries().ListRolesForOrganization(ctx, &orgID)
	if err != nil {
		return nil, fmt.Errorf("store: listing roles: %w", err)
	}
	out := make([]Role, 0, len(rows))
	for _, row := range rows {
		out = append(out, Role{
			ID: row.ID, Slug: row.Slug, Name: row.Name,
			Permissions: row.Permissions, Builtin: row.IsBuiltin,
			Organization: row.OrganizationID,
		})
	}
	return out, nil
}

// BindRequest grants a role to somebody.
type BindRequest struct {
	Organization uuid.UUID
	User         uuid.UUID

	// Role is the slug somebody typed. An organisation's own role of that name wins over
	// the built-in.
	Role string

	// Network narrows the grant to one network. Nil grants it across the organisation.
	Network *uuid.UUID

	Actor    Actor
	SourceIP *netip.Addr
}

// BindRole grants a role, and records who granted it.
//
// Granting a role somebody already holds succeeds and changes nothing, because that is what
// the person asking meant. What comes back is the binding either way.
func (s *Store) BindRole(ctx context.Context, req BindRequest) (Binding, error) {
	var out Binding
	err := s.InTx(ctx, func(q *dbgen.Queries) error {
		var err error
		out, err = bindRole(ctx, q, req)
		return err
	})
	return out, err
}

// bindRole is the grant itself, inside somebody else's transaction.
//
// Separated from BindRole because creating an account and granting it a role happen
// together: an account with no role can do nothing, so the two must commit or fail as one
// rather than leaving somebody who can sign in and then cannot act.
func bindRole(ctx context.Context, q *dbgen.Queries, req BindRequest) (Binding, error) {
	role, err := q.GetRoleForOrganizationBySlug(ctx, dbgen.GetRoleForOrganizationBySlugParams{
		OrganizationID: &req.Organization, Slug: req.Role,
	})
	if IsNotFound(err) {
		return Binding{}, fmt.Errorf("%w: %q", ErrNoSuchRole, req.Role)
	}
	if err != nil {
		return Binding{}, fmt.Errorf("store: resolving the role: %w", err)
	}

	// A network-narrowed binding must name a network in this organisation. Without this a
	// grant could be scoped to another tenant's network — which would grant nothing, because
	// the lookup joins through the network's own organisation, but it would sit in the list
	// looking like a grant somebody made on purpose.
	if req.Network != nil {
		network, err := q.GetNetwork(ctx, *req.Network)
		if IsNotFound(err) || (err == nil && network.OrganizationID != req.Organization) {
			return Binding{}, invalid("that network is not in this organisation")
		}
		if err != nil {
			return Binding{}, fmt.Errorf("store: reading the network: %w", err)
		}
	}

	row, err := q.CreateRoleBinding(ctx, dbgen.CreateRoleBindingParams{
		RoleID: role.ID, UserID: req.User,
		OrganizationID: req.Organization, NetworkID: req.Network,
	})
	switch {
	case IsNotFound(err):
		// ON CONFLICT DO NOTHING returns no row when the grant already existed. Success:
		// somebody made sure of something that was already true.
		return Binding{
			User: req.User, RoleID: role.ID, RoleSlug: role.Slug, RoleName: role.Name,
			Network: req.Network, Permissions: role.Permissions,
		}, nil
	case IsForeignKeyViolation(err):
		// The user is not a row. Reported as no such user rather than as a database error,
		// because that is what it is.
		return Binding{}, fmt.Errorf("%w: %s", ErrNoSuchUser, req.User)
	case err != nil:
		return Binding{}, fmt.Errorf("store: granting the role: %w", err)
	}

	metadata, _ := json.Marshal(map[string]any{
		"role":       role.Slug,
		"user_id":    req.User.String(),
		"network_id": networkLabel(req.Network),
	})
	if err := WriteAudit(ctx, q, req.Actor, dbgen.CreateAuditEventParams{
		OrganizationID: &req.Organization,
		NetworkID:      req.Network,
		Action:         "role.granted",
		ResourceKind:   "role_binding",
		ResourceID:     &row.ID,
		SourceIp:       req.SourceIP,
		Metadata:       metadata,
	}); err != nil {
		return Binding{}, err
	}

	return Binding{
		ID: row.ID, User: row.UserID, RoleID: role.ID,
		RoleSlug: role.Slug, RoleName: role.Name,
		Network: row.NetworkID, Permissions: role.Permissions,
		CreatedAt: row.CreatedAt,
	}, nil
}

// UnbindRequest removes a grant.
type UnbindRequest struct {
	Organization uuid.UUID
	Binding      uuid.UUID

	Actor    Actor
	SourceIP *netip.Addr
}

// UnbindRole removes a grant, unless it is the last one that could put it back.
func (s *Store) UnbindRole(ctx context.Context, req UnbindRequest) error {
	return s.InTx(ctx, func(q *dbgen.Queries) error {
		// Read first, because what is being removed decides whether it may be, and because
		// the audit event should say what was taken away rather than only that something
		// was. Scoped by organisation, so a binding id from another tenant is not found
		// rather than inspected.
		target, err := q.GetRoleBindingForOrganization(ctx, dbgen.GetRoleBindingForOrganizationParams{
			ID: req.Binding, OrganizationID: req.Organization,
		})
		if IsNotFound(err) {
			return fmt.Errorf("%w: %s", ErrNoSuchBinding, req.Binding)
		}
		if err != nil {
			return fmt.Errorf("store: reading the grant: %w", err)
		}

		// The last organisation-wide owner keeps their role. Not because the deployment
		// would be unrecoverable — the administrative token is still there — but because
		// recovering with the deployment's root credential is a worse afternoon than being
		// told no.
		if target.RoleSlug == authz.RoleOwner && target.NetworkID == nil {
			owners, err := q.CountOrganizationWideBindingsOfRole(ctx,
				dbgen.CountOrganizationWideBindingsOfRoleParams{
					OrganizationID: req.Organization, RoleID: target.RoleID,
				})
			if err != nil {
				return fmt.Errorf("store: counting owners: %w", err)
			}
			if owners <= 1 {
				return ErrLastOwner
			}
		}

		affected, err := q.DeleteRoleBinding(ctx, dbgen.DeleteRoleBindingParams{
			ID: req.Binding, OrganizationID: req.Organization,
		})
		if err != nil {
			return fmt.Errorf("store: removing the grant: %w", err)
		}
		if affected == 0 {
			return fmt.Errorf("%w: %s", ErrNoSuchBinding, req.Binding)
		}

		metadata, _ := json.Marshal(map[string]any{
			"role":       target.RoleSlug,
			"user_id":    target.UserID.String(),
			"network_id": networkLabel(target.NetworkID),
		})
		return WriteAudit(ctx, q, req.Actor, dbgen.CreateAuditEventParams{
			OrganizationID: &req.Organization,
			NetworkID:      target.NetworkID,
			Action:         "role.revoked",
			ResourceKind:   "role_binding",
			ResourceID:     &req.Binding,
			SourceIp:       req.SourceIP,
			Metadata:       metadata,
		})
	})
}

// ListBindings is what this person holds in this organisation.
func (s *Store) ListBindings(ctx context.Context, orgID, userID uuid.UUID) ([]Binding, error) {
	rows, err := s.Queries().ListRoleBindingsForUser(ctx, dbgen.ListRoleBindingsForUserParams{
		UserID: userID, OrganizationID: orgID,
	})
	if err != nil {
		return nil, fmt.Errorf("store: listing role bindings: %w", err)
	}
	out := make([]Binding, 0, len(rows))
	for _, row := range rows {
		b := Binding{
			ID: row.ID, User: row.UserID, RoleID: row.RoleID,
			RoleSlug: row.RoleSlug, RoleName: row.RoleName,
			Network: row.NetworkID, Permissions: row.Permissions,
			CreatedAt: row.CreatedAt,
		}
		if row.NetworkSlug != nil {
			b.NetworkSlug = *row.NetworkSlug
		}
		if row.NetworkName != nil {
			b.NetworkName = *row.NetworkName
		}
		out = append(out, b)
	}
	return out, nil
}

// networkLabel renders a nullable network id for an audit event's metadata, where "the whole
// organisation" is a meaningful answer and an absent key is not.
func networkLabel(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return id.String()
}
