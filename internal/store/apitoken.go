package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/meshpnet/meshp/internal/authz"
	"github.com/meshpnet/meshp/internal/secret"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// APITokenPrefix marks a meshp API token.
//
// Distinct from the enrolment token's prefix so that one Authorization header can be told
// apart from another without a lookup, and so a secret scanner can recognise either.
const APITokenPrefix = "meshp_api_"

// Token lifetimes.
const (
	// DefaultTokenLife is what a token gets when its creator does not say.
	DefaultTokenLife = 90 * 24 * time.Hour

	// MaxTokenLife is the ceiling. There is deliberately no "never": a bearer secret that
	// does not expire is one that outlives the reason it was made, the person who made it,
	// and usually the deployment's memory of what it was for. Rotation is the cost of that
	// not being true, and a year is long enough that it is an annual chore rather than a
	// weekly one.
	MaxTokenLife = 365 * 24 * time.Hour

	// tokenTouchInterval is how stale last_used_at is allowed to get. A machine polling
	// once a second would otherwise turn a read into a write per second.
	tokenTouchInterval = time.Minute
)

// What a caller is allowed to tell apart.
var (
	// ErrNoSuchToken means no live token by that hash, or none by that id here.
	ErrNoSuchToken = errors.New("store: no such API token")

	// ErrTokenNameTaken means this person already has a token by that name.
	ErrTokenNameTaken = errors.New("store: you already have a token with that name")
)

// APIToken is a credential a machine presents.
type APIToken struct {
	ID             uuid.UUID
	Name           string
	OrganizationID uuid.UUID

	// Owner is whose permissions this token acts within. A token is a person acting through
	// a machine, and this is the person.
	Owner      uuid.UUID
	OwnerEmail string

	// Scope is what the token was allowed to do at creation. It only ever narrows: what the
	// token may actually do is this intersected with what the owner may do now.
	Scope []string

	// Network narrows the token to one network, the same shape a role binding uses. Nil
	// reaches every network the owner does.
	Network *uuid.UUID

	LastUsedAt *time.Time
	ExpiresAt  time.Time
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

// MintedToken is a token and the one chance to see its secret.
type MintedToken struct {
	APIToken

	// Plaintext is shown once and never stored. What the database holds is its SHA-256.
	Plaintext string
}

// MintTokenRequest asks for a credential.
type MintTokenRequest struct {
	Organization uuid.UUID

	// Owner is whose permissions the token will act within. Always the person asking:
	// minting a token for somebody else would be a way to act as them, and there is no
	// route that allows it.
	Owner uuid.UUID

	Name string

	// Scope is what the token may do, and it is required. A credential minted without
	// saying what it is for is one that ends up being used for everything.
	Scope []string

	Network   *uuid.UUID
	ExpiresIn time.Duration

	Actor    Actor
	SourceIP *netip.Addr
}

// MintToken creates a credential for a machine.
//
// The scope is checked against what the owner can do *now*, which is a courtesy rather than
// the enforcement: the real intersection happens at every use, in TokenPermissions. Checking
// here means somebody who asks for a permission they do not hold is told immediately, rather
// than discovering it as a 403 from a machine at three in the morning.
func (s *Store) MintToken(ctx context.Context, req MintTokenRequest) (MintedToken, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		// Refused rather than defaulted to something like "token 3". A list of credentials
		// nobody can tell apart is a list nobody will ever prune.
		return MintedToken{}, invalid("a token needs a name; it is how you will know which one to revoke")
	}
	if len(req.Scope) == 0 {
		return MintedToken{}, invalid(
			"say what the token may do; see GET /api/v1/permissions for the catalogue")
	}
	for _, p := range req.Scope {
		if !authz.Known(p) {
			return MintedToken{}, invalid("%q is not a permission; see GET /api/v1/permissions", p)
		}
	}

	life := req.ExpiresIn
	if life <= 0 {
		life = DefaultTokenLife
	}
	if life > MaxTokenLife {
		return MintedToken{}, invalid(
			"a token may live at most %d days; there is no unexpiring token, on purpose",
			int(MaxTokenLife.Hours()/24))
	}

	// What the owner may do where the token will be used. A token narrowed to one network is
	// checked there, because that is where its permissions will be resolved.
	var (
		held authz.Set
		err  error
	)
	if req.Network != nil {
		held, err = s.PermissionsInNetwork(ctx, *req.Network, req.Owner)
	} else {
		held, err = s.PermissionsInOrganization(ctx, req.Organization, req.Owner)
	}
	if err != nil {
		return MintedToken{}, err
	}
	for _, p := range req.Scope {
		if !held.Allows(authz.Permission(p)) {
			return MintedToken{}, invalid(
				"you do not hold %s here, so a token of yours could never use it", p)
		}
	}

	raw, err := secret.New(APITokenPrefix)
	if err != nil {
		return MintedToken{}, err
	}

	var out MintedToken
	err = s.InTx(ctx, func(q *dbgen.Queries) error {
		row, err := q.CreateAPIToken(ctx, dbgen.CreateAPITokenParams{
			TokenHash:      raw.Hash,
			UserID:         req.Owner,
			OrganizationID: req.Organization,
			Name:           name,
			Permissions:    req.Scope,
			NetworkID:      req.Network,
			ExpiresAt:      time.Now().UTC().Add(life),
		})
		if IsUniqueViolation(err) {
			return fmt.Errorf("%w: %q", ErrTokenNameTaken, name)
		}
		if err != nil {
			return fmt.Errorf("store: minting the token: %w", err)
		}

		metadata, _ := json.Marshal(map[string]any{
			"name":        row.Name,
			"permissions": req.Scope,
			"network_id":  networkLabel(req.Network),
			"expires_at":  row.ExpiresAt.UTC(),
		})
		if err := WriteAudit(ctx, q, req.Actor, dbgen.CreateAuditEventParams{
			OrganizationID: &req.Organization,
			NetworkID:      req.Network,
			Action:         "api_token.minted",
			ResourceKind:   "api_token",
			ResourceID:     &row.ID,
			SourceIp:       req.SourceIP,
			Metadata:       metadata,
		}); err != nil {
			return err
		}

		out = MintedToken{
			APIToken: APIToken{
				ID: row.ID, Name: row.Name, OrganizationID: row.OrganizationID,
				Owner: row.UserID, Scope: row.Permissions, Network: row.NetworkID,
				ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
			},
			Plaintext: raw.Plaintext,
		}
		return nil
	})
	if err != nil {
		return MintedToken{}, err
	}
	return out, nil
}

// FindToken resolves a presented token, or says it is not one.
//
// Expired, revoked, and belonging to a suspended or deleted account all read the same as
// "not recognised": a machine presenting a dead credential learns that it is dead and
// nothing more, and every one of those needs the same thing done about it.
func (s *Store) FindToken(ctx context.Context, presented string) (APIToken, error) {
	hash, err := secret.Hash(APITokenPrefix, presented)
	if err != nil {
		// Malformed, so no lookup happens at all. An endpoint hammered with rubbish costs
		// a parse rather than a query.
		return APIToken{}, fmt.Errorf("%w: %w", ErrNoSuchToken, err)
	}

	row, err := s.Queries().GetAPITokenByHash(ctx, hash)
	if IsNotFound(err) {
		return APIToken{}, ErrNoSuchToken
	}
	if err != nil {
		return APIToken{}, fmt.Errorf("store: reading the API token: %w", err)
	}

	token := APIToken{
		ID: row.ID, Name: row.Name, OrganizationID: row.OrganizationID,
		Owner: row.UserID, OwnerEmail: row.OwnerEmail,
		Scope: row.Permissions, Network: row.NetworkID,
		LastUsedAt: row.LastUsedAt, ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
	}

	// Decided here rather than left to the UPDATE's own WHERE clause, so the common case
	// costs no round trip at all. The clause is still there, so two requests that both
	// decide to write cannot both do it.
	if token.LastUsedAt == nil || time.Now().UTC().Sub(*token.LastUsedAt) > tokenTouchInterval {
		if _, err := s.Queries().TouchAPIToken(ctx, dbgen.TouchAPITokenParams{
			ID: row.ID, Stale: touchInterval(),
		}); err != nil {
			// Logged by the caller's error path would be wrong: the token is valid and the
			// request should proceed. Failing to record that a credential was used is not a
			// reason to refuse the work it was presented for.
			s.log.Warn("could not record that an API token was used", "error", err)
		}
	}
	return token, nil
}

// TokenPermissions is what a token may do in one network, or across its organisation when
// networkID is nil.
//
// The owner's *current* permissions, intersected with the token's scope. Evaluated here at
// every use rather than stored at creation, which is the whole design: a token whose
// permissions were frozen when it was minted would keep working after its owner was demoted,
// and that is precisely what the intersection exists to prevent.
//
// A token can therefore only ever lose power, never gain it — including when its owner gains
// some, because the scope does not widen to meet them.
func (s *Store) TokenPermissions(ctx context.Context, token APIToken, networkID *uuid.UUID) (authz.Set, error) {
	// A token narrowed to one network reaches that network and nothing else. Asked about
	// any other, or about the organisation as a whole, it holds nothing.
	if token.Network != nil {
		if networkID == nil || *networkID != *token.Network {
			return authz.NewSet(nil), nil
		}
	}

	var (
		owner authz.Set
		err   error
	)
	if networkID != nil {
		owner, err = s.PermissionsInNetwork(ctx, *networkID, token.Owner)
	} else {
		owner, err = s.PermissionsInOrganization(ctx, token.OrganizationID, token.Owner)
	}
	if err != nil {
		return authz.Set{}, err
	}

	allowed := make([]string, 0, len(token.Scope))
	for _, p := range token.Scope {
		if owner.Allows(authz.Permission(p)) {
			allowed = append(allowed, p)
		}
	}
	return authz.NewSet(allowed), nil
}

// ListTokensForUser is somebody's own tokens.
func (s *Store) ListTokensForUser(ctx context.Context, userID uuid.UUID) ([]APIToken, error) {
	rows, err := s.Queries().ListAPITokensForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("store: listing API tokens: %w", err)
	}
	out := make([]APIToken, 0, len(rows))
	for _, row := range rows {
		out = append(out, APIToken{
			ID: row.ID, Name: row.Name, OrganizationID: row.OrganizationID,
			Owner: row.UserID, Scope: row.Permissions, Network: row.NetworkID,
			LastUsedAt: row.LastUsedAt, ExpiresAt: row.ExpiresAt,
			CreatedAt: row.CreatedAt, RevokedAt: row.RevokedAt,
		})
	}
	return out, nil
}

// ListTokensForOrganization is every token in an organisation, with whose it is.
func (s *Store) ListTokensForOrganization(ctx context.Context, orgID uuid.UUID) ([]APIToken, error) {
	rows, err := s.Queries().ListAPITokensForOrganization(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("store: listing API tokens: %w", err)
	}
	out := make([]APIToken, 0, len(rows))
	for _, row := range rows {
		out = append(out, APIToken{
			ID: row.ID, Name: row.Name, OrganizationID: row.OrganizationID,
			Owner: row.UserID, OwnerEmail: row.OwnerEmail,
			Scope: row.Permissions, Network: row.NetworkID,
			LastUsedAt: row.LastUsedAt, ExpiresAt: row.ExpiresAt,
			CreatedAt: row.CreatedAt, RevokedAt: row.RevokedAt,
		})
	}
	return out, nil
}

// RevokeTokenRequest withdraws a credential.
type RevokeTokenRequest struct {
	Organization uuid.UUID
	Token        uuid.UUID

	// Owner, when set, restricts this to that person's own tokens. What the /me routes
	// pass, so somebody pruning their own list cannot reach a colleague's by id.
	Owner *uuid.UUID

	Actor    Actor
	SourceIP *netip.Addr
}

// RevokeToken withdraws a credential, and records who withdrew it.
//
// Revoking an already-revoked token is not an error: somebody making sure a credential is
// dead has got what they asked for, and the second attempt writes no second audit event.
func (s *Store) RevokeToken(ctx context.Context, req RevokeTokenRequest) error {
	return s.InTx(ctx, func(q *dbgen.Queries) error {
		token, err := q.GetAPITokenForOrganization(ctx, dbgen.GetAPITokenForOrganizationParams{
			ID: req.Token, OrganizationID: req.Organization,
		})
		if IsNotFound(err) {
			return fmt.Errorf("%w: %s", ErrNoSuchToken, req.Token)
		}
		if err != nil {
			return fmt.Errorf("store: reading the API token: %w", err)
		}
		if req.Owner != nil && token.UserID != *req.Owner {
			// Not found rather than forbidden. Somebody pruning their own tokens has no
			// business learning that an id they guessed belongs to a colleague.
			return fmt.Errorf("%w: %s", ErrNoSuchToken, req.Token)
		}
		if token.RevokedAt != nil {
			return nil
		}

		if _, err := q.RevokeAPIToken(ctx, dbgen.RevokeAPITokenParams{
			ID: req.Token, OrganizationID: req.Organization,
		}); err != nil {
			return fmt.Errorf("store: revoking the API token: %w", err)
		}

		metadata, _ := json.Marshal(map[string]any{
			"name":  token.Name,
			"owner": token.OwnerEmail,
		})
		return WriteAudit(ctx, q, req.Actor, dbgen.CreateAuditEventParams{
			OrganizationID: &req.Organization,
			NetworkID:      token.NetworkID,
			Action:         "api_token.revoked",
			ResourceKind:   "api_token",
			ResourceID:     &req.Token,
			SourceIp:       req.SourceIP,
			Metadata:       metadata,
		})
	})
}

// touchInterval is tokenTouchInterval as PostgreSQL wants it.
func touchInterval() pgtype.Interval {
	return pgtype.Interval{Microseconds: tokenTouchInterval.Microseconds(), Valid: true}
}
