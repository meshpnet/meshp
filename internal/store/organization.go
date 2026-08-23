package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// ErrOrganizationExists means that slug is taken.
var ErrOrganizationExists = errors.New("store: an organisation with that name already exists")

// Organization is one tenant.
//
// Deliberately without `kind` or a parent. Those columns exist so the proprietary layer can
// build a hierarchy over this table without forking the schema (ADR-0009), and the open
// control plane treats organisations as flat — so surfacing them here would offer a
// structure nothing in this repository honours.
type Organization struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	CreatedAt time.Time

	// Networks is how many this organisation has. Zero is the shape of an organisation
	// somebody created and did not finish setting up.
	Networks int64
}

// CreateOrganization makes a tenant for networks to belong to.
//
// The first thing a deployment needs and the last thing to get an endpoint: the quickstart
// has been reaching into PostgreSQL for this since it was written, which means standing up
// meshp has required database access to a table nothing else asks anyone to touch.
func (s *Store) CreateOrganization(ctx context.Context, slug, name string) (Organization, error) {
	if err := validateSlug("organisation", slug); err != nil {
		return Organization{}, err
	}
	if name == "" {
		// Not defaulted to the slug. A display name and a URL-safe identifier are different
		// things, and quietly making one the other is how every organisation ends up called
		// "acme" in a list somebody has to read.
		return Organization{}, invalid("an organisation needs a name")
	}

	row, err := s.Queries().CreateOrganization(ctx, dbgen.CreateOrganizationParams{
		Slug: slug, Name: name,
	})
	if IsUniqueViolation(err) {
		return Organization{}, fmt.Errorf("%w: %q", ErrOrganizationExists, slug)
	}
	if err != nil {
		return Organization{}, fmt.Errorf("store: creating the organisation: %w", err)
	}
	return Organization{ID: row.ID, Slug: row.Slug, Name: row.Name, CreatedAt: row.CreatedAt}, nil
}

// ListOrganizations returns every tenant this control plane holds.
func (s *Store) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.Queries().ListOrganizations(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: listing organisations: %w", err)
	}
	out := make([]Organization, 0, len(rows))
	for _, row := range rows {
		out = append(out, Organization{
			ID: row.ID, Slug: row.Slug, Name: row.Name,
			CreatedAt: row.CreatedAt, Networks: row.NetworkCount,
		})
	}
	return out, nil
}
