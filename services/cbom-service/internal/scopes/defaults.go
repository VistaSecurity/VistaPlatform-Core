package scopes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// DefaultScopeName is a logical identifier for the three system-seeded scopes.
type DefaultScopeName string

const (
	DefaultAll        DefaultScopeName = "All"
	DefaultProduction DefaultScopeName = "Production"
	DefaultNonDevTest DefaultScopeName = "Non-Dev/Test"
)

// systemDefaults returns the three default Scope definitions. Predicates align
// with the user's clarification: Production = environment in (prod, production);
// Non-Dev/Test = exclude env in (dev/test/etc) OR tag-any-of (dev, test).
//
// `seededBy` is recorded as both created_by and updated_by — typically the
// platform's system user UUID, or the first user to hit cbom-service.
func systemDefaults(tenantID, seededBy uuid.UUID) []Scope {
	return []Scope{
		{
			TenantID:    tenantID,
			Name:        string(DefaultAll),
			Description: "Every asset in the tenant. Default CBOM scope when no narrower boundary is required.",
			Predicate:   Predicate{}, // empty = match everything under RLS
			IsDefault:   true,
			IsSystem:    true,
			CreatedBy:   seededBy,
			UpdatedBy:   seededBy,
		},
		{
			TenantID:    tenantID,
			Name:        string(DefaultProduction),
			Description: "Production-environment assets only. Use this scope for audit-grade CBOM artifacts.",
			Predicate: Predicate{
				Include: &PredicateClause{
					Environment: []string{"production", "prod"},
				},
			},
			IsDefault: false,
			IsSystem:  true,
			CreatedBy: seededBy,
			UpdatedBy: seededBy,
		},
		{
			TenantID:    tenantID,
			Name:        string(DefaultNonDevTest),
			Description: "Everything except dev/test environments. Excludes by env column AND by 'dev'/'test' tag.",
			Predicate: Predicate{
				Exclude: &PredicateClause{
					Environment: []string{"dev", "development", "test", "testing"},
					TagsAnyOf:   []string{"dev", "test"},
				},
			},
			IsDefault: false,
			IsSystem:  true,
			CreatedBy: seededBy,
			UpdatedBy: seededBy,
		},
	}
}

// SeedDefaultsIfMissing inserts the three default scopes for `tenantID` iff no
// scopes exist yet for that tenant. Called lazily on the first cbom-service
// request for a tenant (so the bootstrap stays decoupled from auth-service's
// tenant-create event).
//
// Returns (true, nil) if seeding occurred, (false, nil) if scopes already
// existed.
//
// Race-safe by outcome, not by exclusion. Counting first narrows the window but
// does not close it: two first requests for the same tenant can both read zero
// and both insert, and the loser used to surface a duplicate-key error as a 500
// on what is a perfectly ordinary first page load. The (tenant_id, name) UNIQUE
// constraint is the real arbiter — when it fires, the scope we wanted exists,
// which is the state the caller asked for, so it is success.
func (r *Repository) SeedDefaultsIfMissing(ctx context.Context, tenantID, seededBy uuid.UUID) (bool, error) {
	existing, err := r.CountForTenant(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("seed defaults: count: %w", err)
	}
	if existing > 0 {
		return false, nil
	}
	seeded := false
	for _, s := range systemDefaults(tenantID, seededBy) {
		scope := s
		switch err := r.Create(ctx, &scope); {
		case err == nil:
			seeded = true
		case IsDuplicateScope(err):
			// Another request seeded this one between our count and our insert.
		default:
			return false, fmt.Errorf("seed defaults: create %q: %w", scope.Name, err)
		}
	}
	return seeded, nil
}

// IsDuplicateScope reports whether err is a unique-constraint violation, i.e.
// the row we tried to create already exists.
func IsDuplicateScope(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == uniqueViolationCode
	}
	// Drivers other than lib/pq (and the sqlmock used in tests) surface the same
	// condition as text; matching on the SQLSTATE keeps this honest without
	// pinning a driver.
	return strings.Contains(err.Error(), uniqueViolationCode)
}

// uniqueViolationCode is SQLSTATE 23505.
const uniqueViolationCode = "23505"
