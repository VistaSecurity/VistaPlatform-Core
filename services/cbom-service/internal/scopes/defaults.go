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

// systemDefaults returns the three default Scope definitions, as query strings.
//
// The translation from the jsonb shapes they used to carry is
// QUERY_LANGUAGE §8's, applied once here:
//
//	All          {}                                        → ""
//	Production   include.environment: [production, prod]    → environment:production
//	Non-Dev/Test exclude.environment + exclude.tags_any_of  → (not exists(environment) or not environment in (…)) and not (tag:dev or tag:test)
//
// `prod` is gone from Production, deliberately (§12 amendment 1): `environment`
// is the `environment_type` enum, which has no such member, so the old list's
// second value could never have matched a row. Writing it as a query makes that
// visible — the validator rejects it — where the jsonb form carried a dead
// value indefinitely.
//
// `seededBy` is recorded as both created_by and updated_by — typically the
// platform's system user UUID, or the first user to hit cbom-service.
func systemDefaults(tenantID, seededBy uuid.UUID) []Scope {
	return []Scope{
		{
			TenantID:    tenantID,
			Name:        string(DefaultAll),
			Description: "Every asset in the tenant. Default CBOM scope when no narrower boundary is required.",
			Query:       "", // empty = match everything under RLS
			IsDefault:   true,
			IsSystem:    true,
			CreatedBy:   seededBy,
			UpdatedBy:   seededBy,
		},
		{
			TenantID:    tenantID,
			Name:        string(DefaultProduction),
			Description: "Production-environment assets only. Use this scope for audit-grade CBOM artifacts.",
			Query:       "environment:production",
			IsDefault:   false,
			IsSystem:    true,
			CreatedBy:   seededBy,
			UpdatedBy:   seededBy,
		},
		{
			TenantID:    tenantID,
			Name:        string(DefaultNonDevTest),
			Description: "Everything except dev/test environments. Excludes by env column AND by 'dev'/'test' tag.",
			// Exclusion wins, and the two arms are AND-ed: an asset is in
			// scope only if its environment column is neither dev nor test AND
			// it carries neither tag. The tag arm is the key-or-value form
			// §5.4 defines, which is what tags_any_of meant.
			//
			// Written as `(tag:dev or tag:test)` rather than the shorter
			// `tag:(dev or test)` because that is the CANONICAL form: the
			// grouped-value sugar desugars to an Or of Compare nodes (§12), and
			// a seed stored in non-canonical text would fail its own
			// round-trip check and, worse, read as an edit the first time a
			// tenant saved it unchanged.
			//
			// # Why the environment arm names absence explicitly
			//
			// `not environment in (development, test)` alone would EXCLUDE every
			// asset whose environment is unset, because a comparison against an
			// absent value is UNKNOWN and so is its negation (§5.2) — and on a
			// discovered inventory that is most assets. The scope's name is a
			// promise about dev and test, not about the unmeasured, so turning
			// "nobody recorded an environment" into "assume it is dev" would
			// silently drop them out of a CBOM's attestation boundary. The
			// jsonb predicate this replaced kept them in, because its `inSet`
			// returned false for an unset value rather than unknown.
			//
			// `not exists(environment)` is the explicit way to say it, and it
			// has to be explicit: three-valued logic is right for a FILTER and
			// wrong for an EXCLUSION, and only the author of the predicate knows
			// which one they are writing. The tag arm needs no such clause — it
			// is a NOT EXISTS over the tag rows, which is already true for an
			// asset with no tags.
			Query:     "(not exists(environment) or not environment in (development, test)) and not (tag:dev or tag:test)",
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
