// Package scopes models the Scope first-class object: a named, versioned,
// tenant-owned predicate definition that selects a subset of inventory.
// A Scope is the boundary a CBOM Artifact is generated against — "everything
// matching this Scope at this point in time becomes the CBOM."
//
// See docsv4/internal/developer/architecture/cbom/scope-predicate-shape.md
// for the full design rationale.
package scopes

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Scope is a tenant-owned predicate definition selecting a subset of inventory.
//
// `is_system` scopes (All / Production / Non-Dev-Test) are auto-seeded on first
// cbom-service contact for a tenant. Tenants can edit system scopes (predicates
// and names are not locked) but cannot delete them — deletion would orphan
// existing CBOM artifacts that reference the scope by id.
type Scope struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description,omitempty" db:"description"`
	Predicate   Predicate  `json:"predicate" db:"predicate"`
	Version     int        `json:"version" db:"version"`
	IsDefault   bool       `json:"is_default" db:"is_default"`
	IsSystem    bool       `json:"is_system" db:"is_system"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	CreatedBy   uuid.UUID  `json:"created_by" db:"created_by"`
	UpdatedBy   uuid.UUID  `json:"updated_by" db:"updated_by"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// Predicate is the JSONB-stored selection rule. An empty Predicate (no Include
// and no Exclude) matches every asset visible to the tenant under RLS.
//
// Evaluation semantics:
//   - Include: asset must match EVERY populated Include field; within one
//     field's list the values are OR-ed. An empty Include matches everything.
//     (This comment used to say OR-across-fields, which no implementation has
//     ever done and which would make an Include of
//     {environment: [production], risk_level: [critical]} select every
//     production asset plus every critical asset anywhere — the opposite of the
//     narrowing a scope is for.)
//   - Exclude: asset matching ANY populated Exclude field is removed. Exclusion
//     wins over inclusion.
//
// Field shapes mirror inventory-service's AssetFilters
// (services/inventory-service/internal/models/asset.go). Evaluation happens in
// cbom-service: cbom.Builder translates a Predicate into handlers.AssetPredicate
// and the CBOM assembly applies it to the fetched asset records.
type Predicate struct {
	Include *PredicateClause `json:"include,omitempty"`
	Exclude *PredicateClause `json:"exclude,omitempty"`
}

// PredicateClause is a set of asset-attribute filters: OR within a field's
// list, AND across populated fields for Include, OR across populated fields for
// Exclude. The same shape is used for both clauses.
//
// Every field here must be wired into cbom.clauseTranslators. One that is not
// makes any scope using it fail generation with 422 rather than produce an
// artifact wider than its stated boundary.
type PredicateClause struct {
	Environment    []string `json:"environment,omitempty"`
	AssetType      []string `json:"asset_type,omitempty"`
	AssetOwnership []string `json:"asset_ownership,omitempty"`
	AssetStatus    []string `json:"asset_status,omitempty"`
	BusinessUnit   []string `json:"business_unit,omitempty"`
	LocationRegion []string `json:"location_region,omitempty"`
	RiskLevel      []string `json:"risk_level,omitempty"`
	// TagsAnyOf matches assets whose JSONB tags column contains ANY of the listed
	// tag values (case-insensitive). Used for the Non-Dev/Test default scope.
	TagsAnyOf []string `json:"tags_any_of,omitempty"`
}

// IsEmpty reports whether a predicate has no rules — matches everything.
func (p Predicate) IsEmpty() bool {
	return (p.Include == nil || p.Include.isEmpty()) &&
		(p.Exclude == nil || p.Exclude.isEmpty())
}

func (c *PredicateClause) isEmpty() bool {
	if c == nil {
		return true
	}
	return len(c.Environment) == 0 &&
		len(c.AssetType) == 0 &&
		len(c.AssetOwnership) == 0 &&
		len(c.AssetStatus) == 0 &&
		len(c.BusinessUnit) == 0 &&
		len(c.LocationRegion) == 0 &&
		len(c.RiskLevel) == 0 &&
		len(c.TagsAnyOf) == 0
}

// Value implements the database/sql/driver.Valuer interface, allowing the
// repository to write Predicate directly to a JSONB column.
//
// The return type must be exactly `driver.Value` — Go's interface satisfaction
// check matches signatures by named type, not by underlying type. An earlier
// version of this method used a local type alias `driverValue = interface{}`
// thinking it would still satisfy Valuer (since both resolve to interface{}),
// but at runtime the sql driver fails to detect the method and emits
// "unsupported type scopes.Predicate, a struct" on INSERT.
func (p Predicate) Value() (driver.Value, error) {
	return json.Marshal(p)
}

// Scan implements the database/sql.Scanner interface, allowing the repository
// to read Predicate from a JSONB column.
func (p *Predicate) Scan(src interface{}) error {
	if src == nil {
		*p = Predicate{}
		return nil
	}
	switch v := src.(type) {
	case []byte:
		return json.Unmarshal(v, p)
	case string:
		return json.Unmarshal([]byte(v), p)
	default:
		return fmt.Errorf("scopes.Predicate.Scan: unsupported type %T", src)
	}
}

// CreateRequest is the JSON body for POST /scopes.
type CreateRequest struct {
	Name        string    `json:"name" binding:"required"`
	Description string    `json:"description,omitempty"`
	Predicate   Predicate `json:"predicate"`
}

// UpdateRequest is the JSON body for PUT /scopes/:id. Predicate and Name are
// the meaningful editable fields; updating either bumps version and writes an
// audit row.
type UpdateRequest struct {
	Name        string    `json:"name" binding:"required"`
	Description string    `json:"description,omitempty"`
	Predicate   Predicate `json:"predicate"`
}

// ValidateName trims and lowercases-uniqueness is enforced by a DB constraint;
// here we only sanity-check the input.
func ValidateName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("scope name cannot be empty")
	}
	if len(trimmed) > 255 {
		return fmt.Errorf("scope name exceeds 255 characters")
	}
	return nil
}
