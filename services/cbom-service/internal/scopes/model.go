// Package scopes models the Scope first-class object: a named, versioned,
// tenant-owned predicate definition that selects a subset of inventory.
// A Scope is the boundary a CBOM Artifact is generated against — "everything
// matching this Scope at this point in time becomes the CBOM."
//
// See docsv4/internal/developer/architecture/cbom/scope-predicate-shape.md
// for the full design rationale.
package scopes

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
)

// Scope is a tenant-owned predicate definition selecting a subset of inventory.
//
// `is_system` scopes (All / Production / Non-Dev-Test) are auto-seeded on first
// cbom-service contact for a tenant. Tenants can edit system scopes (predicates
// and names are not locked) but cannot delete them — deletion would orphan
// existing CBOM artifacts that reference the scope by id.
type Scope struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description,omitempty" db:"description"`
	// Query is the boundary, as a query-language string over the `asset`
	// target (QUERY_LANGUAGE.md). Empty matches every asset under RLS, which
	// is what the `All` scope is.
	//
	// It replaced a jsonb include/exclude predicate whose vocabulary was a
	// third of the language's and which only cbom-service could evaluate —
	// so a scope meant one thing to the artifact builder and nothing at all
	// to the inventory page beside it. Stored in CANONICAL form: an artifact
	// captures scope_id + scope_version, and two spellings of one predicate
	// are two versions a diff cannot match.
	Query     string     `json:"query" db:"query"`
	Version   int        `json:"version" db:"version"`
	IsDefault bool       `json:"is_default" db:"is_default"`
	IsSystem  bool       `json:"is_system" db:"is_system"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	CreatedBy uuid.UUID  `json:"created_by" db:"created_by"`
	UpdatedBy uuid.UUID  `json:"updated_by" db:"updated_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// CreateRequest is the JSON body for POST /scopes.
type CreateRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description,omitempty"`
	Query       string `json:"query"`
}

// UpdateRequest is the JSON body for PUT /scopes/:id. Query and Name are the
// meaningful editable fields; updating either bumps version and writes an
// audit row.
type UpdateRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description,omitempty"`
	Query       string `json:"query"`
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

// AssetTarget is the query-language target a scope is a predicate over: a scope
// selects ASSETS, and the artifact is assembled from what those assets carry.
const AssetTarget = "asset"

// scopeCatalog is the production query catalogue, built once.
//
// It takes the default band ladder rather than models.RiskBands. That is a
// stated compromise, not an oversight: cbom-service cannot import
// inventory-service's models package, and the two ladders are pinned equal by
// services/inventory-service/internal/services/query_registry_catalog_test.go.
// A scope writing `risk >= high` is therefore validated against the same rungs
// the inventory list bands with — and if that parity test ever fails, this is
// one of the places it is protecting.
var scopeCatalog = sync.OnceValue(func() *registrycatalog.Catalog {
	return query.DefaultCatalog()
})

// ValidateQuery checks a scope's query and returns its canonical form, which is
// what gets stored.
//
// Validation happens at WRITE time. A scope is an attestation boundary: a
// predicate that fails when the artifact is generated would either abort a
// generation the customer expected, or — far worse, and the failure this
// replaces — be partly ignored and produce evidence covering MORE than the
// scope said it did.
func ValidateQuery(src string) (string, error) {
	if strings.TrimSpace(src) == "" {
		// The `All` scope. Empty is every asset the tenant may see under RLS.
		return "", nil
	}
	cat := scopeCatalog()
	node, err := query.Check(src, AssetTarget, cat, query.DefaultOptionsFor(cat).Validate)
	if err != nil {
		if list := query.Errors(err); list != nil {
			return "", &InvalidQueryError{Query: src, Errors: list.Sorted()}
		}
		return "", fmt.Errorf("scope query: %w", err)
	}
	return query.FormatNode(node), nil
}

// InvalidQueryError carries QUERY_LANGUAGE §10's structured diagnostics up to
// the HTTP layer, so a scope editor can render a caret under the offending span
// instead of a sentence.
//
// It exists because `query.Errors` reads the error by TYPE ASSERTION, not
// errors.As — so wrapping the list in `fmt.Errorf("scope query: %w", …)` made
// the diagnostics unreachable and every scope write answered with one flattened
// string. Scopes get the same treatment as the inventory list for the same
// reason: the caller is a person typing a predicate, and "invalid query" is
// what the absence of a span looks like from the outside.
type InvalidQueryError struct {
	// Query is the text that failed, echoed back so a caller rendering carets
	// has the string the spans index into.
	Query string
	// Errors are every diagnostic, sorted by span.
	Errors queryerr.List
}

func (e *InvalidQueryError) Error() string {
	if len(e.Errors) == 0 {
		return "scope query is invalid"
	}
	return "scope query: " + e.Errors.Error()
}

// AsInvalidQuery returns the structured diagnostics behind err, if it has any.
// It uses errors.As, so it still finds them through a wrap.
func AsInvalidQuery(err error) (*InvalidQueryError, bool) {
	var qe *InvalidQueryError
	if errors.As(err, &qe) {
		return qe, true
	}
	return nil, false
}
