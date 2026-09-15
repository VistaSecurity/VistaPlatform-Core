// Package catalog is the seam between the query language and the schema.
//
// The parser knows the grammar; the validator and translator know nothing about
// fields except what a Catalog tells them. The production catalogue will read
// the generated registries (shared/assetclass from standards/asset-classes.yaml
// and shared/facts from standards/fact-keys.yaml) so the vocabulary cannot
// drift from the schema; the static one under testcatalog/ implements
// QUERY_LANGUAGE.md §4.3 directly and is what the conformance fixtures resolve
// against. Both satisfy this interface, and neither the parser, the validator
// nor the translator changes when one is swapped for the other.
package catalog

import (
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// Target is a collection a query can be a predicate over (§4.1), together with
// the physical shape the translator needs to build SQL for it.
type Target struct {
	// Name is the target's name in the language: asset, endpoint, …
	Name string
	// Table is the physical table.
	Table string
	// Alias is the code-supplied alias the translator gives it.
	Alias string
	// IDColumn is the primary key column.
	IDColumn string
	// AssetIDColumn is how a row reaches its owning asset, empty when the
	// target is the asset itself. Used by `asset:(…)` from a child target.
	AssetIDColumn string
	// Subs lists the sub-predicate collections reachable from this target. A
	// collection outside the list is untranslatable rather than silently
	// resolved against the wrong table.
	Subs []string
	// Traversable reports whether relationship traversal starts here. Edges
	// join assets, so only asset-shaped targets are traversable.
	Traversable bool
	// FreeTextable reports whether a term with no field has a meaning here.
	// §5.4 defines free text over an asset's display name, hostname,
	// identifier values and tags; a target without that column set rejects a
	// free-text term rather than silently searching something narrower.
	FreeTextable bool
	// InMemory marks a target that has no table: the `observation` target is
	// evaluated by the identification engine against an in-flight discovery,
	// so the SQL translator refuses it rather than inventing a table.
	InMemory bool
}

// FieldInfo is one entry of a target's field catalogue.
type FieldInfo struct {
	// Name is the field as a user writes it, including any namespace prefix.
	Name string
	// Type decides the legal operators and the SQL shape.
	Type ast.FieldType
	// Accessor is how the translator reaches the value.
	Accessor ast.Accessor
	// Enum, when set, is the closed value set the validator enforces.
	Enum []string
	// Description is autocomplete help text.
	Description string
}

// ClassInfo is a class key and its materialised path (§5.3).
type ClassInfo struct {
	Key  string
	Path string
}

// Catalog resolves field paths for a target and answers the closed-vocabulary
// questions the validator asks.
type Catalog interface {
	// Targets lists the query targets this catalogue knows.
	Targets() []Target
	// Fields lists a target's resolvable fields, for suggestions and
	// autocomplete. Namespaced entries appear under their prefixed name.
	Fields(target string) []FieldInfo
	// Resolve resolves a field path against a target. The returned FieldRef
	// carries Namespace, Key, Type and Accessor filled in.
	Resolve(target string, path []string) (ast.FieldRef, error)
	// RelationshipNames lists the twenty relationship spellings.
	RelationshipNames() []ast.Relationship
	// ClassExists resolves a class key to its path.
	ClassExists(key string) (ClassInfo, bool)
	// EnumValues returns the closed value set of a resolved field, if it has
	// one.
	EnumValues(field ast.FieldRef) ([]string, bool)
}

// ResolveReason says why a path did not resolve, so the validator can write the
// right message and suggestion.
type ResolveReason string

const (
	// ReasonUnknownTarget is a target the catalogue does not know.
	ReasonUnknownTarget ResolveReason = "unknown_target"
	// ReasonUnknownField is a bare path with no first-class field.
	ReasonUnknownField ResolveReason = "unknown_field"
	// ReasonUnknownKey is a namespaced path whose key is not registered.
	ReasonUnknownKey ResolveReason = "unknown_key"
	// ReasonEmptyKey is a namespace prefix with nothing after it.
	ReasonEmptyKey ResolveReason = "empty_key"
)

// ResolveError is the error Resolve returns. It is deliberately data, not
// prose: the validator owns the wording.
type ResolveError struct {
	Target    string
	Path      []string
	Namespace ast.Namespace
	Reason    ResolveReason
}

// Error implements the error interface.
func (e *ResolveError) Error() string {
	return fmt.Sprintf("%s: %q on target %q", e.Reason, strings.Join(e.Path, "."), e.Target)
}

// FindTarget returns the named target.
func FindTarget(c Catalog, name string) (Target, bool) {
	for _, t := range c.Targets() {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return Target{}, false
}

// TargetNames lists the catalogue's target names, for error messages.
func TargetNames(c Catalog) []string {
	targets := c.Targets()
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Name)
	}
	return out
}

// FieldNames lists a target's field names, for suggestions.
func FieldNames(c Catalog, target string) []string {
	fields := c.Fields(target)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.Name)
	}
	return out
}

// CollectionTarget maps a sub-predicate collection name (§3) to the target
// whose field catalogue its inner predicate resolves against.
var CollectionTarget = map[string]string{
	"endpoint":     "endpoint",
	"software":     "software_install",
	"finding":      "finding",
	"cert":         "certificate",
	"crypto":       "crypto_configuration",
	"identifier":   "identifier",
	"relationship": "relationship",
	"asset":        "asset",
}
