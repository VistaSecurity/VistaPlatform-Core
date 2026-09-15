package ast

import "strings"

// Namespace is the prefix a field path carries (§4.2). A bare name resolves
// only against the target's first-class columns, so a class attribute can never
// shadow a column.
type Namespace string

const (
	// NamespaceNone is a first-class column of the target.
	NamespaceNone Namespace = ""
	// NamespaceAttr is `attr.` — a class attribute in the `attributes` jsonb.
	NamespaceAttr Namespace = "attr"
	// NamespaceFact is `fact.` — a registered key in `asset_facts`.
	NamespaceFact Namespace = "fact"
	// NamespaceID is `id.` — an identifier kind in `asset_identifiers`.
	NamespaceID Namespace = "id"
	// NamespaceTag is `tag.` — a tenant tag key in the `tags` jsonb.
	NamespaceTag Namespace = "tag"
)

// Namespaces lists the four prefixes, for suggestions and docs.
var Namespaces = []Namespace{NamespaceAttr, NamespaceFact, NamespaceID, NamespaceTag}

// IsNamespace reports whether s names one of the four prefixes.
func IsNamespace(s string) (Namespace, bool) {
	switch Namespace(strings.ToLower(s)) {
	case NamespaceAttr:
		return NamespaceAttr, true
	case NamespaceFact:
		return NamespaceFact, true
	case NamespaceID:
		return NamespaceID, true
	case NamespaceTag:
		return NamespaceTag, true
	}
	return NamespaceNone, false
}

// FieldType is the declared type of a field. It decides which operators are
// legal (§4.4) and which SQL shape the translator emits (§7.2).
type FieldType string

const (
	// TypeKeyword is an exact-match string column.
	TypeKeyword FieldType = "keyword"
	// TypeText is a free-form string column; ":" means substring.
	TypeText FieldType = "text"
	// TypeNumber is numeric.
	TypeNumber FieldType = "number"
	// TypeTimestamp is a point in time.
	TypeTimestamp FieldType = "timestamp"
	// TypeBoolean is true/false.
	TypeBoolean FieldType = "boolean"
	// TypeInet is an address or network; ":" means CIDR containment.
	TypeInet FieldType = "inet"
	// TypeClass is the hierarchical class key; ":" means subtree.
	TypeClass FieldType = "class"
	// TypeBand is a risk/severity band, ordered through the supplied ladder.
	TypeBand FieldType = "band"
	// TypeVersion compares on a normalised component-wise sort key.
	TypeVersion FieldType = "version"
	// TypeUUID is a uuid column.
	TypeUUID FieldType = "uuid"
	// TypeKeywordArray is a text[] column; ":" means array-contains.
	TypeKeywordArray FieldType = "keyword[]"
	// TypeJSON is a jsonb value that is not a scalar — an array or an object
	// inside `attributes` or `asset_facts.value`. It is §4.4's json row taken
	// at its word: `exists` and nothing else.
	//
	// It exists because the alternative shapes are both wrong. A jsonb
	// accessor yields the value's raw TEXT (`->>`, `#>> '{}'`), so typing a
	// JSON array as keyword[] generates `unnest(text)` and `array_length(text)`
	// — a runtime error from the database, not a wrong answer but not an
	// answer either. Typing it as text instead makes `:` a substring over the
	// JSON source, where `vlans:10` matches the stored `[100]`. Refusing the
	// comparison and keeping the presence test is the same choice the language
	// already makes for a band with no ladder: refused, not guessed.
	TypeJSON FieldType = "json"
	// TypeUnresolved is the zero value, before the validator resolves a field.
	TypeUnresolved FieldType = ""
)

// AccessorKind picks the SQL shape a resolved field uses. Every accessor is
// built by the catalogue, never from user text, which is what keeps a
// user-supplied identifier out of SQL (§7.1).
type AccessorKind string

const (
	// AccessorColumn is a plain column of the shape's relation.
	AccessorColumn AccessorKind = "column"
	// AccessorJSONB is a key inside a jsonb column (`attributes`, `tags`). The
	// key is bound as a parameter, not interpolated.
	AccessorJSONB AccessorKind = "jsonb"
	// AccessorFact is a key in asset_facts, reached by an EXISTS.
	AccessorFact AccessorKind = "fact"
	// AccessorIdentifier is a kind in asset_identifiers, reached by an EXISTS.
	AccessorIdentifier AccessorKind = "identifier"
	// AccessorTagAny is the bare `tag` field: any tag key or value.
	AccessorTagAny AccessorKind = "tag_any"
	// AccessorIdentifierAny is the bare `id` field: any identifier value.
	AccessorIdentifierAny AccessorKind = "identifier_any"
	// AccessorDerived names a whitelisted derived-field builder in the
	// translator (§8's `strength` and `algorithm.deprecated`).
	AccessorDerived AccessorKind = "derived"
)

// Accessor says how the translator reaches a field's value. Column, JSONColumn
// and Derived are code-supplied strings from the generated catalogue; Key holds
// user text and is always bound as a parameter.
type Accessor struct {
	Kind AccessorKind
	// Rel names the logical relation inside the SQL shape that owns the
	// column ("self" unless a shape joins more than one table, e.g. "product"
	// for software_products inside `software:(…)`).
	Rel string
	// Column is the physical column name.
	Column string
	// JSONColumn is the jsonb column for AccessorJSONB.
	JSONColumn string
	// Key is the jsonb key, fact key or identifier kind. User text: bound.
	Key string
	// Derived names the translator's builder for AccessorDerived.
	Derived string
	// Cast is an optional SQL cast applied to the column expression, for enum
	// columns that must be compared as text.
	Cast string
	// PathColumn is the materialised class-path column of a TypeClass field.
	// Column holds the exact key column, PathColumn the subtree one (§5.3).
	PathColumn string
	// LabelColumn is the stored band label of a TypeBand field, when the row
	// carries one (findings do; assets score without a label). Equality uses
	// the label where it exists; ordering always goes through the ladder and
	// the numeric column.
	LabelColumn string
	// SortColumn is the normalised component-wise sort key of a TypeVersion
	// field. A version field without one is untranslatable, because a lexical
	// fallback is forbidden (§5.5).
	SortColumn string
	// AssessedBy is the column proving a band field was assessed at all. Only
	// a band field with one set accepts the `not_assessed` value (§5.2).
	AssessedBy string
}

// FieldRef is a field as it appears in the AST. The parser fills Segments,
// Text and Sp; the validator fills the rest by resolving against the catalogue.
// Only a resolved FieldRef may reach the translator.
type FieldRef struct {
	// Segments are the path segments as written, with unquoted segments
	// lowercased and quoted segments kept verbatim.
	Segments []string
	// Quoted marks which segments were written as quoted strings.
	Quoted []bool
	// Text is the canonical rendering of the path.
	Text string
	// Namespace is the resolved prefix.
	Namespace Namespace
	// Key is the resolved key within the namespace (the field name for
	// first-class columns, the dotted remainder for attr/fact/id/tag).
	Key string
	// Type is the resolved field type.
	Type FieldType
	// Accessor is the resolved SQL accessor.
	Accessor Accessor
	// Enum, when non-empty, is the closed value set the validator checks
	// against (§6 unknown_value).
	Enum []string
	// Resolved reports whether the validator has resolved this reference. The
	// translator refuses an unresolved field, fail-closed.
	Resolved bool
	Sp       Span
}

// String returns the canonical field text.
func (f FieldRef) String() string { return f.Text }
