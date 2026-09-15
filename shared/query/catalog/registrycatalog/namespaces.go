package registrycatalog

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
)

// The four namespaces of §4.2, derived from the generated registries.
//
// Nothing here is a list. `attr.` is every attribute every class declares in
// standards/asset-classes.yaml, `fact.` every key in standards/fact-keys.yaml,
// `id.` the identifier kinds of ADR-0002 D3 — all read out of the generated Go
// mirrors, so adding a key to a YAML file and running `make generate` adds it
// to the query language with no edit here. `tag.` is open by design: tags are
// tenant text.

// ------------------------------------------------------------ type mapping --

// registryType maps a registry-declared value type onto a query field type.
// It is the one rule both namespaces use, and it is deliberately short:
//
//	string            → keyword   (a registry value is a token, not prose)
//	integer / number  → number
//	boolean           → boolean
//	date              → timestamp
//	array / object    → json      (presence only — see ast.TypeJSON)
//	anything else     → not published
//
// Two of those rows are the ones worth arguing about.
//
// **string → keyword, not text.** `:` on keyword is case-insensitive equality;
// on text it is substring. Every string in these registries is a short
// structured value a collector wrote — a region, a model, an image id, an OS
// name — and a facet chip built from `attr.provider` has to mean equality or it
// is not a facet. A registry that ever declares genuinely prose-shaped text
// needs a signal in the YAML saying so; guessing from the attribute's NAME
// would be exactly the kind of second opinion this catalogue exists to remove.
// `~ "regex"` and `attr.model:Cat*` both remain available for partial matching.
//
// **array/object → json, not keyword[].** The accessor for a jsonb value yields
// its raw TEXT (`attributes ->> 'k'`, `value #>> '{}'`), so keyword[] would
// generate `unnest(text)` and `array_length(text)` — errors from Postgres, not
// answers. keyword[] is for a real `text[]` COLUMN (assets.risk_assessed_by,
// asset_endpoints.sni), and those are first-class fields, not registry keys.
func registryType(declared string) (ast.FieldType, bool) {
	switch declared {
	case "string":
		return ast.TypeKeyword, true
	case "integer", "number":
		return ast.TypeNumber, true
	case "boolean":
		return ast.TypeBoolean, true
	case "date":
		return ast.TypeTimestamp, true
	case "array", "object":
		return ast.TypeJSON, true
	default:
		// An unpublishable type is left out of the vocabulary entirely, so the
		// key reports unknown_key rather than acquiring a type by default.
		return ast.TypeUnresolved, false
	}
}

const (
	attributesColumn = "attributes"
	tagsColumn       = "tags"
	factValueColumn  = "value"
)

// ------------------------------------------------------------- attributes --

// attrFields is every class attribute in the registry, keyed by lowercased
// name. Built once: the generated schemas are immutable for the life of the
// process.
var attrFields = sync.OnceValue(func() map[string]catalog.FieldInfo {
	schemas := make(map[string]map[string]assetclass.AttributeProperty, len(assetclass.All))
	for _, c := range assetclass.All {
		props, ok := assetclass.Attributes(c.Key)
		if !ok {
			continue
		}
		schemas[c.Key] = props
	}
	return buildAttributeFields(assetclass.All, schemas)
})

// buildAttributeFields folds every class's effective attribute schema into one
// `attr.` namespace. §4.2 makes the namespace flat and global — `attr.model` is
// one field, not one per class — because a query is a predicate over `assets`,
// whose `attributes` jsonb holds whichever class's keys the row carries, and
// a per-class vocabulary would make `class:hardware and attr.model:X` legal
// while `attr.model:X` alone was not.
//
// It takes its inputs rather than reading the package registry so a conflict
// can be exercised in a test. A conflict PANICS: two classes declaring one
// attribute name with two types is a registry bug that `make generate` should
// never emit and `make audit` would catch, and there is no correct runtime
// behaviour — typing one class's data by another class's schema is the silent
// wrong answer, and dropping the attribute is a vocabulary that changes shape
// depending on a YAML edit nobody reviewed.
func buildAttributeFields(classes []assetclass.Class,
	schemas map[string]map[string]assetclass.AttributeProperty,
) map[string]catalog.FieldInfo {
	out := make(map[string]catalog.FieldInfo)
	// owner and descriptions track where a name came from, for the panic
	// message and for the "describe it only if everyone agrees" rule below.
	owner := make(map[string]string)
	agreed := make(map[string]bool)

	for _, c := range classes {
		props := schemas[c.Key]
		names := make([]string, 0, len(props))
		for name := range props {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			p := props[name]
			key := strings.ToLower(name)
			typ, ok := registryType(p.Type)
			if !ok {
				continue
			}
			f := catalog.FieldInfo{
				Name:        attrName(key),
				Type:        typ,
				Enum:        p.Enum,
				Description: p.Description,
				Accessor: ast.Accessor{
					Kind: ast.AccessorJSONB, JSONColumn: attributesColumn, Key: key,
				},
			}
			prev, seen := out[key]
			if !seen {
				out[key] = f
				owner[key] = c.Key
				agreed[key] = true
				continue
			}
			if prev.Type != f.Type || !sameValues(prev.Enum, f.Enum) {
				panic(fmt.Sprintf(
					"query/catalog/registrycatalog: class attribute %q is declared as %s%s by %q "+
						"and as %s%s by %q; one name cannot be two fields",
					key, prev.Type, enumSuffix(prev.Enum), owner[key],
					f.Type, enumSuffix(f.Enum), c.Key))
			}
			if prev.Description != f.Description {
				// Several classes declare the attribute and describe it
				// differently. Showing one class's wording as if it were the
				// field's would be a small lie in a tooltip; showing none is
				// not.
				agreed[key] = false
			}
		}
	}
	for key, ok := range agreed {
		if ok {
			continue
		}
		f := out[key]
		f.Description = ""
		out[key] = f
	}
	return out
}

func attrName(key string) string { return string(ast.NamespaceAttr) + "." + key }

func enumSuffix(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return " (" + strings.Join(values, "|") + ")"
}

func sameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------ facts --

// factFields is every registered fact key, keyed by lowercased key.
var factFields = sync.OnceValue(func() map[string]catalog.FieldInfo {
	out := make(map[string]catalog.FieldInfo, len(facts.All))
	for _, k := range facts.All {
		typ, ok := registryType(k.Type)
		if !ok {
			continue
		}
		key := strings.ToLower(k.Key)
		out[key] = catalog.FieldInfo{
			Name:        factName(key),
			Type:        typ,
			Enum:        k.Enum,
			Description: k.Description,
			Accessor: ast.Accessor{
				Kind: ast.AccessorFact, Column: factValueColumn, Key: key,
			},
		}
	}
	return out
})

func factName(key string) string { return string(ast.NamespaceFact) + "." + key }

// ------------------------------------------------------------ identifiers --

// IdentifierAnyKind is the pseudo-kind matching an identifier of ANY kind
// (§13 A1). It cannot collide with a real kind: the registry's kinds come from
// shared/assetclass and "any" is not one of them, which
// TestIdentifierAnyIsNotARealKind pins.
const IdentifierAnyKind = "any"

// identifierAliases maps a written kind to the STORED one. §12 amendment 4:
// the §3 cheat sheet writes `id.mac`, ADR-0002 D3 names the kind
// `mac_address`, and both resolve — but only `mac_address` ever reaches the
// column, because that is what is in it.
var identifierAliases = map[string]string{"mac": "mac_address"}

// storedIdentifierKinds is the registry's kinds, WITHOUT the aliases. It is
// what the `identifier` target's `kind` column may hold.
func storedIdentifierKinds() []string {
	out := make([]string, len(assetclass.IdentifierKinds))
	copy(out, assetclass.IdentifierKinds)
	return out
}

// writableIdentifierKinds is every spelling `id.<kind>` accepts: the registry's
// kinds plus the aliases. Sorted, so Fields is deterministic.
func writableIdentifierKinds() []string {
	out := storedIdentifierKinds()
	for alias := range identifierAliases {
		out = append(out, alias)
	}
	sort.Strings(out)
	return out
}

func identifierField(kind string) catalog.FieldInfo {
	stored := kind
	if alias, ok := identifierAliases[kind]; ok {
		stored = alias
	}
	return catalog.FieldInfo{
		Name: string(ast.NamespaceID) + "." + kind,
		Type: ast.TypeKeyword,
		Accessor: ast.Accessor{
			Kind: ast.AccessorIdentifier, Column: "value", Key: stored,
		},
	}
}

func identifierAnyField() catalog.FieldInfo {
	return catalog.FieldInfo{
		Name: string(ast.NamespaceID) + "." + IdentifierAnyKind,
		Type: ast.TypeKeyword,
		Accessor: ast.Accessor{
			Kind: ast.AccessorIdentifierAny, Column: "value",
		},
		Description: "an identifier of any kind with this value (§13 A1)",
	}
}

// -------------------------------------------------------------------- tags --

func tagAnyField() catalog.FieldInfo {
	return catalog.FieldInfo{
		Name: string(ast.NamespaceTag), Type: ast.TypeText,
		Accessor:    ast.Accessor{Kind: ast.AccessorTagAny, JSONColumn: tagsColumn},
		Description: "any tag key or value",
	}
}

func tagField(key string) catalog.FieldInfo {
	return catalog.FieldInfo{
		Name: string(ast.NamespaceTag) + "." + key, Type: ast.TypeKeyword,
		Accessor: ast.Accessor{Kind: ast.AccessorJSONB, JSONColumn: tagsColumn, Key: key},
	}
}

// ------------------------------------------------------- per-target access --

// namespacesByTarget says which of the four namespaces resolve on a target
// (§4.2). Only an asset-shaped row carries class attributes, facts, identifiers
// and tags; a measurement predicate reads facts and nothing else (§8).
var namespacesByTarget = map[string][]ast.Namespace{
	"asset":       {ast.NamespaceAttr, ast.NamespaceFact, ast.NamespaceID, ast.NamespaceTag},
	"observation": {ast.NamespaceAttr, ast.NamespaceFact, ast.NamespaceID, ast.NamespaceTag},
	"measurement": {ast.NamespaceFact},
}

func namespaceAllowed(target string, ns ast.Namespace) bool {
	for _, n := range namespacesByTarget[target] {
		if n == ns {
			return true
		}
	}
	return false
}
