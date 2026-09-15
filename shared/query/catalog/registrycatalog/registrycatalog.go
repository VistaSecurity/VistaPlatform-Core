// Package registrycatalog is the production implementation of catalog.Catalog:
// the query language's vocabulary, assembled from the generated registries and
// the real schema rather than from a list somebody typed.
//
// Two halves, and the split is the point.
//
//	GENERATED  attr.<name>  every class attribute in standards/asset-classes.yaml
//	           fact.<key>   every key in standards/fact-keys.yaml
//	           id.<kind>    the identifier kinds of ADR-0002 D3
//	           class        the 49-node hierarchy, keys and materialised paths
//	           finding.*    producers, kinds and subject types from
//	                        standards/findings-registry.yaml
//	           relationship.type  the ten canonical types
//
//	HAND-WRITTEN  the first-class field table (fields.go) — a column name is not
//	              a field name, and nothing in the schema says which columns are
//	              queryable
//	              the closed value sets (enums.go) — every one of them pinned to
//	              scripts/database/schema.sql by TestEnumsMatchSchema
//
// Add a fact key to the YAML, run `make generate`, and `fact.<key>` is
// queryable with no edit here. That is the difference between this catalogue
// and catalog/testcatalog, which implements QUERY_LANGUAGE §4.3 statically and
// is what the conformance fixtures resolve against.
//
// Contract: docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md.
package registrycatalog

import (
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/ladder"
)

// Options configure the catalogue.
type Options struct {
	// Ladder is the risk/severity band ladder every band predicate is
	// generated from (§5.5). A SERVICE must pass models.RiskBands: it is the
	// one true ladder, and shared/ may not import it.
	//
	// Nil falls back to ladder.CVSS, the same five rungs written down once in
	// shared/ for callers with no service context. The fallback is a
	// convenience, not a second opinion — the two are pinned equal by
	// services/inventory-service/internal/services/query_registry_catalog_test.go.
	Ladder catalog.BandLadder
}

// Catalog is the registry-backed catalogue.
type Catalog struct {
	ladder catalog.BandLadder

	// fields is the published vocabulary per target: first-class fields plus
	// the namespaces that target allows, sorted by name, deduplicated.
	// Precomputed, so Fields is a copy rather than a rebuild and is identical
	// on every call.
	fields map[string][]catalog.FieldInfo

	// byName is the first-class lookup per target, keyed by lowercased field
	// name. Resolve walks a map, not the slice, so a long table costs nothing.
	byName map[string]map[string]catalog.FieldInfo
}

// New builds the catalogue.
//
// It is cheap enough to call per request (a few hundred map entries) and safe
// to share: nothing in the returned value is mutated after construction, and
// every accessor hands back a copy.
func New(opts Options) *Catalog {
	l := opts.Ladder
	if l == nil {
		l = ladder.CVSS
	}
	c := &Catalog{
		ladder: l,
		fields: make(map[string][]catalog.FieldInfo, len(targets)),
		byName: make(map[string]map[string]catalog.FieldInfo, len(targets)),
	}
	for _, t := range targets {
		base := firstClass[t.Name]

		lookup := make(map[string]catalog.FieldInfo, len(base))
		for _, f := range base {
			lookup[strings.ToLower(f.Name)] = f
		}
		c.byName[t.Name] = lookup

		c.fields[t.Name] = publishedFields(t.Name, base)
	}
	return c
}

// Ladder returns the band ladder the catalogue was built with, so a caller
// cannot hand the catalogue one ladder and the translator another. See
// query.DefaultOptionsFor.
func (c *Catalog) Ladder() catalog.BandLadder { return c.ladder }

// publishedFields assembles one target's whole vocabulary: its first-class
// fields plus every namespace it allows.
//
// Sorted by name and deduplicated, because both properties are load-bearing
// rather than tidy. Deterministic order is what makes autocomplete and the
// "did you mean" suggestion stable between two processes reading the same
// registries. And §13 A1 forbids publishing one name twice: a catalogue that
// did made autocomplete and the suggester both wrong about which field a user
// would get.
func publishedFields(target string, base []catalog.FieldInfo) []catalog.FieldInfo {
	out := make([]catalog.FieldInfo, 0, len(base)+64)
	out = append(out, base...)

	if namespaceAllowed(target, ast.NamespaceAttr) {
		out = append(out, sortedByName(attrFields())...)
	}
	if namespaceAllowed(target, ast.NamespaceFact) {
		out = append(out, sortedByName(factFields())...)
	}
	if namespaceAllowed(target, ast.NamespaceID) {
		for _, kind := range writableIdentifierKinds() {
			out = append(out, identifierField(kind))
		}
		// The any-kind form is `id.any`, NOT a second entry named `id`: a bare
		// `id` is the row's uuid column (§13 A1).
		out = append(out, identifierAnyField())
	}
	if namespaceAllowed(target, ast.NamespaceTag) {
		// Only the bare `tag` is publishable. A tag KEY is tenant text with no
		// registry behind it, so there is no list of `tag.<key>` to offer —
		// they all resolve, and none can be enumerated.
		out = append(out, tagAnyField())
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return dedupe(out)
}

// dedupe drops a duplicate name rather than publishing it twice. It cannot
// happen today — TestNoDuplicateFieldNames pins that, and the namespaces are
// prefixed so a collision would have to be between two first-class entries —
// and it is here so that if it ever does, the catalogue publishes ONE field
// rather than two indistinguishable ones.
func dedupe(in []catalog.FieldInfo) []catalog.FieldInfo {
	out := in[:0]
	var last string
	for i, f := range in {
		if i > 0 && f.Name == last {
			continue
		}
		last = f.Name
		out = append(out, f)
	}
	return out
}

func sortedByName(m map[string]catalog.FieldInfo) []catalog.FieldInfo {
	out := make([]catalog.FieldInfo, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ------------------------------------------------------ catalog.Catalog --

// Targets implements catalog.Catalog.
func (c *Catalog) Targets() []catalog.Target { return AllTargets() }

// Fields implements catalog.Catalog. The slice is a copy of a precomputed,
// sorted, duplicate-free list.
func (c *Catalog) Fields(target string) []catalog.FieldInfo {
	src := c.fields[strings.ToLower(target)]
	out := make([]catalog.FieldInfo, len(src))
	copy(out, src)
	return out
}

// RelationshipNames implements catalog.Catalog.
//
// TODO: switch to shared/relationships when it lands. ast.Relationships
// is the generated vocabulary today — the ten canonical ADR-0003 D2 types plus
// their reverse labels — and moving it does not change a name.
func (c *Catalog) RelationshipNames() []ast.Relationship { return ast.Relationships }

// EnumValues implements catalog.Catalog.
func (c *Catalog) EnumValues(field ast.FieldRef) ([]string, bool) {
	if len(field.Enum) == 0 {
		return nil, false
	}
	return field.Enum, true
}

// ClassExists implements catalog.Catalog, over the generated hierarchy.
//
// A class is nameable by its key OR by its full materialised path, because §9
// example 3 writes `class:hardware.computer.server` while example 14 writes
// `class=hypervisor`. Tenant subclasses are runtime rows and are not in the
// generated hierarchy, so they do not resolve here; a catalogue that needs them
// wraps this one.
func (c *Catalog) ClassExists(key string) (catalog.ClassInfo, bool) {
	key = strings.ToLower(key)
	if cl, ok := assetclass.Get(key); ok {
		return catalog.ClassInfo{Key: cl.Key, Path: cl.Path}, true
	}
	for _, cl := range assetclass.All {
		if cl.Path == key {
			return catalog.ClassInfo{Key: cl.Key, Path: cl.Path}, true
		}
	}
	return catalog.ClassInfo{}, false
}

// ClassKeys implements validate.ClassLister, so an unknown class key gets a
// "did you mean".
func (c *Catalog) ClassKeys() []string {
	out := make([]string, 0, len(assetclass.All))
	for _, cl := range assetclass.All {
		out = append(out, cl.Key)
	}
	return out
}

// Resolve implements catalog.Catalog.
func (c *Catalog) Resolve(target string, path []string) (ast.FieldRef, error) {
	target = strings.ToLower(target)
	tgt, ok := catalog.FindTarget(c, target)
	if !ok {
		return ast.FieldRef{}, &catalog.ResolveError{
			Target: target, Path: path, Reason: catalog.ReasonUnknownTarget,
		}
	}
	if len(path) == 0 {
		return ast.FieldRef{}, &catalog.ResolveError{
			Target: target, Path: path, Reason: catalog.ReasonUnknownField,
		}
	}

	// A bare `id` is the ROW's uuid on every target, never the identifier
	// namespace (§13 A1). Taking the namespace branch first made `assets.id` —
	// a first-class uuid column §4.3 lists — unreachable.
	if len(path) == 1 && strings.EqualFold(path[0], "id") {
		return c.resolveFirstClass(tgt, path)
	}
	if ns, isNS := ast.IsNamespace(path[0]); isNS && namespaceAllowed(tgt.Name, ns) {
		return c.resolveNamespaced(tgt, ns, path)
	}
	return c.resolveFirstClass(tgt, path)
}

func (c *Catalog) resolveFirstClass(tgt catalog.Target, path []string) (ast.FieldRef, error) {
	name := strings.ToLower(strings.Join(path, "."))
	if f, ok := c.byName[tgt.Name][name]; ok {
		return fieldRef(path, f, ast.NamespaceNone, f.Name), nil
	}
	return ast.FieldRef{}, &catalog.ResolveError{
		Target: tgt.Name, Path: path, Reason: catalog.ReasonUnknownField,
	}
}

// resolveNamespaced resolves attr./fact./id./tag. paths, and the bare `tag`
// form that means "any key".
func (c *Catalog) resolveNamespaced(tgt catalog.Target, ns ast.Namespace, path []string) (ast.FieldRef, error) {
	key := strings.ToLower(strings.Join(path[1:], "."))
	if key == "" {
		// Bare `id` never reaches here — it is the row's uuid (§13 A1).
		if ns == ast.NamespaceTag {
			return fieldRef(path, tagAnyField(), ns, ""), nil
		}
		return ast.FieldRef{}, &catalog.ResolveError{
			Target: tgt.Name, Path: path, Namespace: ns, Reason: catalog.ReasonEmptyKey,
		}
	}

	switch ns {
	case ast.NamespaceAttr:
		f, ok := attrFields()[key]
		if !ok {
			return ast.FieldRef{}, unknownKey(tgt, path, ns)
		}
		return fieldRef(path, f, ns, key), nil

	case ast.NamespaceFact:
		f, ok := factFields()[key]
		if !ok {
			return ast.FieldRef{}, unknownKey(tgt, path, ns)
		}
		return fieldRef(path, f, ns, key), nil

	case ast.NamespaceID:
		if key == IdentifierAnyKind {
			return fieldRef(path, identifierAnyField(), ns, ""), nil
		}
		f := identifierField(key)
		if !knownIdentifierKind(key) {
			return ast.FieldRef{}, unknownKey(tgt, path, ns)
		}
		return fieldRef(path, f, ns, f.Accessor.Key), nil

	default:
		// tag: any tenant key resolves; tags are free-form by design, so there
		// is nothing to check the key against and nothing to suggest.
		//
		// The key keeps the case the user wrote — unlike every other
		// namespace, a tag key is data, and `tag.Owner` and `tag.owner` are
		// two different jsonb keys.
		written := strings.Join(path[1:], ".")
		return fieldRef(path, tagField(written), ns, written), nil
	}
}

func unknownKey(tgt catalog.Target, path []string, ns ast.Namespace) error {
	return &catalog.ResolveError{
		Target: tgt.Name, Path: path, Namespace: ns, Reason: catalog.ReasonUnknownKey,
	}
}

func knownIdentifierKind(kind string) bool {
	if _, ok := identifierAliases[kind]; ok {
		return true
	}
	for _, k := range assetclass.IdentifierKinds {
		if strings.EqualFold(k, kind) {
			return true
		}
	}
	return false
}

// fieldRef builds the resolved reference the validator hands the translator.
func fieldRef(path []string, info catalog.FieldInfo, ns ast.Namespace, key string) ast.FieldRef {
	return ast.FieldRef{
		Segments:  path,
		Text:      strings.Join(path, "."),
		Namespace: ns,
		Key:       key,
		Type:      info.Type,
		Accessor:  info.Accessor,
		Enum:      info.Enum,
		Resolved:  true,
	}
}
