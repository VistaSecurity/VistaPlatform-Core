package registrycatalog

import (
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/ladder"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
	"github.com/vistasecurity/vistaplatform/shared/query/validate"
)

func newCatalog() *Catalog { return New(Options{}) }

// ------------------------------------------------------------- the shape --

// TestFieldsIsDeterministic runs the same question twice, on two independently
// constructed catalogues, and requires the same answer.
//
// It looks like a tautology and is not. The namespaces are built out of Go
// MAPS, whose range order is deliberately randomised per process — a catalogue
// that appended them without sorting would return a different list on every
// call, and the symptom would be autocomplete that reorders while you type and
// a "did you mean" that picks a different candidate on each keystroke.
func TestFieldsIsDeterministic(t *testing.T) {
	a, b := newCatalog(), newCatalog()
	for _, tgt := range a.Targets() {
		first := names(a.Fields(tgt.Name))
		for i := 0; i < 8; i++ {
			if got := names(a.Fields(tgt.Name)); !equalStrings(got, first) {
				t.Fatalf("%s: Fields differs between calls on one catalogue", tgt.Name)
			}
		}
		if got := names(b.Fields(tgt.Name)); !equalStrings(got, first) {
			t.Errorf("%s: Fields differs between two catalogues", tgt.Name)
		}
		if !sort.StringsAreSorted(first) {
			t.Errorf("%s: Fields is not sorted by name: %v", tgt.Name, first)
		}
	}
}

// TestNoDuplicateFieldNames is §13 A1 as a structural rule: a catalogue may not
// publish one field name twice. It is how `id` came to mean two things at once,
// leaving §4.3's uuid column unreachable and the suggester wrong about which
// field a user would get.
func TestNoDuplicateFieldNames(t *testing.T) {
	c := newCatalog()
	for _, tgt := range c.Targets() {
		seen := map[string]bool{}
		for _, f := range c.Fields(tgt.Name) {
			if seen[f.Name] {
				t.Errorf("%s: field %q is published twice", tgt.Name, f.Name)
			}
			seen[f.Name] = true
		}
	}
}

// TestEveryPublishedFieldResolves closes the loop between the two halves of the
// interface. Fields() is what autocomplete offers and what the suggester names;
// a field it offers that Resolve refuses would send a user to a term that
// cannot be written.
func TestEveryPublishedFieldResolves(t *testing.T) {
	c := newCatalog()
	for _, tgt := range c.Targets() {
		for _, f := range c.Fields(tgt.Name) {
			if f.Name == string(ast.NamespaceTag) {
				// The bare `tag` is published as one field and resolves
				// through the empty-key branch; covered by TestTagNamespace.
				continue
			}
			ref, err := c.Resolve(tgt.Name, strings.Split(f.Name, "."))
			if err != nil {
				t.Errorf("%s: Fields offers %q but Resolve refuses it: %v", tgt.Name, f.Name, err)
				continue
			}
			if ref.Type != f.Type {
				t.Errorf("%s: %q is published as %s and resolves as %s", tgt.Name, f.Name, f.Type, ref.Type)
			}
			if !ref.Resolved {
				t.Errorf("%s: %q resolved without Resolved set", tgt.Name, f.Name)
			}
		}
	}
}

// TestTargetsAreTheSpecsTargets pins §4.1's list, including the two table-less
// ones. A target quietly dropped would make every predicate over it an
// unknown_target, which reads like a caller bug rather than a catalogue one.
func TestTargetsAreTheSpecsTargets(t *testing.T) {
	want := []string{
		"asset", "certificate", "crypto_configuration", "endpoint", "finding",
		"identifier", "measurement", "observation", "relationship", "software_install",
	}
	got := make([]string, 0, len(want))
	for _, tgt := range newCatalog().Targets() {
		got = append(got, tgt.Name)
	}
	sort.Strings(got)
	if !equalStrings(got, want) {
		t.Errorf("targets:\n  got  %v\n  want %v", got, want)
	}
	for _, name := range []string{"observation", "measurement"} {
		tgt, _ := catalog.FindTarget(newCatalog(), name)
		if !tgt.InMemory || tgt.Table != "" {
			t.Errorf("%s must be table-less: it is evaluated where the value is, not in SQL", name)
		}
	}
}

// ------------------------------------------------------------ namespaces --

// TestEveryClassAttributeResolves walks every attribute of every class in the
// generated registry and requires it to resolve with the type registryType
// documents. This is the whole promise of the package: add an attribute to
// standards/asset-classes.yaml, run `make generate`, and it is queryable.
func TestEveryClassAttributeResolves(t *testing.T) {
	c := newCatalog()
	checked := 0
	for _, class := range assetclass.All {
		props, ok := assetclass.Attributes(class.Key)
		if !ok {
			t.Errorf("class %q has no attribute schema", class.Key)
			continue
		}
		for name, p := range props {
			want, publishable := registryType(p.Type)
			ref, err := c.Resolve("asset", []string{"attr", strings.ToLower(name)})
			if !publishable {
				if err == nil {
					t.Errorf("attr.%s declares type %q, which is not publishable, but resolved", name, p.Type)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s.%s: %v", class.Key, name, err)
				continue
			}
			checked++
			if ref.Type != want {
				t.Errorf("attr.%s: type %s, want %s for a %q attribute", name, ref.Type, want, p.Type)
			}
			if ref.Accessor.Kind != ast.AccessorJSONB || ref.Accessor.JSONColumn != attributesColumn {
				t.Errorf("attr.%s: accessor %+v, want a jsonb read of %q", name, ref.Accessor, attributesColumn)
			}
			if ref.Accessor.Key != strings.ToLower(name) {
				t.Errorf("attr.%s: accessor key %q", name, ref.Accessor.Key)
			}
			if len(p.Enum) > 0 && !equalStrings(ref.Enum, p.Enum) {
				t.Errorf("attr.%s: enum %v, want the registry's %v", name, ref.Enum, p.Enum)
			}
		}
	}
	// A registry that had gone empty would pass every assertion above without
	// checking anything.
	if checked < 50 {
		t.Errorf("only %d attributes checked; the registry has ~80 — did the schemas fail to load?", checked)
	}
}

// TestEveryFactKeyResolves is the same promise for standards/fact-keys.yaml.
func TestEveryFactKeyResolves(t *testing.T) {
	c := newCatalog()
	if len(facts.All) == 0 {
		t.Fatal("the fact registry is empty")
	}
	for _, k := range facts.All {
		want, publishable := registryType(k.Type)
		ref, err := c.Resolve("asset", strings.Split("fact."+k.Key, "."))
		if !publishable {
			if err == nil {
				t.Errorf("fact.%s declares type %q, which is not publishable, but resolved", k.Key, k.Type)
			}
			continue
		}
		if err != nil {
			t.Errorf("fact.%s: %v", k.Key, err)
			continue
		}
		if ref.Type != want {
			t.Errorf("fact.%s: type %s, want %s for a %q key", k.Key, ref.Type, want, k.Type)
		}
		if ref.Accessor.Kind != ast.AccessorFact || ref.Accessor.Key != k.Key {
			t.Errorf("fact.%s: accessor %+v", k.Key, ref.Accessor)
		}
		if len(k.Enum) > 0 && !equalStrings(ref.Enum, k.Enum) {
			t.Errorf("fact.%s: enum %v, want the registry's %v", k.Key, ref.Enum, k.Enum)
		}
	}

	// A fact predicate reads facts on the ASSET, so the namespace is offered
	// only where there is one (§4.2). `measurement` reads facts and nothing
	// else (§8).
	if _, err := c.Resolve("endpoint", []string{"fact", "os.name"}); err == nil {
		t.Error("fact. resolved on `endpoint`, which has no facts of its own")
	}
	if _, err := c.Resolve("measurement", []string{"fact", "os", "name"}); err != nil {
		t.Errorf("fact. must resolve on `measurement`: %v", err)
	}
	if _, err := c.Resolve("measurement", []string{"attr", "model"}); err == nil {
		t.Error("attr. resolved on `measurement`, which reads facts and nothing else")
	}
}

// TestArrayAndObjectAreePresenceOnly pins the sharpest edge of the type rule.
//
// A jsonb array read through `->>` or `#>> '{}'` is TEXT. Typing it keyword[]
// would generate `unnest(text)` — a Postgres error — and typing it text would
// make `fact.net.vlans:10` a substring search that matches the stored `[100]`.
// It is json: exists, and nothing else (ast.TypeJSON).
func TestArrayAndObjectArePresenceOnly(t *testing.T) {
	c := newCatalog()
	arrays := 0
	for _, k := range facts.All {
		if k.Type != "array" && k.Type != "object" {
			continue
		}
		arrays++
		ref, err := c.Resolve("asset", strings.Split("fact."+k.Key, "."))
		if err != nil {
			t.Fatalf("fact.%s: %v", k.Key, err)
		}
		if ref.Type != ast.TypeJSON {
			t.Errorf("fact.%s is %q; an %s fact must be json", k.Key, ref.Type, k.Type)
		}
	}
	if arrays == 0 {
		t.Fatal("no array or object fact keys in the registry — this test checked nothing")
	}

	// Same rule on the attribute side, where the registry's arrays live.
	ref, err := c.Resolve("asset", []string{"attr", "industrial_protocols"})
	if err != nil {
		t.Fatalf("attr.industrial_protocols: %v", err)
	}
	if ref.Type != ast.TypeJSON {
		t.Errorf("attr.industrial_protocols is %q, want json", ref.Type)
	}

	// And the consequence, which is the point: exists is allowed, every
	// comparison is refused.
	if !catalog.KnownType(ast.TypeJSON) {
		t.Error("json must be a known type, or exists() on it is refused too")
	}
	for _, op := range []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe, ast.OpLt, ast.OpGte} {
		if catalog.OperatorAllowed(ast.TypeJSON, op) {
			t.Errorf("json must not accept %q", op)
		}
	}
}

// TestIdentifierNamespace covers the three §12/§13 decisions that meet here.
func TestIdentifierNamespace(t *testing.T) {
	c := newCatalog()

	// Every registry kind resolves and carries its own kind as the bound key.
	for _, kind := range assetclass.IdentifierKinds {
		ref, err := c.Resolve("asset", []string{"id", kind})
		if err != nil {
			t.Errorf("id.%s: %v", kind, err)
			continue
		}
		if ref.Accessor.Kind != ast.AccessorIdentifier || ref.Accessor.Key != kind {
			t.Errorf("id.%s: accessor %+v", kind, ref.Accessor)
		}
	}

	// §12 amendment 4: `id.mac` is a documented alias and resolves to the
	// STORED kind. Binding "mac" would match nothing, silently and forever.
	ref, err := c.Resolve("asset", []string{"id", "mac"})
	if err != nil {
		t.Fatalf("id.mac: %v", err)
	}
	if ref.Accessor.Key != "mac_address" {
		t.Errorf("id.mac binds %q, want the stored kind %q", ref.Accessor.Key, "mac_address")
	}

	// §13 A1: a bare `id` is the ROW's uuid on every target, and the any-kind
	// form is id.any.
	ref, err = c.Resolve("asset", []string{"id"})
	if err != nil {
		t.Fatalf("bare id: %v", err)
	}
	if ref.Type != ast.TypeUUID || ref.Accessor.Kind != ast.AccessorColumn {
		t.Errorf("bare `id` resolved to %s/%s, want the row's uuid column", ref.Type, ref.Accessor.Kind)
	}
	ref, err = c.Resolve("asset", []string{"id", IdentifierAnyKind})
	if err != nil {
		t.Fatalf("id.any: %v", err)
	}
	if ref.Accessor.Kind != ast.AccessorIdentifierAny {
		t.Errorf("id.any accessor %q", ref.Accessor.Kind)
	}

	if _, err := c.Resolve("asset", []string{"id", "not_a_kind"}); err == nil {
		t.Error("an unregistered identifier kind must not resolve")
	}
}

// TestIdentifierAnyIsNotARealKind is the collision check the `any` pseudo-kind
// depends on. If the registry ever adds a kind called "any", `id.any` would
// mean two things and the pseudo-kind would shadow the real one.
func TestIdentifierAnyIsNotARealKind(t *testing.T) {
	for _, kind := range assetclass.IdentifierKinds {
		if kind == IdentifierAnyKind {
			t.Fatalf("the registry now has a real identifier kind %q, which collides with the "+
				"any-kind pseudo-kind; one of the two has to be renamed", IdentifierAnyKind)
		}
	}
	for alias, stored := range identifierAliases {
		if !containsFold(assetclass.IdentifierKinds, stored) {
			t.Errorf("alias %q points at %q, which is not a registered kind", alias, stored)
		}
		if containsFold(assetclass.IdentifierKinds, alias) {
			t.Errorf("alias %q is also a real kind; the alias would shadow it", alias)
		}
	}
}

// TestIdentifierTargetKindExcludesTheAlias is the other half of the alias
// decision, and the one that is easy to get wrong by being generous.
//
// `id.mac` is a spelling of the NAMESPACE and rewrites to mac_address on the
// way to the column. `identifier:(kind:mac)` compares the column itself, and
// the column only ever holds mac_address — so accepting "mac" there would
// validate happily and return nothing, forever. The static catalogue does
// accept it.
func TestIdentifierTargetKindExcludesTheAlias(t *testing.T) {
	c := newCatalog()
	var kindField catalog.FieldInfo
	for _, f := range c.Fields("identifier") {
		if f.Name == "kind" {
			kindField = f
		}
	}
	if len(kindField.Enum) == 0 {
		t.Fatal("identifier.kind has no closed value set")
	}
	for alias := range identifierAliases {
		if containsFold(kindField.Enum, alias) {
			t.Errorf("identifier.kind accepts the alias %q; the column never holds it", alias)
		}
	}
	if !containsFold(kindField.Enum, "mac_address") {
		t.Error("identifier.kind should accept the stored kind mac_address")
	}
}

// TestTagNamespace: tags are tenant text, so every key resolves and none can be
// enumerated — and the key keeps the case it was written in, because a jsonb
// key is data.
func TestTagNamespace(t *testing.T) {
	c := newCatalog()
	ref, err := c.Resolve("asset", []string{"tag", "Owner"})
	if err != nil {
		t.Fatalf("tag.Owner: %v", err)
	}
	if ref.Accessor.Key != "Owner" {
		t.Errorf("tag key %q; a tag key is data and keeps its case", ref.Accessor.Key)
	}
	if ref.Accessor.JSONColumn != tagsColumn {
		t.Errorf("tag accessor reads %q", ref.Accessor.JSONColumn)
	}
	ref, err = c.Resolve("asset", []string{"tag"})
	if err != nil {
		t.Fatalf("bare tag: %v", err)
	}
	if ref.Accessor.Kind != ast.AccessorTagAny || ref.Type != ast.TypeText {
		t.Errorf("bare `tag` resolved to %s/%s, want a text search over any key or value",
			ref.Type, ref.Accessor.Kind)
	}
}

// TestUnknownKeysReportTheRightReason: the validator turns a ResolveReason into
// a message and a suggestion, so the reason has to be the right one.
func TestUnknownKeysReportTheRightReason(t *testing.T) {
	c := newCatalog()
	for _, tc := range []struct {
		name string
		path []string
		want catalog.ResolveReason
	}{
		{"unregistered attribute", []string{"attr", "not_registered"}, catalog.ReasonUnknownKey},
		{"unregistered fact", []string{"fact", "cve", "max_cvss"}, catalog.ReasonUnknownKey},
		{"unregistered identifier kind", []string{"id", "nonesuch"}, catalog.ReasonUnknownKey},
		{"empty attr key", []string{"attr"}, catalog.ReasonEmptyKey},
		{"unknown column", []string{"hostnaem"}, catalog.ReasonUnknownField},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Resolve("asset", tc.path)
			var re *catalog.ResolveError
			if !asResolveError(err, &re) {
				t.Fatalf("got %v, want a *catalog.ResolveError", err)
			}
			if re.Reason != tc.want {
				t.Errorf("reason %q, want %q", re.Reason, tc.want)
			}
		})
	}
	if _, err := c.Resolve("nonesuch", []string{"hostname"}); err == nil {
		t.Error("an unknown target must not resolve")
	}
}

// -------------------------------------------------------------- vocabulary --

// TestFindingVocabularyComesFromTheRegistry: the findings table carries no
// CHECK on producer, kind or subject_type — shared/findings is the enforcement
// point for WRITES, and this catalogue must offer the same words for reads, or
// a kind that can be written cannot be queried.
func TestFindingVocabularyComesFromTheRegistry(t *testing.T) {
	c := newCatalog()
	byName := map[string]catalog.FieldInfo{}
	for _, f := range c.Fields("finding") {
		byName[f.Name] = f
	}
	for _, p := range findings.Producers {
		if !containsFold(byName["producer"].Enum, p.Key) {
			t.Errorf("finding.producer does not accept the registered producer %q", p.Key)
		}
	}
	for _, k := range findings.All {
		if !containsFold(byName["kind"].Enum, k.Key) {
			t.Errorf("finding.kind does not accept the registered kind %q", k.Key)
		}
	}
	if !equalStrings(byName["subject_type"].Enum, findings.SubjectTypes) {
		t.Errorf("finding.subject_type = %v, want the registry's %v",
			byName["subject_type"].Enum, findings.SubjectTypes)
	}
}

// TestClassVocabularyComesFromTheRegistry: a class is nameable by key or by its
// materialised path (§9 examples 3 and 14 use one each), and every one of the
// generated hierarchy's nodes answers to both.
func TestClassVocabularyComesFromTheRegistry(t *testing.T) {
	c := newCatalog()
	for _, cl := range assetclass.All {
		byKey, ok := c.ClassExists(cl.Key)
		if !ok || byKey.Path != cl.Path {
			t.Errorf("class %q: got %+v, %v", cl.Key, byKey, ok)
		}
		byPath, ok := c.ClassExists(cl.Path)
		if !ok || byPath.Key != cl.Key {
			t.Errorf("class path %q: got %+v, %v", cl.Path, byPath, ok)
		}
	}
	if _, ok := c.ClassExists("not_a_class"); ok {
		t.Error("an unknown class key must not resolve")
	}
	if got, want := len(c.ClassKeys()), len(assetclass.All); got != want {
		t.Errorf("ClassKeys has %d entries, the hierarchy has %d", got, want)
	}
}

// TestCryptoConfigurationFieldsFollowTheSpec pins §4.3's crypto table, added by
// §12 amendment 5 — the one target that had no field table at all when the
// static catalogue was written.
//
// Worth pinning by hand because no conformance fixture covers this target's
// algorithm fields, so nothing that RUNS would notice a rename. The static
// catalogue published the columns' short names (`signature`, `symmetric`,
// `hash`) against §4.3's `signature_algorithm`, `symmetric_algorithm`,
// `hash_algorithm` for exactly that reason — two catalogues disagreeing about a
// field name with no case able to fail. Both now use the spec's names
// (workstream 0.8e); TestTestcatalogAgreesOnCryptoFieldNames pins that.
func TestCryptoConfigurationFieldsFollowTheSpec(t *testing.T) {
	want := map[string]ast.FieldType{
		"protocol":             ast.TypeKeyword,
		"protocol_version":     ast.TypeKeyword,
		"cipher_suite":         ast.TypeKeyword,
		"key_exchange":         ast.TypeKeyword,
		"signature_algorithm":  ast.TypeKeyword,
		"symmetric_algorithm":  ast.TypeKeyword,
		"hash_algorithm":       ast.TypeKeyword,
		"key_size":             ast.TypeNumber,
		"strength":             ast.TypeKeyword,
		"risk":                 ast.TypeBand,
		"risk_score":           ast.TypeNumber,
		"algorithm.deprecated": ast.TypeBoolean,
		"last_seen":            ast.TypeTimestamp,
	}
	got := map[string]catalog.FieldInfo{}
	for _, f := range newCatalog().Fields("crypto_configuration") {
		got[f.Name] = f
	}
	for name, typ := range want {
		f, ok := got[name]
		if !ok {
			t.Errorf("§4.3 lists crypto_configuration.%s and the catalogue does not publish it", name)
			continue
		}
		if f.Type != typ {
			t.Errorf("crypto_configuration.%s is %s, §4.3 says %s", name, f.Type, typ)
		}
	}
	if f := got["strength"]; !equalStrings(f.Enum, cryptoStrengthValues) {
		t.Errorf("crypto_configuration.strength enum %v, want %v", f.Enum, cryptoStrengthValues)
	}
	// `risk` here has no AssessedBy column, so `risk:not_assessed` must not be
	// offered: crypto_implementations.risk_score DEFAULTs to 0 with nothing
	// recording whether anybody scored it, and answering "not assessed" from
	// that would be the §5.2 mistake the coverage guard exists to prevent.
	if got["risk"].Accessor.AssessedBy != "" {
		t.Errorf("crypto_configuration.risk claims an AssessedBy column (%q); the table has none",
			got["risk"].Accessor.AssessedBy)
	}
}

// TestTestcatalogAgreesOnCryptoFieldNames pins the two catalogues to one set of
// names for crypto_configuration.
//
// This is the check that was missing while they disagreed. The conformance
// exemption list only catches a case that RUNS, and no fixture writes any of
// these six names — so `signature` here and `signature_algorithm` there was a
// contradiction between the static catalogue and the spec that every green test
// run stepped straight over. Comparing the tables directly is what makes a
// rename on one side fail.
func TestTestcatalogAgreesOnCryptoFieldNames(t *testing.T) {
	// crypto_configuration carries no namespaces (§4.2 gives them to asset,
	// observation and measurement only), so the static catalogue's whole
	// vocabulary for it IS its first-class table and the two are comparable.
	static := map[string]bool{}
	for _, f := range testcatalog.New().Fields("crypto_configuration") {
		static[f.Name] = true
	}
	registry := map[string]bool{}
	for _, f := range FirstClassFields("crypto_configuration") {
		registry[f.Name] = true
	}

	for name := range registry {
		if !static[name] {
			t.Errorf("crypto_configuration.%s is published by the registry catalogue "+
				"and not by the static one", name)
		}
	}
	for name := range static {
		if !registry[name] {
			t.Errorf("crypto_configuration.%s is published by the static catalogue "+
				"and not by the registry one", name)
		}
	}
	for _, name := range []string{"signature_algorithm", "symmetric_algorithm", "hash_algorithm"} {
		if !registry[name] || !static[name] {
			t.Errorf("§12 amendment 5 names crypto_configuration.%s; registry=%t static=%t",
				name, registry[name], static[name])
		}
	}
}

// ------------------------------------------------------------ type mapping --

// TestRegistryTypeRule restates the documented mapping by hand, in both
// polarities — the same reason catalog's operator matrix has a table of its
// own. A mapping is exactly the shape of thing where a typo looks like intent.
func TestRegistryTypeRule(t *testing.T) {
	for declared, want := range map[string]ast.FieldType{
		"string":  ast.TypeKeyword,
		"integer": ast.TypeNumber,
		"number":  ast.TypeNumber,
		"boolean": ast.TypeBoolean,
		"date":    ast.TypeTimestamp,
		"array":   ast.TypeJSON,
		"object":  ast.TypeJSON,
	} {
		got, ok := registryType(declared)
		if !ok || got != want {
			t.Errorf("registryType(%q) = %s,%v want %s,true", declared, got, ok, want)
		}
	}
	for _, declared := range []string{"", "text", "keyword", "jsonb", "uuid"} {
		if got, ok := registryType(declared); ok {
			t.Errorf("registryType(%q) = %s,true; an unknown declared type must not be published",
				declared, got)
		}
	}
}

// TestAttributeConflictPanics is the mutation half of the flat `attr.`
// namespace. §4.2 makes it global — `attr.model` is one field, not one per
// class — so two classes declaring one name with two types has no correct
// answer, and picking one silently would type one class's data by another
// class's schema.
//
// The registry has no such conflict today (TestNoAttributeConflictInTheRegistry
// checks that); this feeds the builder one directly, because a guard nobody has
// seen fire is not a guard.
func TestAttributeConflictPanics(t *testing.T) {
	classes := []assetclass.Class{{Key: "alpha"}, {Key: "beta"}}
	schemas := map[string]map[string]assetclass.AttributeProperty{
		"alpha": {"shared_name": {Type: "string"}},
		"beta":  {"shared_name": {Type: "integer"}},
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("two classes declaring one attribute with two types must panic")
		}
		msg, _ := r.(string)
		for _, want := range []string{"shared_name", "alpha", "beta"} {
			if !strings.Contains(msg, want) {
				t.Errorf("panic message %q does not name %q", msg, want)
			}
		}
	}()
	buildAttributeFields(classes, schemas)
}

// TestAttributeConflictIsNotOverStrict is the same guard pointed the other way:
// the SAME attribute declared identically by several classes — which is most of
// the registry, since the schemas are inherited — must be fine.
func TestAttributeConflictIsNotOverStrict(t *testing.T) {
	classes := []assetclass.Class{{Key: "alpha"}, {Key: "beta"}}
	prop := assetclass.AttributeProperty{Type: "string", Description: "same", Enum: []string{"a", "b"}}
	schemas := map[string]map[string]assetclass.AttributeProperty{
		"alpha": {"shared_name": prop},
		"beta":  {"shared_name": prop},
	}
	out := buildAttributeFields(classes, schemas)
	f, ok := out["shared_name"]
	if !ok {
		t.Fatal("the attribute was dropped")
	}
	if f.Description != "same" {
		t.Errorf("description %q; agreeing classes keep it", f.Description)
	}
}

// TestAttributeDescriptionDropsWhenClassesDisagree: showing one class's wording
// as if it were the field's would be a small lie in a tooltip.
func TestAttributeDescriptionDropsWhenClassesDisagree(t *testing.T) {
	classes := []assetclass.Class{{Key: "alpha"}, {Key: "beta"}}
	schemas := map[string]map[string]assetclass.AttributeProperty{
		"alpha": {"n": {Type: "string", Description: "one"}},
		"beta":  {"n": {Type: "string", Description: "two"}},
	}
	if got := buildAttributeFields(classes, schemas)["n"].Description; got != "" {
		t.Errorf("description %q; classes disagree, so the field should carry none", got)
	}
}

// TestNoAttributeConflictInTheRegistry is the live half: constructing the real
// namespace must not panic, which is only true while the YAML stays consistent.
func TestNoAttributeConflictInTheRegistry(t *testing.T) {
	if got := len(attrFields()); got < 50 {
		t.Errorf("the attr namespace has %d entries; the registry declares ~80", got)
	}
}

// TestUnknownFieldsGetASuggestion runs a near-miss through the validator,
// because the reason code alone is only half the contract: §10 says a message
// "names the offending span and offers the fix — never 'invalid query'", and
// the fix is computed from what Fields() publishes.
//
// A catalogue whose Fields() were empty, unsorted or full of duplicates would
// still return the right CODE here and a useless or unstable suggestion, which
// is the failure this test exists to see.
func TestUnknownFieldsGetASuggestion(t *testing.T) {
	cat := newCatalog()
	for _, tc := range []struct {
		name, query, wantCode, wantIn string
	}{
		{"near-miss attribute", "attr.firmware_versoin:7", "unknown_field", "attr.firmware_version"},
		{"near-miss fact", "fact.os.nmae:linux", "unknown_field", "fact.os.name"},
		{"near-miss column", "hostnaem:web-1", "unknown_field", "hostname"},
		{"near-miss class", "class:servr", "unknown_value", "server"},
		{"near-miss enum value", "environment:producton", "unknown_value", "production"},
		{"near-miss identifier kind", "id.serial_numbr:X", "unknown_field", "id.serial_number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := parser.Parse(tc.query)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			_, err = validate.Validate(res, "asset", cat, validate.DefaultOptions().WithLadder(ladder.CVSS))
			list, ok := err.(queryerr.List)
			if !ok || len(list) == 0 {
				t.Fatalf("got %v, want a validation diagnostic", err)
			}
			e := list[0]
			if string(e.Code) != tc.wantCode {
				t.Errorf("code %q, want %q", e.Code, tc.wantCode)
			}
			if !strings.Contains(e.Suggestion, tc.wantIn) {
				t.Errorf("suggestion %q does not name %q", e.Suggestion, tc.wantIn)
			}
		})
	}

	// The other polarity: the correct spellings must all validate, or the
	// suggestions above would be sending users somewhere that does not work.
	for _, q := range []string{
		"attr.firmware_version:7", "fact.os.name:linux", "hostname:web-1",
		"class:server", "environment:production", "id.serial_number:X",
	} {
		res, err := parser.Parse(q)
		if err != nil {
			t.Fatalf("parse %q: %v", q, err)
		}
		if _, err := validate.Validate(res, "asset", cat,
			validate.DefaultOptions().WithLadder(ladder.CVSS)); err != nil {
			t.Errorf("%q should validate: %v", q, err)
		}
	}
}

// ---------------------------------------------------------------- helpers --

func names(fields []catalog.FieldInfo) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.Name)
	}
	return out
}

func equalStrings(a, b []string) bool {
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

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func asResolveError(err error, out **catalog.ResolveError) bool {
	re, ok := err.(*catalog.ResolveError)
	if !ok {
		return false
	}
	*out = re
	return true
}
