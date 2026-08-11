package cbom

import (
	"reflect"
	"testing"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
)

// predicateToParams is the translator between the typed Scope predicate
// (scopes/model.go) and the params map the CBOM assembly accepts. It used to
// carry Include.Environment and Include.RiskLevel only; the tests below pin the
// contract now that every predicate field is enforced and an untranslatable one
// is an error rather than a silent widening.

func mustTranslate(t *testing.T, p scopes.Predicate) map[string]interface{} {
	t.Helper()
	params, unsupported := predicateToParams(p)
	if len(unsupported) > 0 {
		t.Fatalf("unexpected unsupported fields: %v", unsupported)
	}
	return params
}

func predicateOf(t *testing.T, params map[string]interface{}) handlers.AssetPredicate {
	t.Helper()
	raw, ok := params[handlers.ParamAssetPredicate]
	if !ok {
		t.Fatalf("params carry no %q entry: %#v", handlers.ParamAssetPredicate, params)
	}
	p, ok := raw.(handlers.AssetPredicate)
	if !ok {
		t.Fatalf("%q = %T, want handlers.AssetPredicate", handlers.ParamAssetPredicate, raw)
	}
	return p
}

func TestPredicateToParams_EmptyPredicateIncludesAllOptions(t *testing.T) {
	got := mustTranslate(t, scopes.Predicate{})

	// Defaults: everything included. The CBOM assembly honors these to
	// decide which component sub-trees to assemble.
	for _, key := range []string{
		"includeAlgorithms",
		"includeCertificates",
		"includeProtocols",
		"includeKeys",
		"includeLibraries",
	} {
		v, ok := got[key]
		if !ok {
			t.Fatalf("missing key %q", key)
		}
		if b, _ := v.(bool); !b {
			t.Errorf("%q = %v, want true (defaults flip everything on)", key, v)
		}
	}

	// An empty predicate must not add a filter at all — the "All" scope, which
	// is also what lets standalone certificates into the artifact.
	if _, set := got[handlers.ParamAssetPredicate]; set {
		t.Errorf("%q should be absent for an empty predicate", handlers.ParamAssetPredicate)
	}
}

func TestPredicateToParams_IncludeFieldsAllTranslate(t *testing.T) {
	p := scopes.Predicate{
		Include: &scopes.PredicateClause{
			Environment:    []string{"production", "prod"},
			RiskLevel:      []string{"critical", "high"},
			AssetType:      []string{"server", "loadbalancer"},
			AssetOwnership: []string{"internal"},
			AssetStatus:    []string{"monitoring"},
			BusinessUnit:   []string{"payments"},
			LocationRegion: []string{"us-east-1"},
			TagsAnyOf:      []string{"pci-in-scope"},
		},
	}
	got := predicateOf(t, mustTranslate(t, p))
	if got.Include == nil {
		t.Fatal("Include clause was dropped")
	}

	want := handlers.AssetClause{
		Environment:    []string{"production", "prod"},
		RiskLevel:      []string{"critical", "high"},
		AssetType:      []string{"server", "loadbalancer"},
		AssetOwnership: []string{"internal"},
		AssetStatus:    []string{"monitoring"},
		BusinessUnit:   []string{"payments"},
		LocationRegion: []string{"us-east-1"},
		TagsAnyOf:      []string{"pci-in-scope"},
	}
	if !reflect.DeepEqual(*got.Include, want) {
		t.Fatalf("Include translated to\n %#v\nwant\n %#v", *got.Include, want)
	}
	if got.Exclude != nil {
		t.Errorf("Exclude = %#v, want nil", got.Exclude)
	}
}

func TestPredicateToParams_NilIncludeIsEquivalentToEmpty(t *testing.T) {
	// `Include: nil` and `Include: &PredicateClause{}` should produce the
	// same params shape — both mean "no Include constraint."
	withNil := mustTranslate(t, scopes.Predicate{Include: nil})
	withEmpty := mustTranslate(t, scopes.Predicate{Include: &scopes.PredicateClause{}})

	if !reflect.DeepEqual(withNil, withEmpty) {
		t.Fatalf("nil Include vs empty Include diverged:\n nil:   %#v\n empty: %#v", withNil, withEmpty)
	}
}

// TestPredicateToParams_ExcludeIsCarried replaces a test that pinned the
// opposite: Exclude used to be dropped on the floor, which made the seeded
// "Non-Dev/Test" scope — an Exclude-only predicate — produce byte-for-byte the
// same artifact as "All".
func TestPredicateToParams_ExcludeIsCarried(t *testing.T) {
	p := scopes.Predicate{
		Exclude: &scopes.PredicateClause{
			Environment: []string{"dev", "test"},
			TagsAnyOf:   []string{"dev", "test"},
		},
	}
	got := predicateOf(t, mustTranslate(t, p))

	if got.Exclude == nil {
		t.Fatal("Exclude clause was dropped — the Non-Dev/Test scope would equal All")
	}
	if !reflect.DeepEqual(got.Exclude.Environment, []string{"dev", "test"}) {
		t.Errorf("Exclude.Environment = %v", got.Exclude.Environment)
	}
	if !reflect.DeepEqual(got.Exclude.TagsAnyOf, []string{"dev", "test"}) {
		t.Errorf("Exclude.TagsAnyOf = %v", got.Exclude.TagsAnyOf)
	}
	// Exclude must not leak into Include; they mean opposite things.
	if got.Include != nil {
		t.Errorf("exclude leaked into include: %#v", got.Include)
	}
}

// TestPredicateTranslation_CoversEveryPredicateField is the guard that keeps the
// unsupported-field check from going inert. It walks scopes.PredicateClause by
// reflection, sets every field, and requires the translation to carry all of
// them. Add a field to the predicate without wiring clauseTranslators and this
// fails here — rather than silently widening every artifact generated against a
// scope that uses it.
func TestPredicateTranslation_CoversEveryPredicateField(t *testing.T) {
	clause := &scopes.PredicateClause{}
	v := reflect.ValueOf(clause).Elem()
	fieldNames := make([]string, 0, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.Slice {
			t.Fatalf("predicate field %q is %s; the translator only understands []string",
				v.Type().Field(i).Name, f.Kind())
		}
		f.Set(reflect.ValueOf([]string{"sentinel"}))
		fieldNames = append(fieldNames, jsonFieldName(v.Type().Field(i)))
	}

	translated, unsupported := translateClause(clause)
	if len(unsupported) > 0 {
		t.Fatalf("predicate fields %v are not wired into clauseTranslators; "+
			"scopes using them would be rejected at generate time", unsupported)
	}
	if translated == nil {
		t.Fatal("a fully-populated clause translated to nothing")
	}

	// Every field of the target clause must have received the sentinel, so a
	// translator entry that maps two predicate fields onto one target field
	// cannot hide.
	tv := reflect.ValueOf(translated).Elem()
	if tv.NumField() != len(fieldNames) {
		t.Fatalf("AssetClause has %d fields, scopes.PredicateClause has %d — they must "+
			"correspond one-to-one", tv.NumField(), len(fieldNames))
	}
	for i := 0; i < tv.NumField(); i++ {
		if tv.Field(i).Len() == 0 {
			t.Errorf("AssetClause.%s was not populated by the translation", tv.Type().Field(i).Name)
		}
	}
}

// TestTranslateClause_ReportsUnknownFields proves the unsupported-field path is
// reachable, using a stand-in struct shaped like a future PredicateClause that
// has grown a field nobody wired up.
func TestTranslateClause_ReportsUnknownFields(t *testing.T) {
	type futureClause struct {
		Environment  []string `json:"environment,omitempty"`
		IPSubnetCIDR []string `json:"ip_subnet_cidr,omitempty"`
	}

	// Mirrors translateClause's loop over the real type. Kept in step by
	// TestPredicateTranslation_CoversEveryPredicateField, which uses the real one.
	var unsupported []string
	v := reflect.ValueOf(futureClause{
		Environment:  []string{"production"},
		IPSubnetCIDR: []string{"10.0.0.0/8"},
	})
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Len() == 0 {
			continue
		}
		name := jsonFieldName(v.Type().Field(i))
		if _, known := clauseTranslators[name]; !known {
			unsupported = append(unsupported, name)
		}
	}

	if len(unsupported) != 1 || unsupported[0] != "ip_subnet_cidr" {
		t.Fatalf("unsupported = %v, want [ip_subnet_cidr]", unsupported)
	}

	err := &UnsupportedPredicateError{Fields: unsupported}
	if err.Error() == "" {
		t.Error("UnsupportedPredicateError has no message")
	}
}

func TestFirstNonEmpty_PicksFirstWithContent(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"first wins", []string{"a", "b"}, "a"},
		{"skip empty", []string{"", "b"}, "b"},
		{"all empty", []string{"", ""}, ""},
		{"nothing", []string{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := firstNonEmpty(c.in...)
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
