package cbom

import (
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
)

// scopeToParams is the whole translation now: validate the Scope's query and
// pass it through to inventory-service, which applies it in SQL.
//
// What these tests used to pin was a reflective translator between
// scopes.PredicateClause and an in-memory matcher, plus a per-field check that
// the deployment could actually enforce each one. That machinery is gone — a
// scope means what the query language says it means, in one place — so what is
// left to pin is narrower and more important: a scope that does not validate
// must REFUSE, and an empty scope must add no filter.

func mustParams(t *testing.T, query string) map[string]interface{} {
	t.Helper()
	params, err := scopeToParams(&scopes.Scope{Query: query})
	if err != nil {
		t.Fatalf("scopeToParams(%q): %v", query, err)
	}
	return params
}

func TestScopeToParams_EmptyQueryIncludesAllOptionsAndNoFilter(t *testing.T) {
	got := mustParams(t, "")

	// Defaults: everything included. The CBOM assembly honors these to decide
	// which component sub-trees to assemble.
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

	// The "All" scope must not add a filter at all. A filter that narrowed
	// nothing would still change the assembly's behaviour: `scoped` gates
	// whether unattributed certificates are included.
	if _, ok := got[handlers.ParamAssetQuery]; ok {
		t.Errorf("an empty scope must carry NO query param, got %#v", got[handlers.ParamAssetQuery])
	}
}

func TestScopeToParams_CarriesTheQueryInCanonicalForm(t *testing.T) {
	got := mustParams(t, "environment:production   class:server")
	q, ok := got[handlers.ParamAssetQuery].(string)
	if !ok {
		t.Fatalf("params carry no string %q entry: %#v", handlers.ParamAssetQuery, got)
	}
	// Canonical, not as typed: the artifact records scope_id + scope_version,
	// and two spellings of one predicate are two versions a diff cannot match.
	if q != "environment:production and class:server" {
		t.Errorf("query = %q, want the canonical form with the implicit AND written out", q)
	}
}

// TestScopeToParams_RefusesAScopeThatDoesNotValidate is the fail-closed half.
//
// A scope is an attestation boundary. A predicate the pipeline cannot evaluate
// used to be dropped, and the artifact came out covering MORE than the scope
// said — signed and dated, with nothing anywhere to say so. Refusing is the
// only answer that keeps the boundary claim true.
func TestScopeToParams_RefusesAScopeThatDoesNotValidate(t *testing.T) {
	for _, q := range []string{
		"hostnaem:web-1",                // unknown field
		"environment:nonsense",          // value outside the enum
		"risk >= 70",                    // a band compared against a number
		"depends_on(99):(class:server)", // over the traversal cap
	} {
		_, err := scopeToParams(&scopes.Scope{Query: q})
		if err == nil {
			t.Errorf("%q must be refused, not silently widened", q)
			continue
		}
		var invalid *InvalidScopeQueryError
		if !errors.As(err, &invalid) {
			t.Errorf("%q: got %T, want *InvalidScopeQueryError so the handler can answer 422", q, err)
			continue
		}
		if invalid.Query != q {
			t.Errorf("the error must echo the offending query, got %q", invalid.Query)
		}
	}
}

// TestScopeToParams_AcceptsTheSeededDefaults is the other polarity: the three
// scopes every tenant gets must all translate. An over-strict validator is the
// same bug pointed the other way, and it would break generation for every
// tenant at once.
func TestScopeToParams_AcceptsTheSeededDefaults(t *testing.T) {
	for _, q := range []string{
		"",
		"environment:production",
		"not environment in (development, test) and not (tag:dev or tag:test)",
	} {
		if _, err := scopeToParams(&scopes.Scope{Query: q}); err != nil {
			t.Errorf("seeded scope %q must translate: %v", q, err)
		}
	}
}
