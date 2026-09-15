package findings

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func counter() func(string) string {
	n := 0
	return func(prefix string) string {
		n++
		return prefix + strconv.Itoa(n)
	}
}

// OpenSQL is the hand-written twin of the GENERATED OpenQuery: one is spliced
// into a query-language predicate, the other into SQL a reader wrote by hand,
// and they have to select the same rows.
//
// This DERIVES the expected SQL from OpenQuery and compares the whole string,
// rather than checking that both mention the same words. The word-presence
// version passed with the sense inverted — `workflow_status IN ('RESOLVED',
// 'SUPPRESSED')` names every token `NOT IN` does, and selects exactly the rows
// the definition excludes. A guard that survives the inversion of the thing it
// guards is not guarding it.
func TestOpenSQL_IsOpenQueryInSQL(t *testing.T) {
	// OpenQuery's shape, as the generator guarantees it:
	//   finding:(detection_state:<STATE> and workflow_status not in (<A>, <B>))
	shape := regexp.MustCompile(
		`^finding:\(detection_state:(\w+) and workflow_status (not in|in) \(([^)]*)\)\)$`)
	m := shape.FindStringSubmatch(OpenQuery)
	if m == nil {
		t.Fatalf("OpenQuery = %q, which no longer has the shape this test can translate.\n"+
			"If the definition genuinely changed shape, rewrite BOTH this translation and "+
			"OpenSQL — do not relax the pattern, because a pattern that matches anything "+
			"pins nothing.", OpenQuery)
	}
	state, op, values := m[1], m[2], m[3]

	quoted := make([]string, 0, 2)
	for _, v := range strings.Split(values, ",") {
		quoted = append(quoted, "'"+strings.TrimSpace(v)+"'")
	}
	sqlOp := "NOT IN"
	if op == "in" {
		sqlOp = "IN"
	}
	want := "(f.detection_state = '" + state + "'" +
		" AND f.workflow_status " + sqlOp + " (" + strings.Join(quoted, ", ") + "))"

	if got := OpenSQL("f"); got != want {
		t.Errorf("OpenSQL(%q) and OpenQuery are not the same predicate.\n got: %s\nwant: %s\n"+
			"(OpenQuery = %q)", "f", got, want, OpenQuery)
	}

	// The alias is applied to BOTH columns — implied by the comparison above,
	// asserted separately because a half-aliased predicate compiles against a
	// single-table query and only breaks once it is spliced into one with a
	// join, which is where it is actually used.
	sql := OpenSQL("f")
	if !strings.Contains(sql, "f.detection_state") || !strings.Contains(sql, "f.workflow_status") {
		t.Errorf("OpenSQL(%q) = %s; both columns must carry the alias", "f", sql)
	}

	// And it is parenthesised, because it is AND-ed into larger predicates. An
	// unbracketed `a = x AND b NOT IN (…)` under an OR is the classic widening
	// bug — the one that detached tenant scoping in the permissions generator.
	if !strings.HasPrefix(sql, "(") || !strings.HasSuffix(sql, ")") {
		t.Errorf("OpenSQL is not bracketed: %s", sql)
	}
}

// The subject paths are the answer to "which findings are on this asset", and
// every reader that asks has to walk the same set. This pins the SET — a path
// silently dropped is a whole producer's findings vanishing from the asset page
// and from the has_findings count, with no error anywhere.
//
// `relationship` was the sixth and had been missing: `hygiene/orphan_relationship`
// is the only kind written on that subject, and without the path it was
// unreachable from either asset page — the one surface where somebody would fix
// the broken edge.
//
// `key` is the seventh, added when the `crypto` producer started raising
// `pqc_vulnerable` on a key. It is LAST and `relationship` kept its place,
// because the caller's alias numbering follows this order and inserting a path
// anywhere else renumbers every query already generated from it.
func TestAssetSubjects_CoversTheDescendantPaths(t *testing.T) {
	got := AssetSubjects("a", counter())
	want := []string{SubjectAsset, SubjectEndpoint, SubjectCryptoConfiguration, SubjectCertificate,
		SubjectSoftwareInstall, SubjectRelationship, SubjectKey}
	if len(got) != len(want) {
		t.Fatalf("AssetSubjects returned %d paths, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Type != w {
			t.Errorf("path %d is %q, want %q — the order is part of the contract, because the "+
				"caller's alias numbering depends on it", i, got[i].Type, w)
		}
	}

	// The asset path has no id list: the finding's subject_id IS the asset id.
	// Every other path must have one, and must correlate to the asset alias —
	// an uncorrelated subquery would match findings on EVERY tenant's endpoints.
	for _, s := range got {
		if s.Type == SubjectAsset {
			if !s.Self || s.IDs != "" {
				t.Errorf("the asset path must be Self with no id list, got %+v", s)
			}
			continue
		}
		if s.Self {
			t.Errorf("%s must not be Self", s.Type)
		}
		if !strings.Contains(s.IDs, "a.id") {
			t.Errorf("%s id list is not correlated to the asset alias: %s", s.Type, s.IDs)
		}
	}
}

// The alias generator is called once per alias, so two clauses built in one
// query never collide. Reusing an alias makes Postgres resolve a column against
// the wrong table — which is a silently WRONG answer, not an error.
func TestAssetSubjectClause_UsesDistinctAliases(t *testing.T) {
	uniq := counter()
	first := AssetSubjectClause("f", "a", uniq, func(s string) string { return "'" + s + "'" })
	second := AssetSubjectClause("g", "b", uniq, func(s string) string { return "'" + s + "'" })

	for _, alias := range []string{"e1", "ci2", "e3", "c4", "cic5", "ci6", "e7", "si8", "r9",
		"k10", "ik11", "ci12", "e13"} {
		if !strings.Contains(first, " "+alias+" ") && !strings.Contains(first, " "+alias+".") {
			t.Errorf("first clause is missing alias %q: %s", alias, first)
		}
		if strings.Contains(second, " "+alias+" ") {
			t.Errorf("second clause reused alias %q from the first", alias)
		}
	}
}

// The three paths that hang off a crypto configuration resolve the asset
// through ConfigurationAssetSQL, and nowhere else does AssetSubjects spell a
// COALESCE of its own.
//
// This is the shared-findings half of the guard the `crypto` producer carries
// (TestCryptoProducer_ResolvesAssetsThroughTheSharedFragment): the producer's
// coverage rows and this file's reachability must resolve the SAME asset, and
// they did not — a configuration whose endpoint had moved was recorded as
// coverage of its old asset while the finding hung off the new one. One
// function, spliced by both, is what stops that recurring.
//
// Mutation: swap ConfigurationAssetSQL's two arguments (endpoint last) and this
// fails, because the re-derivation stops matching the rendered text.
func TestAssetSubjects_ResolveTheAssetThroughConfigurationAssetSQL(t *testing.T) {
	coalesce := regexp.MustCompile(`COALESCE\(([a-z][a-z0-9_]*)\.asset_id, ([a-z][a-z0-9_]*)\.asset_id\)`)

	// The configuration, certificate and key paths reach the asset through the
	// configuration; endpoint, software install and relationship do not.
	wantFragment := map[string]bool{
		SubjectCryptoConfiguration: true,
		SubjectCertificate:         true,
		SubjectKey:                 true,
	}

	for _, s := range AssetSubjects("a", counter()) {
		matches := coalesce.FindAllStringSubmatch(s.IDs, -1)
		if wantFragment[s.Type] {
			if len(matches) != 1 {
				t.Errorf("%s resolves the asset with %d COALESCE expressions, want exactly the one "+
					"ConfigurationAssetSQL renders: %s", s.Type, len(matches), s.IDs)
				continue
			}
			// Re-derive it from the exported function and diff.
			ciAlias, endpointAlias := matches[0][2], matches[0][1]
			if want := ConfigurationAssetSQL(ciAlias, endpointAlias); want != matches[0][0] {
				t.Errorf("%s resolves the asset as %q, but ConfigurationAssetSQL(%q, %q) is %q",
					s.Type, matches[0][0], ciAlias, endpointAlias, want)
			}
			continue
		}
		if len(matches) != 0 {
			t.Errorf("%s does not hang off a crypto configuration, so it must not COALESCE an asset id: %s",
				s.Type, s.IDs)
		}
	}
}
