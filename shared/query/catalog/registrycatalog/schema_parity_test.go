package registrycatalog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The closed value sets in enums.go are copies of what the database declares.
// This file is what makes a copy safe.
//
// Without it the copies are a second opinion, and the drift is silent in both
// directions: a value added to the schema and not here validates as
// `unknown_value` for a row the column happily holds, and a value here the
// column cannot hold validates and then returns no rows forever. Neither
// produces an error anywhere — the query just answers wrongly.
//
// It is a TEST rather than a build step on purpose. A shared library cannot
// depend on a file four directories above the package being present at runtime,
// and a catalogue that failed to construct when a deployment shipped without
// the SQL would be worse than a copy with a test.

func schemaPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "..", "scripts", "database", "schema.sql")
}

func readSchema(t *testing.T) string {
	t.Helper()
	path := schemaPath(t)
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v (the schema is the source of truth for these value sets; "+
			"if it moved, repoint this test rather than deleting it)", path, err)
	}
	return string(body)
}

// TestEnumsMatchSchema is the parity check, over both kinds of closed set the
// schema uses: a Postgres ENUM type and the ARRAY of a CHECK constraint.
func TestEnumsMatchSchema(t *testing.T) {
	body := readSchema(t)

	t.Run("enum types", func(t *testing.T) {
		for _, tc := range []struct {
			typeName string
			want     []string
		}{
			{"environment_type", environmentValues},
			{"protocol_type", protocolValues},
		} {
			got := enumTypeValues(t, body, tc.typeName)
			assertSameSet(t, "public."+tc.typeName, got, tc.want)
		}
	})

	t.Run("check constraints", func(t *testing.T) {
		for _, tc := range []struct {
			constraint string
			want       []string
		}{
			{"assets_asset_status_check", assetStatusValues},
			{"assets_identity_status_check", identityStatusValues},
			{"assets_asset_ownership_check", assetOwnershipValues},
			{"assets_stale_status_check", staleStatusValues},
			{"assets_class_source_kind_check", classSourceKindValues},
			{"asset_endpoints_source_kind_check", sourceKindValues},
			{"asset_identifiers_source_kind_check", sourceKindValues},
			{"asset_relationships_source_kind_check", sourceKindValues},
			{"software_installs_source_kind_check", sourceKindValues},
			{"findings_source_kind_check", sourceKindValues},
			{"asset_endpoints_transport_check", endpointTransportValues},
			{"asset_endpoints_status_check", endpointStatusValues},
			{"software_installs_status_check", softwareInstallStatusValues},
			{"asset_relationships_status_check", relationshipStatusValues},
			{"findings_detection_state_check", findingDetectionStateValues},
			{"findings_workflow_status_check", findingWorkflowStatusValues},
			{"valid_certificate_state", certificateStateValues},
			// The observation target has no table, but `network.type` is not
			// computed: the classifier copies the matching segment's column
			// through, so the segment's CHECK IS its range. Pinning it here is
			// what would have caught it being written as {private, public}.
			{"network_segments_network_type_check", observationNetworkTypeValues},
		} {
			got := checkConstraintValues(t, body, tc.constraint)
			assertSameSet(t, tc.constraint, got, tc.want)
		}
	})
}

// TestSchemaParityParserWorks is the guard on the guard.
//
// Every assertion above is of the form "what the parser found equals what the
// catalogue holds". A parser that found NOTHING would make every one of them
// compare two empty sets and pass — the check that cannot fail. These two
// assertions are the ones that would notice.
func TestSchemaParityParserWorks(t *testing.T) {
	body := readSchema(t)

	if got := enumTypeValues(t, body, "protocol_type"); len(got) < 15 {
		t.Errorf("parsed %d protocol_type values (%v); the enum has 21 — the PARSER broke, "+
			"not the schema", len(got), got)
	}
	if got := checkConstraintValues(t, body, "assets_asset_status_check"); len(got) != 4 {
		t.Errorf("parsed %d asset_status values (%v), want 4 — the PARSER broke", len(got), got)
	}

	// And the negative: a name that is not there must be reported, not
	// silently treated as an empty set.
	if _, err := findEnumType(body, "no_such_type"); err == nil {
		t.Error("a missing enum type should be an error, not an empty value list")
	}
	if _, err := findCheckConstraint(body, "no_such_constraint"); err == nil {
		t.Error("a missing constraint should be an error, not an empty value list")
	}
}

// TestSchemaParityCatchesDrift mutation-tests the comparison itself: feed it a
// value set with one value added, one removed and one renamed, and require each
// to be reported. Without this, assertSameSet could be comparing lengths, or
// nothing at all.
func TestSchemaParityCatchesDrift(t *testing.T) {
	base := []string{"a", "b", "c"}
	for _, tc := range []struct {
		name string
		got  []string
	}{
		{"added", []string{"a", "b", "c", "d"}},
		{"removed", []string{"a", "b"}},
		{"renamed", []string{"a", "b", "z"}},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var probe testing.T
			assertSameSet(&probe, "probe", tc.got, base)
			if !probe.Failed() {
				t.Errorf("drift %q was not reported: %v vs %v", tc.name, tc.got, base)
			}
		})
	}
	// The other polarity: identical sets, in a different order, must pass. The
	// schema's declaration order is not the catalogue's, and an over-strict
	// comparison here would fail on a reordering that changes nothing.
	var probe testing.T
	assertSameSet(&probe, "probe", []string{"c", "a", "b"}, base)
	if probe.Failed() {
		t.Error("the same values in a different order must not be reported as drift")
	}
}

// ---------------------------------------------------------------- parsing --

var enumTypeRe = regexp.MustCompile(`(?s)CREATE TYPE public\.(\w+) AS ENUM\s*\((.*?)\)\s*;`)

func findEnumType(body, typeName string) (string, error) {
	for _, m := range enumTypeRe.FindAllStringSubmatch(body, -1) {
		if m[1] == typeName {
			return m[2], nil
		}
	}
	return "", fmt.Errorf("no `CREATE TYPE public.%s AS ENUM (...)` in the schema", typeName)
}

func enumTypeValues(t *testing.T, body, typeName string) []string {
	t.Helper()
	inner, err := findEnumType(body, typeName)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return sqlStringLiterals(stripSQLComments(inner))
}

// findCheckConstraint returns the body of a named CHECK, balancing parentheses
// rather than matching to the first `)`. The constraints here nest three deep
// (`CHECK ((x)::text = ANY ((ARRAY[...])::text[]))`), so a lazy regex stops in
// the middle of one and silently returns a prefix.
func findCheckConstraint(body, name string) (string, error) {
	// Whitespace-tolerant, because a named constraint that is wide enough to
	// wrap puts a newline between its name and CHECK — which a fixed
	// "CONSTRAINT <name> CHECK" search does not find, and a parity row that
	// cannot find its constraint reads as "not in the schema" rather than as a
	// parser limitation. assets_identity_status_check is written that way.
	loc := regexp.MustCompile(`CONSTRAINT\s+` + regexp.QuoteMeta(name) + `\s+CHECK`).FindStringIndex(body)
	if loc == nil {
		return "", fmt.Errorf("no `CONSTRAINT %s CHECK (...)` in the schema", name)
	}
	idx := loc[0]
	open := strings.Index(body[idx:], "(")
	if open < 0 {
		return "", fmt.Errorf("constraint %s has no parenthesised body", name)
	}
	start := idx + open
	depth := 0
	for i := start; i < len(body); i++ {
		switch body[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return body[start+1 : i], nil
			}
		}
	}
	return "", fmt.Errorf("constraint %s has an unbalanced body", name)
}

func checkConstraintValues(t *testing.T, body, name string) []string {
	t.Helper()
	inner, err := findCheckConstraint(body, name)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return sqlStringLiterals(stripSQLComments(inner))
}

// stripSQLComments removes `-- …` to end of line. The protocol_type enum
// carries comments BETWEEN values, and leaving them in glues a comment to the
// value that follows it.
func stripSQLComments(s string) string {
	out := make([]string, 0, 8)
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

var sqlLiteralRe = regexp.MustCompile(`'([^']*)'`)

// sqlStringLiterals pulls every single-quoted literal out, in order, without
// repeats. A CHECK names its column's values once each; a repeat would mean the
// expression mentions something else (a default, a cast target) and is a signal
// worth not silently folding away.
func sqlStringLiterals(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range sqlLiteralRe.FindAllStringSubmatch(s, -1) {
		v := m[1]
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// assertSameSet compares two value sets as SETS, naming what is missing on each
// side. Order is not compared: the schema's declaration order is not the
// catalogue's, and nothing in the language depends on it.
func assertSameSet(t *testing.T, what string, got, want []string) {
	t.Helper()
	inGot := map[string]bool{}
	for _, v := range got {
		inGot[v] = true
	}
	inWant := map[string]bool{}
	for _, v := range want {
		inWant[v] = true
	}

	var missing, extra []string
	for v := range inGot {
		if !inWant[v] {
			missing = append(missing, v)
		}
	}
	for v := range inWant {
		if !inGot[v] {
			extra = append(extra, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("%s: the schema has %v and the catalogue does not — a query for one of these "+
			"would report unknown_value for a row the column holds", what, missing)
	}
	if len(extra) > 0 {
		t.Errorf("%s: the catalogue has %v and the schema does not — a query for one of these "+
			"would validate and then match nothing, forever", what, extra)
	}
}
