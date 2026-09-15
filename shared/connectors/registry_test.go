package connectors

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var validDirections = map[string]bool{
	DirectionPull: true,
	DirectionPush: true,
	DirectionBoth: true,
}

func TestRegistryIsNotEmpty(t *testing.T) {
	if len(All) == 0 {
		t.Fatal("no connectors in the generated registry")
	}
	if len(Kinds) == 0 {
		t.Fatal("no kinds in the generated registry")
	}
}

// The eight kinds ADR-0004 D5 names, plus the ones added since. Written out by
// hand so a kind cannot appear in the vocabulary without the addition being
// made twice and named here.
func TestKindVocabularyMatchesTheADR(t *testing.T) {
	fromADR := []string{
		"cloud", "cmdb", "network_source_of_truth", "itsm",
		"siem", "notification", "edr_mdm", "sbom_source",
	}
	// Added after ADR-0004 D5: a vault or secrets manager is read for the
	// crypto posture it holds, which is neither a cloud nor a CMDB.
	addedSince := []string{"secrets_store"}

	want := append(append([]string{}, fromADR...), addedSince...)
	for _, k := range fromADR {
		if !slices.Contains(Kinds, k) {
			t.Errorf("kind %q from ADR-0004 D5 is missing", k)
		}
	}
	for _, k := range addedSince {
		if !slices.Contains(Kinds, k) {
			t.Errorf("kind %q is missing", k)
		}
	}
	if len(Kinds) != len(want) {
		t.Errorf("registry declares %d kinds, this test names %d: %v", len(Kinds), len(want), Kinds)
	}
}

func TestEveryConnectorIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All {
		if seen[c.Key] {
			t.Errorf("duplicate connector key %q", c.Key)
		}
		seen[c.Key] = true

		if c.Label == "" {
			t.Errorf("%s: no label", c.Key)
		}
		if c.Description == "" {
			t.Errorf("%s: no description", c.Key)
		}
		if !slices.Contains(Kinds, c.Kind) {
			t.Errorf("%s: kind %q is not in the vocabulary", c.Key, c.Kind)
		}
		if !validDirections[c.Direction] {
			t.Errorf("%s: invalid direction %q", c.Key, c.Direction)
		}
		switch c.Status {
		case StatusLive, StatusRegistered:
			// Both are keys the database accepts, so both must name the CHECK
			// that accepts them. What separates them is whether any code
			// dispatches — see implementations_test.go.
			if c.SchemaSource == "" {
				t.Errorf("%s: %s connector has no schema_source", c.Key, c.Status)
			}
		case StatusPlanned:
			if c.SchemaSource != "" {
				t.Errorf("%s: planned connector declares a schema_source", c.Key)
			}
		default:
			t.Errorf("%s: invalid status %q", c.Key, c.Status)
		}
	}
}

// A push-only connector is a sink. Claiming to produce assets in a direction
// it never reads would mislead anything building an intake map from this
// registry.
func TestPushOnlyConnectorsProduceNoClasses(t *testing.T) {
	for _, c := range All {
		if c.Direction == DirectionPush && len(c.ProducesClasses) > 0 {
			t.Errorf("%s: push-only but claims to produce %v", c.Key, c.ProducesClasses)
		}
	}
}

func TestGetAndIsLive(t *testing.T) {
	c, ok := Get(ConnectorAWS)
	if !ok {
		t.Fatal("aws is missing from the registry")
	}
	if c.Kind != KindCloud {
		t.Errorf("aws kind is %q, want cloud", c.Kind)
	}
	if !IsLive(ConnectorAWS) {
		t.Error("aws should be live")
	}
	if IsLive(ConnectorJira) {
		t.Error("jira is planned, not live — IsLive must not report it dispatchable")
	}
	if IsLive(ConnectorGithub) {
		t.Error("github is registered, not live — the schema accepts the key but nothing collects it")
	}
	if _, ok := Get("carrier_pigeon"); ok {
		t.Error("Get accepted an unregistered connector")
	}
	if IsLive("carrier_pigeon") {
		t.Error("IsLive accepted an unregistered connector")
	}
}

func TestPlannedConnectorsFromTheADRArePresent(t *testing.T) {
	// netbox was on this list until workstream 2.7 shipped it; it is now
	// asserted live by TestNetBoxIsLiveAndPullOnly.
	for _, key := range []string{
		ConnectorJira, ConnectorIntune,
		ConnectorJamf, ConnectorOsquery, ConnectorSBOMUpload,
	} {
		c, ok := Get(key)
		if !ok {
			t.Errorf("planned connector %q is missing", key)
			continue
		}
		if c.Status != StatusPlanned {
			t.Errorf("%s: status is %q, want planned", key, c.Status)
		}
	}
}

func TestByKind(t *testing.T) {
	clouds := ByKind(KindCloud)
	if len(clouds) != 3 {
		t.Errorf("expected 3 cloud connectors (aws, azure, gcp), got %d", len(clouds))
	}
	for _, c := range clouds {
		if c.Kind != KindCloud {
			t.Errorf("ByKind(cloud) returned %s with kind %q", c.Key, c.Kind)
		}
	}
	if got := ByKind("not_a_kind"); got != nil {
		t.Errorf("ByKind of an unknown kind returned %v, want nil", got)
	}
}

var checkValuePattern = regexp.MustCompile(`'([^']+)'::character varying`)

// The registry and the two hand-maintained CHECK constraints must agree. The
// CHECKs are the write-time enforcement point until a later workstream
// generates them from this file; until then this is what stops the two from
// drifting apart unnoticed. The generator asserts the same thing in --check,
// so a `go test ./...` and a `make audit` both catch it.
func TestEveryLiveOrRegisteredConnectorIsInItsSchemaCheck(t *testing.T) {
	schema := readSchema(t)
	constraints := map[string]string{
		"platform_integrations": "valid_integration_type",
		"cmdb_sync_profiles":    "valid_cmdb_platform_type",
		"connector_connections": "valid_connector_key",
	}
	values := map[string]map[string]bool{}
	for source, name := range constraints {
		values[source] = checkConstraintValues(t, schema, name)
	}

	for _, c := range All {
		if c.Status != StatusLive && c.Status != StatusRegistered {
			continue
		}
		vals, ok := values[c.SchemaSource]
		if !ok {
			t.Errorf("%s: unknown schema_source %q", c.Key, c.SchemaSource)
			continue
		}
		if !vals[c.Key] {
			t.Errorf("%s: %s but absent from the %s CHECK (%s)", c.Key, c.Status, c.SchemaSource, constraints[c.SchemaSource])
		}
	}
}

// The other direction: a value in a CHECK with no registry entry is a
// connector nothing knows the shape of.
func TestEveryCheckValueHasARegistryEntry(t *testing.T) {
	schema := readSchema(t)
	for source, name := range map[string]string{
		"platform_integrations": "valid_integration_type",
		"cmdb_sync_profiles":    "valid_cmdb_platform_type",
		"connector_connections": "valid_connector_key",
	} {
		for value := range checkConstraintValues(t, schema, name) {
			c, ok := Get(value)
			if !ok {
				t.Errorf("%s CHECK (%s) permits %q, which is not in the connector registry", source, name, value)
				continue
			}
			if c.SchemaSource != source {
				t.Errorf("%s: registry says schema_source %q, but the key is in the %s CHECK", value, c.SchemaSource, source)
			}
		}
	}
}

func readSchema(t *testing.T) string {
	t.Helper()
	p := filepath.Join(repoRoot(t), "scripts", "database", "schema.sql")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("schema.sql not readable (%v)", err)
	}
	return string(b)
}

func checkConstraintValues(t *testing.T, schema, constraint string) map[string]bool {
	t.Helper()
	marker := "CONSTRAINT " + constraint + " CHECK"
	start := strings.Index(schema, marker)
	if start == -1 {
		t.Fatalf("constraint %s not found in schema.sql; if it was renamed, update this test rather than deleting it", constraint)
	}
	// Balanced-paren walk, so a CHECK that grows a nested expression cannot
	// silently truncate the extracted list and make this assert nothing.
	open := strings.Index(schema[start:], "(")
	if open == -1 {
		t.Fatalf("constraint %s: no opening parenthesis", constraint)
	}
	open += start
	depth, end := 0, -1
	for i := open; i < len(schema); i++ {
		switch schema[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end != -1 {
			break
		}
	}
	if end == -1 {
		t.Fatalf("constraint %s: unbalanced parentheses", constraint)
	}
	out := map[string]bool{}
	for _, m := range checkValuePattern.FindAllStringSubmatch(schema[open:end+1], -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatalf("constraint %s: extracted no values — the CHECK's shape changed and this test would pass vacuously", constraint)
	}
	return out
}

// The drift audit `make audit` runs, executed here too so `go test ./...`
// catches a stale generated file without waiting for CI.
func TestGeneratedFileMatchesYAML(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "generate-connectors.mjs")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("generator not present (%v) — public tree or partial checkout", err)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	cmd := exec.Command("node", script, "--check")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generator --check failed: %v\n%s", err, out)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("repo root (go.work) not found")
		}
		dir = parent
	}
}
