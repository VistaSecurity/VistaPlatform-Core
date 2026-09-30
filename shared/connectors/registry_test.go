package connectors

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
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
	// crypto posture it holds, which is neither a cloud nor a CMDB. `generic`
	// is the kind of the one key (`custom`) that is not any particular system.
	addedSince := []string{"secrets_store", "generic"}

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
		if c.ConfiguredBy != ConfiguredByTenant && c.ConfiguredBy != ConfiguredByPlatformOperator {
			t.Errorf("%s: invalid configured_by %q", c.Key, c.ConfiguredBy)
		}
		switch c.Status {
		case StatusLive, StatusRegistered:
			// Both are keys the database accepts, so both must name the CHECK
			// that accepts them. What separates them is whether any code
			// dispatches — see implementations_test.go.
			if c.SchemaSource == "" {
				t.Errorf("%s: %s connector has no schema_source", c.Key, c.Status)
			}
			// `none` means "no row, no CHECK" — an upload endpoint. A registered
			// connector is one a row MAY carry, so it cannot be rowless.
			if c.SchemaSource == SchemaSourceNone && c.Status != StatusLive {
				t.Errorf("%s: %s connector claims schema_source none — only a live upload endpoint may", c.Key, c.Status)
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
	// netbox was on this list until workstream 2.7 shipped it (asserted live by
	// TestNetBoxIsLiveAndPullOnly); sbom_upload until the upload shipped
	// (asserted live by TestSBOMUploadIsLiveWithNoConnectionRow).
	for _, key := range []string{
		ConnectorJira, ConnectorIntune,
		ConnectorJamf, ConnectorOsquery,
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

// schemaChecks names, per schema_source, the schema.sql CHECK that carries the
// connector keys of that source. Mirrors CHECK_CONSTRAINTS in
// scripts/generate-connectors.mjs; both audit the same five constraints.
var schemaChecks = map[string]string{
	"platform_integrations":        "valid_integration_type",
	"cmdb_sync_profiles":           "valid_cmdb_platform_type",
	"connector_connections":        "valid_connector_key",
	"tenant_notification_channels": "valid_tenant_channel_type",
	"siem_integrations":            "siem_integrations_type_check",
}

// The registry and the hand-maintained CHECK constraints must agree. The
// CHECKs are the write-time enforcement point until a later workstream
// generates them from this file; until then this is what stops the two from
// drifting apart unnoticed. The generator asserts the same thing in --check,
// so a `go test ./...` and a `make audit` both catch it.
func TestEveryLiveOrRegisteredConnectorIsInItsSchemaCheck(t *testing.T) {
	schema := readSchema(t)
	values := map[string]map[string]bool{}
	for source, name := range schemaChecks {
		values[source] = checkConstraintValues(t, schema, name)
	}

	for _, c := range All {
		if c.Status != StatusLive && c.Status != StatusRegistered {
			continue
		}
		if c.SchemaSource == SchemaSourceNone {
			// A live upload endpoint: no row, so no CHECK to be in.
			continue
		}
		vals, ok := values[c.SchemaSource]
		if !ok {
			t.Errorf("%s: unknown schema_source %q", c.Key, c.SchemaSource)
			continue
		}
		if !vals[c.Key] {
			t.Errorf("%s: %s but absent from the %s CHECK (%s)", c.Key, c.Status, c.SchemaSource, schemaChecks[c.SchemaSource])
		}
	}
}

// The other direction: a value in a CHECK with no registry entry is a
// connector nothing knows the shape of — unless the registry says, with a
// reason, that the schema keeps the value while nothing acts on it.
func TestEveryCheckValueHasARegistryEntry(t *testing.T) {
	schema := readSchema(t)
	for source, name := range schemaChecks {
		for value := range checkConstraintValues(t, schema, name) {
			if _, dead := RetiredCheckValues[source][value]; dead {
				continue
			}
			c, ok := Get(value)
			if !ok {
				t.Errorf("%s CHECK (%s) permits %q, which is not in the connector registry and not a retired check value", source, name, value)
				continue
			}
			if c.SchemaSource != source {
				t.Errorf("%s: registry says schema_source %q, but the key is in the %s CHECK (and is not retired there)", value, c.SchemaSource, source)
			}
		}
	}
}

// A retired value is "the schema accepts it, nothing acts on it". So it must
// still BE in its CHECK (otherwise the entry is stale and hides nothing), it
// must carry a reason, and it must not also be a live or registered connector
// for that same CHECK (otherwise the registry both offers and disowns it).
func TestRetiredCheckValuesAreStillInTheSchemaAndNotOffered(t *testing.T) {
	schema := readSchema(t)
	total := 0
	for source, vals := range RetiredCheckValues {
		name, ok := schemaChecks[source]
		if !ok {
			t.Errorf("retired_check_values names unknown schema_source %q", source)
			continue
		}
		inCheck := checkConstraintValues(t, schema, name)
		for value, reason := range vals {
			total++
			if !inCheck[value] {
				t.Errorf("retired %s.%s is no longer in the %s CHECK (%s): the entry is stale, remove it", source, value, source, name)
			}
			if strings.TrimSpace(reason) == "" {
				t.Errorf("retired %s.%s has no reason", source, value)
			}
			if c, ok := Get(value); ok && c.SchemaSource == source &&
				(c.Status == StatusLive || c.Status == StatusRegistered) {
				t.Errorf("%s is both retired for %s and a %s connector there", value, source, c.Status)
			}
		}
	}
	if total == 0 {
		t.Fatal("no retired check values; the test would pass whatever the registry said")
	}
}

// slack and pagerduty are still accepted by the platform_integrations CHECK
// (nothing dispatches on them there since W16), while their delivery lives in
// tenant_notification_channels — so the SAME key is retired in one table and
// live in another. Pinned by name because that split is the whole point of
// the notification entries: the reverse audit would otherwise have to choose
// between "slack is unexplained" and "slack is not delivered".
func TestNotificationAndSIEMKeysLiveWhereTheyAreDelivered(t *testing.T) {
	for _, key := range []string{ConnectorSlack, ConnectorPagerduty} {
		c, _ := Get(key)
		if c.SchemaSource != "tenant_notification_channels" || c.Kind != KindNotification {
			t.Errorf("%s: schema_source %q kind %q, want tenant_notification_channels / notification", key, c.SchemaSource, c.Kind)
		}
		if _, dead := RetiredCheckValues["platform_integrations"][key]; !dead {
			t.Errorf("%s is still accepted by the platform_integrations CHECK and must be retired there", key)
		}
	}
	for _, key := range []string{ConnectorSplunk, ConnectorDatadog} {
		c, _ := Get(key)
		if c.SchemaSource != "siem_integrations" || c.Kind != KindSIEM {
			t.Errorf("%s: schema_source %q kind %q, want siem_integrations / siem", key, c.SchemaSource, c.Kind)
		}
		if _, dead := RetiredCheckValues["platform_integrations"][key]; !dead {
			t.Errorf("%s is still accepted by the platform_integrations CHECK and must be retired there", key)
		}
	}
	// Teams is not supported and must not appear as a connector.
	for _, c := range All {
		if strings.Contains(c.Key, "teams") {
			t.Errorf("%s: Microsoft Teams is not supported and must stay absent from the registry", c.Key)
		}
	}
	// email, webhook and in_app are what actually delivers besides Slack and
	// PagerDuty; they must be live notification sinks.
	for _, key := range []string{ConnectorEmail, ConnectorWebhook, ConnectorInApp} {
		c, ok := Get(key)
		if !ok || c.Status != StatusLive || c.Kind != KindNotification || len(c.ProducesClasses) != 0 {
			t.Errorf("%s should be a live notification sink, got %+v", key, c)
		}
	}
	// sms is accepted by the tenant channel CHECK and delivers nothing.
	if _, ok := Get("sms"); ok {
		t.Error("sms is not a connector: notification-service refuses every SMS permanently")
	}
	if _, dead := RetiredCheckValues["tenant_notification_channels"]["sms"]; !dead {
		t.Error("sms should be retired in tenant_notification_channels")
	}
}

// SIEM export forwards the audit stream of the whole deployment: platform-
// global, Enterprise, configured by the platform operator and never by a
// tenant. Every siem connector must say so, and nothing else may.
func TestSIEMConnectorsAreOperatorConfiguredAndGated(t *testing.T) {
	siem := ByKind(KindSIEM)
	if len(siem) != 4 {
		t.Fatalf("expected splunk, datadog, elastic and generic_webhook, got %d siem connectors", len(siem))
	}
	for _, c := range siem {
		if c.ConfiguredBy != ConfiguredByPlatformOperator {
			t.Errorf("%s: configured_by %q, want platform_operator — a tenant cannot add a SIEM destination", c.Key, c.ConfiguredBy)
		}
		if c.Feature != "siem_export" {
			t.Errorf("%s: feature %q, want siem_export", c.Key, c.Feature)
		}
		if c.SchemaSource != "siem_integrations" {
			t.Errorf("%s: schema_source %q, want siem_integrations", c.Key, c.SchemaSource)
		}
		if c.Direction != DirectionPush {
			t.Errorf("%s: direction %q, want push", c.Key, c.Direction)
		}
	}
	for _, c := range All {
		if c.Kind != KindSIEM && c.ConfiguredBy == ConfiguredByPlatformOperator {
			t.Errorf("%s: only SIEM export is operator-configured today; is %s really?", c.Key, c.Key)
		}
	}
}

// produces_classes must name classes that exist. The registry used to claim
// `serverless_function` for all three clouds on the strength of a taxonomy that
// has the class, when no collector produced it; a class key that is not even in
// the taxonomy would be the cheaper mistake to catch.
func TestProducedClassesAreRealAssetClasses(t *testing.T) {
	checked := 0
	for _, c := range All {
		for _, cls := range c.ProducesClasses {
			checked++
			if _, ok := assetclass.Get(cls); !ok {
				t.Errorf("%s: produces_classes names %q, which is not an asset class (standards/asset-classes.yaml)", c.Key, cls)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no produces_classes checked; the test would pass whatever the registry said")
	}
}

// The cloud connectors used to claim `serverless_function` although no
// collector for Lambda, Azure Functions or Cloud Functions exists (review M35).
func TestNoCloudConnectorClaimsServerlessFunctions(t *testing.T) {
	for _, c := range ByKind(KindCloud) {
		if slices.Contains(c.ProducesClasses, "serverless_function") {
			t.Errorf("%s claims serverless_function; no collector produces it", c.Key)
		}
		for _, want := range []string{"compute_instance", "virtual_network", "subnet", "cloud_load_balancer", "key_store", "object_storage", "managed_database"} {
			if !slices.Contains(c.ProducesClasses, want) {
				t.Errorf("%s does not claim %s, which every cloud collector produces", c.Key, want)
			}
		}
	}
}

// `none` names no CHECK; it is for a live upload endpoint only. sbom_upload is
// the one such connector.
func TestSBOMUploadIsLiveWithNoConnectionRow(t *testing.T) {
	c, ok := Get(ConnectorSBOMUpload)
	if !ok {
		t.Fatal("sbom_upload is missing")
	}
	if c.Status != StatusLive || c.SchemaSource != SchemaSourceNone {
		t.Errorf("sbom_upload: status %q schema_source %q, want live / none", c.Status, c.SchemaSource)
	}
	if !slices.Equal(c.ProducesClasses, []string{"application"}) {
		t.Errorf("sbom_upload produces %v; with no target asset it creates an application asset, and nothing else", c.ProducesClasses)
	}
	if c.Feature != "" {
		t.Errorf("sbom_upload is Core, got feature %q", c.Feature)
	}
	for _, other := range All {
		if other.Key != ConnectorSBOMUpload && other.SchemaSource == SchemaSourceNone {
			t.Errorf("%s claims schema_source none; only an upload endpoint has no row", other.Key)
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
