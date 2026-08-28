package auth

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The default notification pack is the ONLY thing standing between a new tenant
// and total silence: notification-service's rule engine matches an alert against
// tenant_notification_rules, and a severity that matches no rule is recorded as
// "sent" with zero channels_used and delivered nowhere. Nothing in schema.sql or
// seed.sql creates rules, so if the pack misses a severity band, every alert in
// that band is dropped for every tenant, permanently and without an error.
//
// asset_limit_approaching opens at severity "info" (the 80% rung in
// standards/alert-registry.yaml), NormalizeSeverity degrades any unrecognized
// producer severity to "info", and billing notifications are emitted at "info" —
// so "info" is not a hypothetical band.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

// canonicalSeverities is notification-service's normalized severity enum
// (NormalizeSeverity + the notification_history valid_notification_severity
// CHECK). Every one of these must be routed somewhere by the seeded pack.
var canonicalSeverities = []string{"critical", "high", "medium", "low", "info"}

// TestIntegration_SeedDefaultNotificationPack_RoutesEverySeverity asserts the
// seeded pack leaves no severity band unrouted. Mutation check: drop "info" from
// the "Default activity feed" rule in seedDefaultNotificationPack and this fails.
func TestIntegration_SeedDefaultNotificationPack_RoutesEverySeverity(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)

	a := &AuthService{db: db, bypassDB: db}
	if err := a.seedDefaultNotificationPack(tenantID); err != nil {
		t.Fatalf("seedDefaultNotificationPack: %v", err)
	}

	for _, sev := range canonicalSeverities {
		// Mirrors RuleEngine.GetTenantRulesForAlert: enabled rules whose
		// severity_filter is empty (match-all) or contains this severity, and
		// which name at least one channel.
		var n int
		err := db.QueryRow(`
			SELECT COUNT(*)
			FROM tenant_notification_rules
			WHERE tenant_id = $1
			  AND enabled = true
			  AND cardinality(channel_ids) > 0
			  AND (severity_filter IS NULL
			       OR cardinality(severity_filter) = 0
			       OR $2 = ANY(severity_filter))
		`, tenantID, sev).Scan(&n)
		if err != nil {
			t.Fatalf("count rules for severity %q: %v", sev, err)
		}
		if n == 0 {
			t.Errorf("severity %q is routed by NO seeded rule — every %s alert is silently dropped for a new tenant", sev, sev)
		}
	}
}

// TestIntegration_SeedDefaultNotificationPack_ChannelsAreReferenced guards the
// other half of the same failure: a rule that names a channel id no channel row
// carries routes to nothing. channel_ids is a bare uuid[] with no FK, so nothing
// in the database catches a typo here.
func TestIntegration_SeedDefaultNotificationPack_ChannelsAreReferenced(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)

	a := &AuthService{db: db, bypassDB: db}
	if err := a.seedDefaultNotificationPack(tenantID); err != nil {
		t.Fatalf("seedDefaultNotificationPack: %v", err)
	}

	rows, err := db.Query(`
		SELECT r.rule_name, cid
		FROM tenant_notification_rules r, unnest(r.channel_ids) AS cid
		WHERE r.tenant_id = $1
	`, tenantID)
	if err != nil {
		t.Fatalf("query rule channels: %v", err)
	}
	defer func() { _ = rows.Close() }()

	seen := 0
	for rows.Next() {
		var ruleName string
		var channelID uuid.UUID
		if err := rows.Scan(&ruleName, &channelID); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen++
		var enabled bool
		err := db.QueryRow(`SELECT enabled FROM tenant_notification_channels WHERE id = $1 AND tenant_id = $2`,
			channelID, tenantID).Scan(&enabled)
		if err == sql.ErrNoRows {
			t.Errorf("rule %q references channel %s which does not exist", ruleName, channelID)
			continue
		}
		if err != nil {
			t.Fatalf("lookup channel %s: %v", channelID, err)
		}
		if !enabled {
			t.Errorf("rule %q references disabled channel %s", ruleName, channelID)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if seen == 0 {
		t.Fatal("seeded pack produced no rule→channel references at all")
	}
}

// TestIntegration_SchemaBackfill_DefaultNotificationPackInfoSeverity covers the
// upgrade path for tenants that were created before seedDefaultNotificationPack
// included "info" in the Default activity feed rule. A fresh-tenant test cannot
// catch this: existing rows keep their old severity_filter until schema.sql's
// backfill repairs exactly the shipped default shape.
func TestIntegration_SchemaBackfill_DefaultNotificationPackInfoSeverity(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	legacyTenant := testdb.NewTenant(t, db)
	customTenant := testdb.NewTenant(t, db)
	renamedTenant := testdb.NewTenant(t, db)

	legacyChannel := insertInAppChannel(t, db, legacyTenant, "Legacy in-app")
	customChannel := insertInAppChannel(t, db, customTenant, "Custom in-app")
	renamedChannel := insertInAppChannel(t, db, renamedTenant, "Renamed in-app")

	insertNotificationRule(t, db, legacyTenant, legacyChannel, "Default activity feed", []string{"medium", "low"})
	insertNotificationRule(t, db, customTenant, customChannel, "Default activity feed", []string{"low"})
	insertNotificationRule(t, db, renamedTenant, renamedChannel, "My activity feed", []string{"medium", "low"})

	applySchemaOnly(t, db)
	applySchemaOnly(t, db) // idempotency: the repaired row must not keep changing.

	assertRuleSeverities(t, db, legacyTenant, "Default activity feed", []string{"medium", "low", "info"})
	assertRuleSeverities(t, db, customTenant, "Default activity feed", []string{"low"})
	assertRuleSeverities(t, db, renamedTenant, "My activity feed", []string{"medium", "low"})
}

func applySchemaOnly(t *testing.T, db *sql.DB) {
	t.Helper()
	schemaPath := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql")
	body, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("schema.sql failed to re-apply over tenant_notification_rules data: %v", err)
	}
}

func insertInAppChannel(t *testing.T, db *sql.DB, tenantID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	channelID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_channels (id, tenant_id, channel_name, channel_type, config, enabled)
		VALUES ($1, $2, $3, 'in_app', '{}'::jsonb, true)`,
		channelID, tenantID, name); err != nil {
		t.Fatalf("insert notification channel: %v", err)
	}
	return channelID
}

func insertNotificationRule(t *testing.T, db *sql.DB, tenantID, channelID uuid.UUID, name string, severities []string) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_rules
			(tenant_id, rule_name, alert_source, channel_ids, severity_filter, frequency, enabled, priority)
		VALUES ($1, $2, 'all', ARRAY[$3::uuid], $4::varchar[], 'immediate', true, 50)`,
		tenantID, name, channelID, pqStringArray(severities)); err != nil {
		t.Fatalf("insert notification rule %q: %v", name, err)
	}
}

func assertRuleSeverities(t *testing.T, db *sql.DB, tenantID uuid.UUID, ruleName string, want []string) {
	t.Helper()
	var got pq.StringArray
	if err := db.QueryRow(`
		SELECT severity_filter FROM tenant_notification_rules
		WHERE tenant_id = $1 AND rule_name = $2`,
		tenantID, ruleName).Scan(&got); err != nil {
		t.Fatalf("read severity_filter for %q: %v", ruleName, err)
	}
	if len(got) != len(want) {
		t.Fatalf("%s severity_filter = %v, want %v", ruleName, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s severity_filter = %v, want %v", ruleName, got, want)
		}
	}
}

func pqStringArray(vals []string) pq.StringArray {
	return pq.StringArray(vals)
}
