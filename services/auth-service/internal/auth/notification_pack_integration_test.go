package auth

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
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
