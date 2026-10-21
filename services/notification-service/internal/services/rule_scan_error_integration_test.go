package services

// A tenant_notification_rules row the engine cannot read (here: a NULL
// priority, which the model scans into a plain int — the shape a schema drift
// takes) is skipped, as before, but now says so with the rule's id; the
// readable rules still route. Skipped unless TEST_DATABASE_URL is set.
//
// Mutation: delete the logRuleScanError call in GetTenantRulesForAlert (or
// GetTenantRules) → red.

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RuleEngine_LogsARuleRowItCannotRead(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	insert := func(name, priority string) uuid.UUID {
		var id uuid.UUID
		testdb.RetryTransient(t, func() error {
			return db.QueryRow(`
				INSERT INTO tenant_notification_rules (tenant_id, rule_name, alert_source, alert_type, channel_ids, enabled, priority)
				VALUES ($1, $2, 'all', 'object_changed', ARRAY[gen_random_uuid()], true, `+priority+`) RETURNING id`,
				tenant, name).Scan(&id)
		})
		return id
	}
	good := insert("Readable", "0")
	bad := insert("Drifted", "NULL")

	var logs bytes.Buffer
	re := &RuleEngine{db: sqlx.NewDb(db, "postgres"), logger: log.New(&logs, "[RuleEngine] ", 0)}

	rules, err := re.GetTenantRulesForAlert(context.Background(), tenant, "inventory-service", "object_changed", "info", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != good {
		t.Fatalf("routing rules = %+v, want only the readable one", rules)
	}
	if !strings.Contains(logs.String(), bad.String()) || !strings.Contains(logs.String(), "tenant_notification_rules") {
		t.Fatalf("the unreadable rule %s was skipped without a word; log:\n%s", bad, logs.String())
	}

	logs.Reset()
	all, err := re.GetTenantRules(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || !strings.Contains(logs.String(), bad.String()) {
		t.Fatalf("GetTenantRules: %d rules, log:\n%s", len(all), logs.String())
	}
}

// The platform rule reader has the same skip, and now the same log. The rows
// are platform-wide, so they carry an alert type no other test routes and are
// removed at the end.
func TestIntegration_RuleEngine_LogsAPlatformRuleRowItCannotRead(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	alertType := "scan_error_probe_" + uuid.NewString()[:8]
	var bad uuid.UUID
	testdb.RetryTransient(t, func() error {
		return db.QueryRow(`
			INSERT INTO platform_notification_rules (rule_name, alert_source, alert_type, channel_ids, enabled, priority)
			VALUES ('Drifted', 'all', $1, ARRAY[gen_random_uuid()], true, NULL) RETURNING id`, alertType).Scan(&bad)
	})
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_notification_rules WHERE id = $1`, bad) })

	var logs bytes.Buffer
	re := &RuleEngine{db: sqlx.NewDb(db, "postgres"), logger: log.New(&logs, "[RuleEngine] ", 0)}
	rules, err := re.GetPlatformRulesForAlert("monitoring-service", alertType, "high")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == bad {
			t.Fatal("the unreadable rule was returned")
		}
	}
	if !strings.Contains(logs.String(), bad.String()) || !strings.Contains(logs.String(), "platform_notification_rules") {
		t.Fatalf("the unreadable platform rule %s was skipped without a word; log:\n%s", bad, logs.String())
	}
}
