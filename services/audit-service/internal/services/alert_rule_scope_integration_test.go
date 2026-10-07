package services

// The service layer's own guarantee, independent of the handler's check: a
// tenant-scoped UpdateAlertRule / DeleteAlertRule touches only that tenant's
// rows. Global rules (tenant_id IS NULL) are readable by every tenant but
// writable only by a platform caller (tenantID == nil). Skipped unless
// TEST_DATABASE_URL is set.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AlertRuleService_TenantWritesNeverReachGlobalRules(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	dbx := sqlx.NewDb(raw, "postgres")
	svc := NewAlertRuleService(dbx, dbx)
	tenant := testdb.NewTenant(t, raw)
	ctx := context.Background()

	global := uuid.New()
	if _, err := raw.Exec(`INSERT INTO audit.alert_rules (id, tenant_id, name, description, rule_type, is_enabled, severity, conditions, actions, created_by)
		VALUES ($1, NULL, 'platform rule', 'probe', 'threshold', true, 'high', '{}', '{}', $2)`, global, uuid.New()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM audit.alert_rules WHERE id = $1`, global) })

	rule := &models.AlertRule{Name: "HIJACKED", Description: "x", RuleType: "threshold", Severity: "high"}
	if err := svc.UpdateAlertRule(ctx, global, rule, &tenant); err == nil {
		t.Error("a tenant-scoped UpdateAlertRule changed a global rule")
	}
	if err := svc.DeleteAlertRule(ctx, global, &tenant); err == nil {
		t.Error("a tenant-scoped DeleteAlertRule deleted a global rule")
	}
	var name string
	if err := raw.QueryRow(`SELECT name FROM audit.alert_rules WHERE id = $1`, global).Scan(&name); err != nil || name != "platform rule" {
		t.Fatalf("global rule after tenant write attempts: name=%q err=%v", name, err)
	}

	// The platform caller (nil scope) still can.
	rule.Name = "platform renamed"
	if err := svc.UpdateAlertRule(ctx, global, rule, nil); err != nil {
		t.Errorf("platform update of a global rule: %v", err)
	}
	if err := svc.DeleteAlertRule(ctx, global, nil); err != nil {
		t.Errorf("platform delete of a global rule: %v", err)
	}
}
