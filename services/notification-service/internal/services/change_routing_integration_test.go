package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Inventory change notifications through the REAL rule engine and delivery
// path: rules are created with RuleEngine.CreateTenantRule (so change_filter is
// written and read back by the code that ships — a column the SELECT or Scan
// misses drops the rule silently, because a scan error `continue`s), and the
// event is routed with SendNotification into an in-app channel.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

func mkInAppChannel(t *testing.T, db *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_channels (id, tenant_id, channel_name, channel_type, config, enabled)
		VALUES ($1, $2, $3, 'in_app', '{}'::jsonb, true)`, id, tenantID, "In-app "+id.String()[:8]); err != nil {
		t.Fatalf("insert channel: %v", err)
	}
	return id
}

func sendChange(t *testing.T, svc *NotificationService, tenantID uuid.UUID, kind, action, source string) {
	t.Helper()
	if err := svc.SendNotification(context.Background(), &models.SendNotificationRequest{
		TenantID: &tenantID, AlertSource: "inventory-service", AlertType: "object_changed", Severity: "info",
		Title: "Inventory change", Message: kind + " " + action,
		Metadata: map[string]interface{}{"object_kind": kind, "action": action, "source": source, "changed_fields": []interface{}{"status"}},
	}); err != nil {
		t.Fatalf("SendNotification: %v", err)
	}
}

func TestIntegration_ChangeRouting_FilterIsStoredAndEvaluated(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	ctx := context.Background()

	// A catch-all rule on its own channel: it must stay silent for changes.
	catchAllCh := mkInAppChannel(t, db, tenantID)
	if _, err := svc.RuleEngine().CreateTenantRule(ctx, tenantID, &models.CreateRuleRequest{
		RuleName: "Everything", AlertSource: "all", ChannelIDs: []uuid.UUID{catchAllCh}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	ch := mkInAppChannel(t, db, tenantID)
	objectChanged := "object_changed"
	created, err := svc.RuleEngine().CreateTenantRule(ctx, tenantID, &models.CreateRuleRequest{
		RuleName: "Cable updates", AlertSource: "inventory-service", AlertType: &objectChanged,
		ChannelIDs: []uuid.UUID{ch}, Enabled: true,
		ChangeFilter: &models.ChangeFilter{ObjectKinds: []string{"cable"}, Actions: []string{"update"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	rules, err := svc.RuleEngine().GetTenantRules(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var stored *models.TenantNotificationRule
	for i := range rules {
		if rules[i].ID == created.ID {
			stored = &rules[i]
		}
	}
	if stored == nil || stored.ChangeFilter == nil || len(stored.ChangeFilter.ObjectKinds) != 1 || stored.ChangeFilter.ObjectKinds[0] != "cable" {
		t.Fatalf("change_filter did not round-trip: %+v", stored)
	}

	sendChange(t, svc, tenantID, "cable", "update", "ui") // routed
	sendChange(t, svc, tenantID, "cable", "delete", "ui") // wrong action
	sendChange(t, svc, tenantID, "rack", "update", "ui")  // wrong kind
	sendChange(t, svc, tenantID, "cable", "update", "intake:lldp")
	sendChange(t, svc, tenantID, "cable", "update", "sync:netbox")
	if n := countInApp(t, db, tenantID); n != 1 {
		t.Fatalf("in-app deliveries = %d, want exactly 1 (the person's cable update; the catch-all rule and the intake/sync changes stay silent)", n)
	}

	// Opt in to intake through UpdateTenantRule: the intake change now routes,
	// the sync change still does not.
	if _, err := svc.RuleEngine().UpdateTenantRule(ctx, tenantID, created.ID, &models.UpdateRuleRequest{
		ChangeFilter: &models.ChangeFilter{ObjectKinds: []string{"cable"}, Actions: []string{"update"}, IncludeIntake: true},
	}); err != nil {
		t.Fatal(err)
	}
	sendChange(t, svc, tenantID, "cable", "update", "intake:lldp")
	sendChange(t, svc, tenantID, "cable", "update", "sync:netbox")
	if n := countInApp(t, db, tenantID); n != 2 {
		t.Fatalf("in-app deliveries = %d, want 2 after opting in to intake only", n)
	}

	// An update that does not mention the filter keeps it.
	name := "Cable updates (renamed)"
	if _, err := svc.RuleEngine().UpdateTenantRule(ctx, tenantID, created.ID, &models.UpdateRuleRequest{RuleName: &name}); err != nil {
		t.Fatal(err)
	}
	sendChange(t, svc, tenantID, "cable", "update", "intake:lldp")
	if n := countInApp(t, db, tenantID); n != 3 {
		t.Fatalf("in-app deliveries = %d, want 3 — a rename dropped the stored filter", n)
	}
}
