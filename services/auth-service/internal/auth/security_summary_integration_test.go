package auth

// Database-integration test for GetTenantSecuritySummary. Skips unless
// TEST_DATABASE_URL is set (see shared/testdb); run with
// `make test-integration-db`.
//
// This needs a real Postgres because the defect was a schema mismatch, not a
// logic error: the security-alerts query referenced retired/bogus audit schema.
// Nothing that stubs the driver would catch that — the SQL only fails against
// a real server. Worse, the swallow-and-continue pattern around the two optional
// audit counts didn't actually recover from statement errors — a bare Postgres
// statement error aborts the whole transaction, so the later tx.Commit() still
// failed even though the primary users-table query above it had already
// succeeded. The query now reads the surviving audit.activity_logs table, and
// each optional count runs inside its own SAVEPOINT so a future error in one
// degrades to 0 without taking down the whole summary.

import (
	"testing"

	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_GetTenantSecuritySummary_RealAuditSchema(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenantID := testdb.NewTenant(t, db)
	newImpersonationTarget(t, db, tenantID) // any real user row; summary short-circuits on zero users

	svc := makeAuthForTest(db)

	summary, err := svc.GetTenantSecuritySummary(tenantID)
	if err != nil {
		t.Fatalf("GetTenantSecuritySummary: %v", err)
	}
	if summary.FailedLogins != 0 {
		t.Errorf("FailedLogins = %d, want 0 (no login-failed events seeded)", summary.FailedLogins)
	}
	if summary.SecurityAlerts != 0 {
		t.Errorf("SecurityAlerts = %d, want 0 (no matching activity_logs rows seeded)", summary.SecurityAlerts)
	}
}

func TestIntegration_GetTenantSecuritySummary_CountsActivityLogSecurityAlerts(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	if _, err := db.Exec(`
		SELECT audit.create_activity_logs_partition(
			EXTRACT(YEAR FROM NOW())::int,
			EXTRACT(MONTH FROM NOW())::int
		)
	`); err != nil {
		t.Fatalf("create current activity-log partition: %v", err)
	}

	tenantID := testdb.NewTenant(t, db)
	userID, email := newImpersonationTarget(t, db, tenantID)
	if _, err := db.Exec(`
		INSERT INTO audit.activity_logs (
			tenant_id, user_id, user_type, user_email, event_type, event_category,
			action, success, occurred_at
		)
		VALUES ($1, $2, 'tenant', $3, 'security.unauthorized', 'authentication',
			'unauthorized access blocked', false, NOW())
	`, tenantID, userID, email); err != nil {
		t.Fatalf("insert security activity log: %v", err)
	}

	svc := makeAuthForTest(db)
	summary, err := svc.GetTenantSecuritySummary(tenantID)
	if err != nil {
		t.Fatalf("GetTenantSecuritySummary: %v", err)
	}
	if summary.SecurityAlerts != 1 {
		t.Errorf("SecurityAlerts = %d, want 1 from audit.activity_logs", summary.SecurityAlerts)
	}
}
