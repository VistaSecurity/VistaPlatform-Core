package auth

// Database-integration test for GetTenantSecuritySummary. Skips unless
// TEST_DATABASE_URL is set (see shared/testdb); run with
// `make test-integration-db`.
//
// This needs a real Postgres because the defect was a schema mismatch, not a
// logic error: the security-alerts query referenced audit.audit_logs.severity,
// a column that has never existed on that table. Every call 500'd — reported
// live on a dev cluster as a recurring "pq: Could not complete operation in a failed
// transaction" error, polled every ~60s by an internal caller. Nothing that
// stubs the driver would catch a bad column reference; it only fails against
// a real server. Worse, the swallow-and-continue pattern around the two
// optional audit counts didn't actually recover from that error — a bare
// Postgres statement error aborts the whole transaction, so the later
// tx.Commit() still failed even though the primary users-table query above it
// had already succeeded. Both are fixed: the bogus column reference is gone,
// and each optional count now runs inside its own SAVEPOINT so a future error
// in one degrades to 0 without taking down the whole summary.

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
		t.Errorf("SecurityAlerts = %d, want 0 (no matching audit_logs rows seeded)", summary.SecurityAlerts)
	}
}
