package services

// tenant_frameworks.description is NULLABLE (scripts/database/schema.sql),
// but models.TenantFramework scans it into a plain Go string. A NULL fails
// that row's Scan outright, which takes down the WHOLE read (sqlx.Select
// aborts the entire scan on one row's error for ListTenantFrameworks; a
// single-row Get fails outright for GetTenantFramework) — the same defect
// framework_readers_null_columns_integration_test.go fixed for
// platform_frameworks.{description,organization} readers in, on the
// tenant_frameworks (custom policies) sibling that was left standing.
//
// No application code path writes a NULL description today —
// CreateFramework/UpdateFramework in ee/policyauthoring bind
// models.TenantFrameworkInput.Description, a plain (never-nil) Go string, so
// an omitted description round-trips as "" — but the column itself allows
// NULL, and a row can carry one from before that validation existed, from a
// direct SQL fix, or from a future write path this test does not anticipate.
// A reader has to survive the column's actual contract, not just today's
// write paths.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedNullDescriptionTenantFramework inserts a tenant-owned custom policy
// with a SQL NULL description directly (bypassing the API, which cannot
// produce one — see the file comment), so the readers below face the column's
// real contract rather than only the shapes the app happens to write today.
func seedNullDescriptionTenantFramework(t *testing.T, db *sqlx.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenant_frameworks (id, tenant_id, name, version, description)
		VALUES ($1, $2, 'Null Description Custom Policy', '1.0', NULL)`,
		id, tenant); err != nil {
		t.Fatalf("seed NULL-description tenant framework: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenant_frameworks WHERE id = $1`, id) })
	return id
}

func TestIntegration_TenantFrameworkService_NullDescriptionIsReadable(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	svc := NewTenantFrameworkService(db)

	id := seedNullDescriptionTenantFramework(t, db, tenant)

	t.Run("ListTenantFrameworks", func(t *testing.T) {
		got, err := svc.ListTenantFrameworks(tenant)
		if err != nil {
			t.Fatalf("a custom policy with a NULL description broke the whole list: %v", err)
		}
		found := false
		for _, f := range got {
			if f.ID == id {
				found = true
				if f.Description != "" {
					t.Errorf("description=%q, want empty", f.Description)
				}
			}
		}
		if !found {
			t.Fatalf("the NULL-description custom policy exists for this tenant but ListTenantFrameworks did not return it")
		}
	})

	t.Run("GetTenantFramework", func(t *testing.T) {
		got, err := svc.GetTenantFramework(tenant, id)
		if err != nil {
			t.Fatalf("a custom policy with a NULL description broke GetTenantFramework: %v", err)
		}
		if got.Description != "" {
			t.Errorf("description=%q, want empty", got.Description)
		}
	})
}

// TestIntegration_EvaluationService_TenantFramework_NullDescription pins the
// evaluation path (EvaluateFramework's tenant_frameworks branch), which was
// already COALESCEd — this is a regression guard, not a fix, so a future edit
// to that query cannot silently drop the COALESCE without a red test.
func TestIntegration_EvaluationService_TenantFramework_NullDescription(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	svc := NewEvaluationService(db)

	id := seedNullDescriptionTenantFramework(t, db, tenant)

	_, err := svc.EvaluateFramework(tenant, id, "1.0", models.ScenarioFilters{}, nil)
	if err != nil {
		t.Fatalf("a custom policy with a NULL description broke EvaluateFramework: %v", err)
	}
}
