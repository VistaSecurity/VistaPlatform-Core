package services

// platform_frameworks.description and .organization are NULLABLE
// (scripts/database/schema.sql), but models.PlatformFramework scans both into
// plain Go strings. A NULL fails that row's Scan outright — lib/pq reports
// "converting NULL to string is unsupported" — and because a scan error aborts
// the WHOLE read, one such row does not degrade to one missing field: it takes
// down every reader of the table for every framework, not just the affected
// one.
//
// framework_null_columns_integration_test.go already covers the four readers
// in framework_license_service.go (fixed first). This file covers every
// OTHER reader of platform_frameworks.{description,organization} in the
// module — found by grepping the module for `pf.organization` / `organization,`
// in SELECT lists, per the review note that named only a few of these by line
// number:
//
//   - PlatformFrameworkService.ListFrameworks / GetFramework /
//     GetPlatformDefaultFramework (platform_framework_service.go)
//   - TenantFrameworkService.ListPublishedFrameworks /
//     ListPublishedFrameworksWithLicense / ViewFramework
//     (tenant_framework_service.go)
//   - FrameworkContextService.evaluateSingleFramework
//     (framework_context_service.go)
//   - EvaluationService.GetFrameworkStatus / GetComplianceScore
//     (evaluation_service.go)
//
// Each sub-test seeds a published (and, where relevant, licensed) framework
// with description AND organization both SQL NULL, then asserts the reader
// still returns it — reporting "" rather than erroring the whole call, or
// (GetFrameworkStatus) silently dropping the framework from the tenant's
// status list, which is the same three-valued-honesty violation under another
// name: a real "not assessed" rendered as "does not exist".
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_PlatformFrameworkService_NullOrganizationIsReadable(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	svc := NewPlatformFrameworkService(db)

	id := seedNullTextFramework(t, db, tenant, false, false)

	t.Run("ListFrameworks", func(t *testing.T) {
		got, err := svc.ListFrameworks("published")
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke ListFrameworks: %v", err)
		}
		found := false
		for _, f := range got {
			if f.ID == id {
				found = true
				if f.Organization != "" || f.Description != "" {
					t.Errorf("organization=%q description=%q, want both empty", f.Organization, f.Description)
				}
			}
		}
		if !found {
			t.Fatalf("the NULL-organization framework is published but ListFrameworks did not return it")
		}
	})

	t.Run("GetFramework", func(t *testing.T) {
		got, err := svc.GetFramework(id)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke GetFramework: %v", err)
		}
		if got.Organization != "" || got.Description != "" {
			t.Errorf("organization=%q description=%q, want both empty", got.Organization, got.Description)
		}
	})
}

func TestIntegration_PlatformFrameworkService_NullOrganizationDefaultFramework(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	svc := NewPlatformFrameworkService(db)

	// GetPlatformDefaultFramework keys off platform_frameworks.is_platform_default
	// directly (not a tenant_framework_licenses row), and a partial unique index
	// (idx_platform_frameworks_single_default) allows only ONE such row. This
	// package's other integration tests run against the SAME database and some
	// of them (see grep for ApplySchemaAndSeed) apply the real seed.sql, which
	// plants the real "Best Practices" default framework — so a plain schema-only
	// fixture insert here works in isolation but fails the unique index the
	// moment it runs after one of those. Rather than fight the constraint,
	// commandeer whichever row currently holds is_platform_default (seeded or
	// freshly minted) and restore it afterwards.
	var existingID uuid.UUID
	err := db.Get(&existingID, `SELECT id FROM platform_frameworks WHERE is_platform_default = true LIMIT 1`)

	var id uuid.UUID
	switch err {
	case nil:
		// A default already exists (real seed data): null its text columns for
		// the duration of the test and put them back.
		id = existingID
		var prevDescription, prevOrganization sql.NullString
		if gErr := db.QueryRow(`SELECT description, organization FROM platform_frameworks WHERE id = $1`, id).
			Scan(&prevDescription, &prevOrganization); gErr != nil {
			t.Fatalf("read existing default framework's text columns: %v", gErr)
		}
		if _, uErr := db.Exec(`UPDATE platform_frameworks SET description = NULL, organization = NULL WHERE id = $1`, id); uErr != nil {
			t.Fatalf("null out existing default framework's text columns: %v", uErr)
		}
		t.Cleanup(func() {
			_, _ = db.Exec(`UPDATE platform_frameworks SET description = $2, organization = $3 WHERE id = $1`,
				id, prevDescription, prevOrganization)
		})
	case sql.ErrNoRows:
		// No default exists yet (schema-only database): mint one.
		author, suffix := seedPlatformFrameworkAuthor(t, db)
		id = uuid.New()
		if _, iErr := db.Exec(`
			INSERT INTO platform_frameworks
			    (id, code, name, version, description, organization, status, is_platform_default, published_at, created_by)
			VALUES ($1, $2, 'Null Text Default Framework', '1.0', NULL, NULL, 'published', true, NOW(), $3)`,
			id, "nulltext-default-"+suffix, author); iErr != nil {
			t.Fatalf("seed NULL-text default framework: %v", iErr)
		}
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, id) })
	default:
		t.Fatalf("check for an existing default framework: %v", err)
	}

	got, gErr := svc.GetPlatformDefaultFramework()
	if gErr != nil {
		t.Fatalf("a framework with a NULL organization broke GetPlatformDefaultFramework: %v", gErr)
	}
	if got.ID != id {
		t.Fatalf("GetPlatformDefaultFramework returned %s, want the NULL-text fixture %s", got.ID, id)
	}
	if got.Organization != "" || got.Description != "" {
		t.Errorf("organization=%q description=%q, want both empty", got.Organization, got.Description)
	}
}

func TestIntegration_TenantFrameworkService_NullOrganizationIsReadable(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	svc := NewTenantFrameworkService(db)

	id := seedNullTextFramework(t, db, tenant, true, false)

	t.Run("ListPublishedFrameworks", func(t *testing.T) {
		got, err := svc.ListPublishedFrameworks(&tenant)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke ListPublishedFrameworks: %v", err)
		}
		found := false
		for _, f := range got {
			if f.ID == id {
				found = true
				if f.Organization != "" || f.Description != "" {
					t.Errorf("organization=%q description=%q, want both empty", f.Organization, f.Description)
				}
			}
		}
		if !found {
			t.Fatalf("the NULL-organization framework is published but ListPublishedFrameworks did not return it")
		}
	})

	t.Run("ListPublishedFrameworksWithLicense", func(t *testing.T) {
		got, err := svc.ListPublishedFrameworksWithLicense(tenant)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke ListPublishedFrameworksWithLicense: %v", err)
		}
		found := false
		for _, f := range got {
			if f.ID == id {
				found = true
				if !f.IsLicensed {
					t.Errorf("IsLicensed = false, want true (this fixture activates it)")
				}
				if f.Organization != "" || f.Description != "" {
					t.Errorf("organization=%q description=%q, want both empty", f.Organization, f.Description)
				}
			}
		}
		if !found {
			t.Fatalf("the NULL-organization framework is published but ListPublishedFrameworksWithLicense did not return it")
		}
	})

	t.Run("ViewFramework", func(t *testing.T) {
		got, err := svc.ViewFramework(id)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke ViewFramework: %v", err)
		}
		if got.Organization != "" || got.Description != "" {
			t.Errorf("organization=%q description=%q, want both empty", got.Organization, got.Description)
		}
	})
}

func TestIntegration_FrameworkContextService_EvaluateSingleFramework_NullOrganization(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	svc := NewFrameworkContextService(db, nil, nil)

	id := seedNullTextFramework(t, db, tenant, false, false)

	// evaluateSingleFramework is unexported; this test lives in the same
	// package so it can call it directly rather than going through the whole
	// BatchEvaluate request shape, which needs nothing else this fixture omits.
	got, err := svc.evaluateSingleFramework(tenant, id, models.ScenarioFilters{}, false)
	if err != nil {
		t.Fatalf("a framework with a NULL organization broke evaluateSingleFramework: %v", err)
	}
	if got.FrameworkID != id.String() {
		t.Fatalf("FrameworkID = %s, want %s", got.FrameworkID, id)
	}
}

func TestIntegration_EvaluationService_NullOrganization(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	svc := NewEvaluationService(db)

	// activate=true, isDefault=true: GetFrameworkStatus/GetComplianceScore both
	// resolve "the tenant's active framework" via tenant_framework_licenses'
	// is_default column, so the fixture must be the default licence, not merely
	// a licensed one. Clear whatever the tenant-creation trigger already
	// planted so this fixture's is_default row is the one both readers find.
	if _, err := raw.Exec(`DELETE FROM tenant_framework_licenses WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatalf("clear seeded licences: %v", err)
	}
	id := seedNullTextFramework(t, db, tenant, true, true)

	t.Run("GetFrameworkStatus", func(t *testing.T) {
		got, err := svc.GetFrameworkStatus(tenant)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke GetFrameworkStatus: %v", err)
		}
		found := false
		for _, f := range got.Frameworks {
			if f.ID == id.String() {
				found = true
			}
		}
		if !found {
			t.Fatalf("the NULL-organization framework is licensed as default but GetFrameworkStatus dropped it "+
				"silently instead of erroring or reporting it — got %d framework(s): %+v", len(got.Frameworks), got.Frameworks)
		}
	})

	t.Run("GetComplianceScore", func(t *testing.T) {
		got, err := svc.GetComplianceScore(tenant, nil)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke GetComplianceScore: %v", err)
		}
		found := false
		for _, f := range got.Frameworks {
			if f.ID == id.String() {
				found = true
			}
		}
		if !found {
			t.Fatalf("the NULL-organization framework is the tenant's default but GetComplianceScore did not "+
				"report it — got %d framework(s): %+v", len(got.Frameworks), got.Frameworks)
		}
	})
}
