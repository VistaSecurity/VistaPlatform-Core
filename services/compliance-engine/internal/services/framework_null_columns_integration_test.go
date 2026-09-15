package services

// platform_frameworks.description and .organization are NULLABLE, and
// models.PlatformFramework reads both into a plain Go string. NULL does not
// scan into a string — lib/pq fails the row with "converting NULL to string is
// unsupported" — and because a scan error aborts the whole read, ONE such row
// does not degrade one entry: it takes down the entire list.
//
// A tenant would have seen an empty Frameworks page (and an empty framework
// picker everywhere downstream of it) with a 500 behind it, caused by a
// framework somebody created without naming an organization.
//
// These tests insert exactly that row and assert each reader still returns it,
// reporting the missing organization as "" — the same way the API reports
// "this framework names no organization". They cover all four readers in
// framework_license_service.go because the queries are four separate SELECT
// lists and fixing one proves nothing about the others.
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

// seedNullTextFramework publishes a framework whose description AND
// organization are both SQL NULL, optionally activating it for the tenant.
func seedNullTextFramework(t *testing.T, db *sqlx.DB, tenant uuid.UUID, activate, isDefault bool) uuid.UUID {
	t.Helper()
	author, suffix := seedPlatformFrameworkAuthor(t, db)
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO platform_frameworks
		    (id, code, name, version, description, organization, status, published_at, created_by)
		VALUES ($1, $2, 'Null Text Framework', '1.0', NULL, NULL, 'published', NOW(), $3)`,
		id, "nulltext-"+suffix, author); err != nil {
		t.Fatalf("seed NULL-text framework: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, id) })

	if activate {
		if _, err := db.Exec(`
			INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status, is_default)
			VALUES ($1, $2, 'active', $3)`, tenant, id, isDefault); err != nil {
			t.Fatalf("activate NULL-text framework: %v", err)
		}
	}
	return id
}

func TestIntegration_FrameworkLicense_NullOrganizationIsListed(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	svc := NewFrameworkLicenseService(db)

	id := seedNullTextFramework(t, db, tenant, true, false)

	t.Run("ListLicensedFrameworks", func(t *testing.T) {
		got, err := svc.ListLicensedFrameworks(tenant)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke the whole list: %v", err)
		}
		pf := findLicensed(t, got, id)
		if pf.Organization != "" || pf.Description != "" {
			t.Errorf("organization=%q description=%q, want both empty", pf.Organization, pf.Description)
		}
	})

	t.Run("ListAllTenantSubscriptionsForAdmin", func(t *testing.T) {
		got, err := svc.ListAllTenantSubscriptionsForAdmin(tenant)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke the admin subscription list: %v", err)
		}
		pf := findLicensed(t, got, id)
		if pf.Organization != "" {
			t.Errorf("organization=%q, want empty", pf.Organization)
		}
	})

	t.Run("GetAvailableFrameworks", func(t *testing.T) {
		got, err := svc.GetAvailableFrameworks(tenant)
		if err != nil {
			t.Fatalf("a framework with a NULL organization broke the available list: %v", err)
		}
		found := false
		for _, f := range got {
			if f.PlatformFramework != nil && f.PlatformFramework.ID == id {
				found = true
				if f.PlatformFramework.Organization != "" || f.PlatformFramework.Description != "" {
					t.Errorf("organization=%q description=%q, want both empty",
						f.PlatformFramework.Organization, f.PlatformFramework.Description)
				}
			}
		}
		if !found {
			t.Fatalf("the NULL-organization framework is published but was not offered")
		}
	})
}

// GetDefaultFramework takes the JOIN'd branch only when the tenant's DEFAULT
// licence is the NULL-text framework, so it gets its own fixture.
func TestIntegration_FrameworkLicense_NullOrganizationDefaultFramework(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	svc := NewFrameworkLicenseService(db)

	// The tenant-creation trigger may already have planted a default licence;
	// stand this one in its place so the query's is_default branch hits ours.
	if _, err := raw.Exec(`DELETE FROM tenant_framework_licenses WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatalf("clear seeded licences: %v", err)
	}
	id := seedNullTextFramework(t, db, tenant, true, true)

	got, err := svc.GetDefaultFramework(tenant)
	if err != nil {
		t.Fatalf("a framework with a NULL organization broke the default-framework read: %v", err)
	}
	if got.FrameworkID != id.String() {
		t.Fatalf("default framework = %s, want the NULL-text one (%s)", got.FrameworkID, id)
	}
	if got.Framework == nil {
		t.Fatal("the default-framework response carries no framework")
	}
	if got.Framework.Organization != "" || got.Framework.Description != "" {
		t.Errorf("organization=%q description=%q, want both empty",
			got.Framework.Organization, got.Framework.Description)
	}
}

func findLicensed(t *testing.T, got []models.LicensedFrameworkResponse, id uuid.UUID) *models.PlatformFramework {
	t.Helper()
	for _, l := range got {
		if l.PlatformFrameworkID == id.String() {
			if l.PlatformFramework == nil {
				t.Fatalf("licence row for %s carries no framework", id)
			}
			return l.PlatformFramework
		}
	}
	t.Fatalf("the NULL-organization framework is licensed but was not listed")
	return nil
}
