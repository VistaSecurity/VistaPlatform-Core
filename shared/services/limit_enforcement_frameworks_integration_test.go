package services

// Database-integration test for the compliance-framework cap (CMP-6).
//
// The behaviour cannot be reached by a pure test: it depends on the seeded
// billable_items / tier_entitlements rows, on the real platform_frameworks
// codes, and on the SQL that decides what counts. Skips unless
// TEST_DATABASE_URL is set (see shared/testdb); run with
// `make test-integration-db`.

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// tenantOnTier creates a throwaway tenant pinned to the named subscription tier.
func tenantOnTier(t *testing.T, db *sql.DB, tier string) uuid.UUID {
	t.Helper()
	tenantID := testdb.NewTenant(t, db)
	var tierID uuid.UUID
	if err := db.QueryRow(`SELECT id FROM subscription_tiers WHERE name = $1`, tier).Scan(&tierID); err != nil {
		t.Fatalf("look up %s tier: %v", tier, err)
	}
	if _, err := db.Exec(`UPDATE tenants SET subscription_tier_id = $1 WHERE id = $2`, tierID, tenantID); err != nil {
		t.Fatalf("assign %s tier: %v", tier, err)
	}
	return tenantID
}

func frameworkIDByCode(t *testing.T, db *sql.DB, code string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM platform_frameworks WHERE code = $1 AND status = 'published' ORDER BY version DESC LIMIT 1`, code).Scan(&id); err != nil {
		t.Fatalf("look up framework %q: %v", code, err)
	}
	return id
}

// A Core tenant sits on the community tier, whose compliance_frameworks_max is
// 0. All six free frameworks must nonetheless be activatable — they cost
// nothing, Core ships them, and five of the six were unreachable because the
// only exemption was `is_platform_default`, which a UNIQUE index restricts to
// one framework.
func TestIntegration_FreeFrameworksActivateAtCapZero(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenantID := tenantOnTier(t, db, "community")
	svc := NewLimitEnforcementService(db)

	// The premise: the cap really is zero.
	_, limit, err := svc.GetComplianceFrameworkUsage(tenantID)
	if err != nil {
		t.Fatalf("GetComplianceFrameworkUsage: %v", err)
	}
	if limit == nil || *limit != 0 {
		t.Fatalf("community compliance_frameworks_max = %v, want 0 — this test asserts the carve-out, not the cap", limit)
	}

	// Activate all six, one at a time, checking the gate before each and
	// writing the license so the next check sees the accumulated usage.
	for _, code := range FreeFrameworkCodes {
		frameworkID := frameworkIDByCode(t, db, code)

		result, err := svc.CheckComplianceFrameworkLimit(tenantID, []uuid.UUID{frameworkID})
		if err != nil {
			t.Fatalf("CheckComplianceFrameworkLimit(%s): %v", code, err)
		}
		if !result.Allowed {
			t.Fatalf("free framework %q blocked at cap 0: %s", code, result.Message)
		}

		if _, err := db.Exec(`
			INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status, provisioned_by)
			VALUES ($1, $2, 'active', 'self_service')
			ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET subscription_status = 'active'
		`, tenantID, frameworkID); err != nil {
			t.Fatalf("license %s: %v", code, err)
		}
	}

	// Six free activations later, GetComplianceFrameworkUsage's `current` is
	// tenant-truth (every active license, free or paid — see its doc comment),
	// so it reports all 6. The cap itself is untouched: cap enforcement runs
	// through countActiveFrameworkSubscriptions/CheckComplianceFrameworkLimit,
	// asserted below, which still excludes free frameworks (CMP-6).
	current, _, err := svc.GetComplianceFrameworkUsage(tenantID)
	if err != nil {
		t.Fatalf("GetComplianceFrameworkUsage after activations: %v", err)
	}
	if current != len(FreeFrameworkCodes) {
		t.Errorf("active framework licenses after 6 free activations = %d, want %d", current, len(FreeFrameworkCodes))
	}

	// The cap still means something: a paid/regulated catalog entry is blocked.
	// The regulated frameworks ship in the Enterprise content bundle, not
	// seed.sql, so one is synthesised here to stand for that catalog.
	paidID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO platform_frameworks (id, code, name, version, organization, status, is_platform_default, created_by)
		VALUES ($1, 'it-regulated-stand-in', 'Regulated Stand-In', '1.0', 'Some Standards Body', 'published', false,
		        '00000000-0000-0000-0000-000000000001')
	`, paidID); err != nil {
		t.Fatalf("insert stand-in paid framework: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, paidID) })

	result, err := svc.CheckComplianceFrameworkLimit(tenantID, []uuid.UUID{paidID})
	if err != nil {
		t.Fatalf("CheckComplianceFrameworkLimit(paid): %v", err)
	}
	if result.Allowed {
		t.Error("a non-free framework was allowed at cap 0 — the carve-out swallowed the whole gate")
	}
}

// A tenant WITH cap can still spend it, and free activations never eat into it.
func TestIntegration_FreeFrameworksDoNotConsumePaidCap(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenantID := tenantOnTier(t, db, "pro") // compliance_frameworks_max = 1
	svc := NewLimitEnforcementService(db)

	_, limit, err := svc.GetComplianceFrameworkUsage(tenantID)
	if err != nil {
		t.Fatalf("GetComplianceFrameworkUsage: %v", err)
	}
	if limit == nil || *limit != 1 {
		t.Fatalf("pro compliance_frameworks_max = %v, want 1", limit)
	}

	// Burn every free framework.
	for _, code := range FreeFrameworkCodes {
		if _, err := db.Exec(`
			INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status, provisioned_by)
			VALUES ($1, $2, 'active', 'self_service')
			ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET subscription_status = 'active'
		`, tenantID, frameworkIDByCode(t, db, code)); err != nil {
			t.Fatalf("license %s: %v", code, err)
		}
	}

	paidID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO platform_frameworks (id, code, name, version, organization, status, is_platform_default, created_by)
		VALUES ($1, 'it-regulated-stand-in-2', 'Regulated Stand-In 2', '1.0', 'Some Standards Body', 'published', false,
		        '00000000-0000-0000-0000-000000000001')
	`, paidID); err != nil {
		t.Fatalf("insert stand-in paid framework: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, paidID) })

	result, err := svc.CheckComplianceFrameworkLimit(tenantID, []uuid.UUID{paidID})
	if err != nil {
		t.Fatalf("CheckComplianceFrameworkLimit(paid): %v", err)
	}
	if !result.Allowed {
		t.Errorf("the tenant's one paid slot was eaten by free activations: %s", result.Message)
	}
}
