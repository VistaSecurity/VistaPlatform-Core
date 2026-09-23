package entitlements_test

// DB-backed tests for the plan block and the Enterprise retention cap: that
// ResolvePlan reads the real licence row and the tenant's real tier, and that
// the default licence source reads platform_settings "retention.max_days" into
// every resolution path (Resolve and GetQuantityInTx), so the cap a platform
// admin saves is the retention_days every service reports.
//
// Both write the global platform_license row, so both run on a scratch
// database (see testdb.ScratchDatabase). Skip without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func writeLicence(t *testing.T, db *sql.DB, edition string) {
	t.Helper()
	mustExec(t, db, `DELETE FROM platform_license`)
	if edition != "" {
		mustExec(t, db, `INSERT INTO platform_license (subject, edition, licensee, expires_at, token_sha256)
			VALUES ('it', $1, 'Acme Corp', now() + interval '30 days', 'x')`, edition)
	}
	entitlements.FlushLicenseCache()
}

func TestIntegration_ResolvePlan_FollowsTheLicence(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	t.Cleanup(entitlements.FlushLicenseCache)
	ctx := context.Background()

	tenant := testdb.NewTenant(t, db)
	var trialTier uuid.UUID
	if err := db.QueryRow(`INSERT INTO subscription_tiers (name, display_name, is_active, is_trial)
		VALUES ($1, 'Starter Trial', true, true) RETURNING id`, "it-trial-"+uuid.NewString()[:8]).Scan(&trialTier); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `UPDATE tenants SET subscription_tier_id = $1, trial_ends_at = now() + interval '5 days' WHERE id = $2`, trialTier, tenant)

	for _, tc := range []struct {
		edition, display string
		trial            bool
	}{
		{"", entitlements.PlanDisplayNameCore, false},
		{"enterprise", entitlements.PlanDisplayNameEnterprise, false},
		{"msp", "Starter Trial", true},
	} {
		writeLicence(t, db, tc.edition)
		p, err := entitlements.ResolvePlan(ctx, db, tenant)
		if err != nil {
			t.Fatalf("licence %q: %v", tc.edition, err)
		}
		if p.DisplayName != tc.display || (p.Trial != nil) != tc.trial {
			t.Errorf("licence %q: plan = %+v, want %q trial=%v", tc.edition, p, tc.display, tc.trial)
		}
		if tc.edition != "" && (p.Licensee == nil || *p.Licensee != "Acme Corp") {
			t.Errorf("licence %q: licensee = %v, want Acme Corp", tc.edition, p.Licensee)
		}
	}
}

func TestIntegration_RetentionCap_ResolvesOnEnterprise(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	t.Cleanup(entitlements.FlushLicenseCache)
	ctx := context.Background()
	tenant := testdb.NewTenant(t, db)
	r := entitlements.NewPostgresResolver(db)

	setCap := func(raw string) {
		t.Helper()
		if raw == "" {
			mustExec(t, db, `DELETE FROM platform_settings WHERE setting_key = $1`, entitlements.RetentionSettingKey)
		} else {
			mustExec(t, db, `INSERT INTO platform_settings (setting_key, setting_value) VALUES ($1, $2::jsonb)
				ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`, entitlements.RetentionSettingKey, raw)
		}
		entitlements.FlushLicenseCache()
	}
	viaResolve := func() *int {
		t.Helper()
		q, err := entitlements.GetQuantity(ctx, r, tenant, entitlements.RetentionItemKey)
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	viaTx := func() *int {
		t.Helper()
		var q *int
		if err := shareddatabase.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
			var err error
			q, err = entitlements.GetQuantityInTx(ctx, tx, tenant, entitlements.RetentionItemKey)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return q
	}
	check := func(label string, want *int) {
		t.Helper()
		for path, got := range map[string]*int{"Resolve": viaResolve(), "GetQuantityInTx": viaTx()} {
			if (got == nil) != (want == nil) || (got != nil && *got != *want) {
				t.Errorf("%s via %s: retention_days = %v, want %v", label, path, deref(got), deref(want))
			}
		}
	}

	writeLicence(t, db, "enterprise")
	setCap("")
	check("Enterprise, no setting", nil)
	setCap("null")
	check("Enterprise, explicit unlimited", nil)
	setCap("730")
	check("Enterprise, capped at 730", ptr(730))
	setCap(`"garbage"`)
	check("Enterprise, malformed setting reads as the default", nil)

	// Positive control: the cap is an Enterprise rule. Core keeps the
	// catalogue/tier value (the seeded default is 7 days for a tenant with no
	// tier), whatever the setting says.
	setCap("730")
	writeLicence(t, db, "")
	if got := viaResolve(); got == nil || *got == 730 {
		t.Errorf("Core: retention_days = %v, want the tier/catalogue value, not the Enterprise cap", deref(got))
	}
}

// ptr is declared in tenant_cap_integration_test.go (same package).

func deref(p *int) any {
	if p == nil {
		return "unlimited"
	}
	return *p
}
