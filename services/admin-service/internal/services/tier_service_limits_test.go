package services

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// DB-backed tests for TierService.GetEffectiveLimits. They assert the
// endpoint reflects the SAME resolved values enforcement uses
// (override > tier > default via shared/entitlements) rather than the
// legacy tier-only columns — the regression fixed in. Skipped
// without TEST_DATABASE_URL, like the sibling entitlements-service suite.

func TestGetEffectiveLimits_TierValues(t *testing.T) {
	_, db := setup(t)
	tenant := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name='pro'), NOW(), NOW())
	`, tenant, "lim-"+tenant.String()[:8], "lim-"+tenant.String()[:8]); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	limits, err := NewTierService(db, db).GetEffectiveLimits(tenant)
	if err != nil {
		t.Fatalf("GetEffectiveLimits: %v", err)
	}

	if limits.MaxSensors == nil || *limits.MaxSensors != 25 {
		t.Errorf("MaxSensors = %v, want 25 (pro tier)", limits.MaxSensors)
	}
	if limits.MaxAssets == nil || *limits.MaxAssets != 10000 {
		t.Errorf("MaxAssets = %v, want 10000 (pro tier)", limits.MaxAssets)
	}
	if limits.RetentionDays == nil || *limits.RetentionDays != 365 {
		t.Errorf("RetentionDays = %v, want 365 (pro tier)", limits.RetentionDays)
	}
	if limits.ComplianceFrameworks == nil || *limits.ComplianceFrameworks != 1 {
		t.Errorf("ComplianceFrameworks = %v, want 1 (pro tier)", limits.ComplianceFrameworks)
	}
	if limits.MaxIntegrations == nil || *limits.MaxIntegrations != 3 {
		t.Errorf("MaxIntegrations = %v, want 3 (pro tier)", limits.MaxIntegrations)
	}
	if limits.HasOverrides {
		t.Errorf("HasOverrides = true, want false (no per-tenant overrides)")
	}
	if len(limits.Overrides) != 0 {
		t.Errorf("Overrides = %d, want 0", len(limits.Overrides))
	}
}

func TestGetEffectiveLimits_OverrideBeatsTier(t *testing.T) {
	_, db := setup(t)
	tenant := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name='pro'), NOW(), NOW())
	`, tenant, "lim-"+tenant.String()[:8], "lim-"+tenant.String()[:8]); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// Grant a higher per-tenant sensor cap than the Pro tier (25) provides.
	if _, err := db.Exec(`
		INSERT INTO tenant_entitlements
		    (tenant_id, item_id, override_value, reason, effective_from)
		VALUES (
		    $1,
		    (SELECT id FROM billable_items WHERE key='max_sensors'),
		    '{"quantity": 99}'::jsonb,
		    'sales override',
		    NOW() - INTERVAL '1 day'
		)
	`, tenant); err != nil {
		t.Fatalf("insert override: %v", err)
	}

	limits, err := NewTierService(db, db).GetEffectiveLimits(tenant)
	if err != nil {
		t.Fatalf("GetEffectiveLimits: %v", err)
	}

	if limits.MaxSensors == nil || *limits.MaxSensors != 99 {
		t.Errorf("MaxSensors = %v, want 99 (override beats tier)", limits.MaxSensors)
	}
	// Unaffected caps still report the tier value.
	if limits.MaxAssets == nil || *limits.MaxAssets != 10000 {
		t.Errorf("MaxAssets = %v, want 10000 (tier, no override)", limits.MaxAssets)
	}
	if !limits.HasOverrides {
		t.Errorf("HasOverrides = false, want true")
	}
	var found bool
	for _, ov := range limits.Overrides {
		if ov.LimitName == "max_sensors" {
			found = true
		}
	}
	if !found {
		t.Errorf("Overrides should include max_sensors; got %+v", limits.Overrides)
	}
}

func TestGetEffectiveLimits_ExpiredOverrideIgnored(t *testing.T) {
	_, db := setup(t)
	tenant := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name='pro'), NOW(), NOW())
	`, tenant, "lim-"+tenant.String()[:8], "lim-"+tenant.String()[:8]); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// An already-expired override must NOT change the reported cap, matching
	// the resolver's effective-window semantics.
	if _, err := db.Exec(`
		INSERT INTO tenant_entitlements
		    (tenant_id, item_id, override_value, reason, effective_from, expires_at)
		VALUES (
		    $1,
		    (SELECT id FROM billable_items WHERE key='max_sensors'),
		    '{"quantity": 99}'::jsonb,
		    'expired trial',
		    NOW() - INTERVAL '10 days',
		    NOW() - INTERVAL '1 day'
		)
	`, tenant); err != nil {
		t.Fatalf("insert expired override: %v", err)
	}

	limits, err := NewTierService(db, db).GetEffectiveLimits(tenant)
	if err != nil {
		t.Fatalf("GetEffectiveLimits: %v", err)
	}
	if limits.MaxSensors == nil || *limits.MaxSensors != 25 {
		t.Errorf("MaxSensors = %v, want 25 (expired override ignored)", limits.MaxSensors)
	}
	if limits.HasOverrides {
		t.Errorf("HasOverrides = true, want false (only override is expired)")
	}
}

func TestGetEffectiveLimits_UnlimitedFromTier(t *testing.T) {
	_, db := setup(t)
	tenant := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name='enterprise'), NOW(), NOW())
	`, tenant, "lim-"+tenant.String()[:8], "lim-"+tenant.String()[:8]); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	limits, err := NewTierService(db, db).GetEffectiveLimits(tenant)
	if err != nil {
		t.Fatalf("GetEffectiveLimits: %v", err)
	}
	if limits.MaxSensors != nil {
		t.Errorf("MaxSensors = %v, want nil (enterprise unlimited)", *limits.MaxSensors)
	}
	if limits.MaxAssets != nil {
		t.Errorf("MaxAssets = %v, want nil (enterprise unlimited)", *limits.MaxAssets)
	}
}

// GetTierCaps is what the tier impact analysis compares. It must report the
// tier's COMPOSITION (tier_entitlements), falling back to the catalogue
// default — never the legacy subscription_tiers.max_* columns, which the plan
// editor does not write on edit.
func TestGetTierCaps_ComposedTierAndCatalogueDefault(t *testing.T) {
	_, db := setup(t)
	svc := NewTierService(db, db)

	// Seeded pro: composed with max_sensors 25 / max_assets 10000 / max_users
	// 25 — and its legacy max_* columns deliberately say something else
	// (seed.sql writes them from the pre-entitlement era), so agreement with
	// the column would be the bug.
	pro := tierID(t, db, "pro")
	caps, err := svc.GetTierCaps(pro, TierCapKeys())
	if err != nil {
		t.Fatalf("GetTierCaps(pro): %v", err)
	}
	if q := caps["max_sensors"]; q == nil || *q != 25 {
		t.Errorf("pro max_sensors = %v, want 25 (tier_entitlements)", q)
	}
	if q := caps["max_assets"]; q == nil || *q != 10000 {
		t.Errorf("pro max_assets = %v, want 10000 (tier_entitlements)", q)
	}

	// A tier with NO composition resolves each cap to the catalogue default —
	// exactly what a tenant on it would be gated by. Its legacy columns are set
	// to 999 to prove they are not consulted.
	name := "caps-" + uuid.New().String()[:8]
	n999 := 999
	scratch, err := svc.CreateTier(models.TierCreateRequest{
		Name: name, DisplayName: name, BillingInterval: "month", BillingMethod: "invoice",
		MaxSensors: &n999, MaxAssets: &n999, MaxUsers: &n999,
	})
	if err != nil {
		t.Fatalf("CreateTier: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM subscription_tiers WHERE id = $1`, scratch.ID) })

	caps, err = svc.GetTierCaps(scratch.ID, TierCapKeys())
	if err != nil {
		t.Fatalf("GetTierCaps(scratch): %v", err)
	}
	if q := caps["max_sensors"]; q == nil || *q != 0 {
		t.Errorf("uncomposed max_sensors = %v, want 0 (catalogue default, NOT the 999 column)", q)
	}
	if q, ok := caps["max_users"]; !ok || q != nil {
		t.Errorf("uncomposed max_users = %v (present=%v), want present and nil = unlimited (catalogue default)", q, ok)
	}
}

// A plan that cannot be resolved must not fall back to the tier-derived
// read-out: on Enterprise that would name the capacity-placeholder tier
// ("community") as the tenant's plan. Same rule as the tenant list/detail
// presenter, which answers 500 rather than the raw rows.
func TestGetEffectiveLimits_PlanErrorFailsClosed(t *testing.T) {
	_, db := setup(t)
	tenant := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name='community'), NOW(), NOW())
	`, tenant, "lim-"+tenant.String()[:8], "lim-"+tenant.String()[:8]); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	svc := NewTierService(db, db)
	svc.resolvePlan = func(context.Context, *sql.DB, uuid.UUID) (entitlements.Plan, error) {
		return entitlements.Plan{}, errors.New("licence unreadable")
	}
	limits, err := svc.GetEffectiveLimits(tenant)
	if err == nil {
		t.Fatalf("GetEffectiveLimits with an unresolvable plan = %+v, want an error (fail closed)", limits)
	}
	if limits != nil {
		t.Fatalf("returned a read-out alongside the error: %+v", limits)
	}
}
