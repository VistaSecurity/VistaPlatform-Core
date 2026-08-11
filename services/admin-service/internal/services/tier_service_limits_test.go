package services

import (
	"testing"

	"github.com/google/uuid"
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
	if limits.RetentionDays != 365 {
		t.Errorf("RetentionDays = %d, want 365 (pro tier)", limits.RetentionDays)
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
