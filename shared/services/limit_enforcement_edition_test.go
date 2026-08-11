package services_test

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// These tests pin the open-core edition boundary at the enforcement layer.
//
// The failure they exist to prevent: tenants are created with a NULL
// subscription_tier_id, and CheckFeatureAccess historically treated "no tier"
// as "allow everything" to keep mid-signup users from being hard-blocked. A
// single-org Core deployment never assigns a tier, so that carve-out would
// have unlocked every paid capability on precisely the deployments that are
// not entitled to them — the open-core equivalent of shipping with the doors
// open. See shared/entitlements.IsEditionGated.
//
// They skip unless TEST_DATABASE_URL is set (see CLAUDE.md, DB-integration
// tests); the DB-free half of this contract is in
// shared/entitlements/editions_test.go and always runs.

// TestIntegration_EditionGate_NoTierDeniesPaidCapabilities is the Core
// deployment proof: a tenant with no tier — the shape of a Core install — must
// resolve every edition-gated capability to denied.
func TestIntegration_EditionGate_NoTierDeniesPaidCapabilities(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db) // no subscription_tier_id — the Core shape
	svc := services.NewLimitEnforcementService(db)

	requireNoTier(t, db, tenant)

	gated := entitlements.EditionGatedKeys()
	if len(gated) == 0 {
		t.Fatal("no edition-gated keys registered; the gate would be vacuous")
	}
	for _, key := range gated {
		allowed, err := svc.CheckFeatureAccess(tenant, key)
		if err != nil {
			t.Errorf("CheckFeatureAccess(%q): unexpected error: %v", key, err)
			continue
		}
		if allowed {
			t.Errorf("CheckFeatureAccess(%q) = true for a tier-less tenant; "+
				"a Core deployment must not unlock paid capabilities", key)
		}
	}
}

// TestIntegration_EditionGate_NoTierPreservesOnboardingCarveOut guards the
// other direction: narrowing the carve-out must not break signup. A tier-less
// tenant still gets ungated capabilities, so unfinished signups are not
// hard-blocked.
func TestIntegration_EditionGate_NoTierPreservesOnboardingCarveOut(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := services.NewLimitEnforcementService(db)

	requireNoTier(t, db, tenant)

	// Not in the edition registry, so the onboarding carve-out still applies.
	const ungated = "some_core_capability_not_in_the_edition_registry"
	if entitlements.IsEditionGated(ungated) {
		t.Fatalf("test premise broken: %q is edition-gated", ungated)
	}
	allowed, err := svc.CheckFeatureAccess(tenant, ungated)
	if err != nil {
		t.Fatalf("CheckFeatureAccess(%q): %v", ungated, err)
	}
	if !allowed {
		t.Errorf("CheckFeatureAccess(%q) = false for a tier-less tenant; "+
			"the onboarding carve-out must survive for ungated capabilities", ungated)
	}
}

// TestIntegration_EditionGate_EnterpriseTierAloneGrantsNothing pins the fix for
// the tier self-grant hole: seed.sql ships in the OPEN-SOURCE repo, so a Core
// deployment has the enterprise tier rows too. If those rows granted gated
// capabilities, any platform admin could unlock the paid product by picking a
// tier from the tier editor — not circumvention requiring intent, just using the
// product as designed.
func TestIntegration_EditionGate_EnterpriseTierAloneGrantsNothing(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := services.NewLimitEnforcementService(db)

	if _, err := db.Exec(`
		UPDATE tenants
		SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'enterprise')
		WHERE id = $1`, tenant); err != nil {
		t.Fatalf("assign enterprise tier: %v", err)
	}

	for _, feature := range []string{"custom_policies", "sso_saml", "cbom_signing", "cmdb_sync"} {
		allowed, err := svc.CheckFeatureAccess(tenant, feature)
		if err != nil {
			t.Fatalf("CheckFeatureAccess(%s): %v", feature, err)
		}
		if allowed {
			t.Errorf("CheckFeatureAccess(%s) = true from the enterprise tier alone — "+
				"a Core deployment could unlock paid capability by assigning a seeded tier", feature)
		}
	}
}

// TestIntegration_EditionGate_AdminEditedTierGrantsNothing covers the path the
// seed-data fix cannot reach. Fixing the seeded enterprise rows makes a
// fresh install safe, but tier_entitlements is writable at runtime: admin-ui's
// Plans -> Tiers grid saves cells live, and EntitlementsService.ReplaceTierEntitlements
// bulk-writes whatever included_value it is handed with no edition filter. So a
// platform admin on a Core deployment could re-tick the box the seed fix cleared
// and be back where we started, using nothing but the shipped UI.
//
// This is why the rule belongs in code and not only in data: no tier row, seeded
// or hand-edited, may grant an edition-gated capability. Only the tenant override
// layer that a verified token seeds can.
func TestIntegration_EditionGate_AdminEditedTierGrantsNothing(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := services.NewLimitEnforcementService(db)

	// Exactly what the tier editor writes when an admin ticks the box.
	if _, err := db.Exec(`
		INSERT INTO tier_entitlements (tier_id, item_id, included_value)
		SELECT st.id, bi.id, '{"enabled": true}'::jsonb
		FROM subscription_tiers st, billable_items bi
		WHERE st.name = 'enterprise' AND bi.key = 'custom_policies'
		ON CONFLICT (tier_id, item_id) DO UPDATE SET included_value = EXCLUDED.included_value`); err != nil {
		t.Fatalf("simulate tier editor write: %v", err)
	}
	if _, err := db.Exec(`
		UPDATE tenants
		SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'enterprise')
		WHERE id = $1`, tenant); err != nil {
		t.Fatalf("assign enterprise tier: %v", err)
	}

	allowed, err := svc.CheckFeatureAccess(tenant, "custom_policies")
	if err != nil {
		t.Fatalf("CheckFeatureAccess(custom_policies): %v", err)
	}
	if allowed {
		t.Error("CheckFeatureAccess(custom_policies) = true from a hand-edited tier row; " +
			"a Core deployment can unlock paid capability from the tier editor alone")
	}
}

// TestIntegration_EditionGate_TokenOverrideGrants is the other half, and the
// reason the test above is not simply a wall: capability arrives through the
// tenant_entitlements override layer that a verified edition token seeds
// (admin-service/ee/edition/seeder.go). Without this, the gate could be
// "correct" by denying everything and the paid editions would ship broken.
func TestIntegration_EditionGate_TokenOverrideGrants(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := services.NewLimitEnforcementService(db)

	// Exactly what the token seeder writes: a per-tenant override with an expiry.
	if _, err := db.Exec(`
		INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from, expires_at)
		SELECT $1, bi.id, '{"enabled": true}'::jsonb, 'test: edition token', now() - interval '1 hour', now() + interval '30 days'
		FROM billable_items bi WHERE bi.key = 'custom_policies'`, tenant); err != nil {
		t.Fatalf("seed token override: %v", err)
	}

	allowed, err := svc.CheckFeatureAccess(tenant, "custom_policies")
	if err != nil {
		t.Fatalf("CheckFeatureAccess(custom_policies): %v", err)
	}
	if !allowed {
		t.Error("CheckFeatureAccess(custom_policies) = false with an active token override; " +
			"a licensed Enterprise deployment would ship with its own feature disabled")
	}
}

// TestIntegration_EditionGate_PilotDeniedThenGranted walks the pilot
// capability across the boundary in one test, which is the end-to-end
// statement Phase B set out to prove: same code, same database, entitlement
// state alone decides.
func TestIntegration_EditionGate_PilotDeniedThenGranted(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := services.NewLimitEnforcementService(db)

	const pilot = "custom_policies"

	allowed, err := svc.CheckFeatureAccess(tenant, pilot)
	if err != nil {
		t.Fatalf("CheckFeatureAccess(%s) pre-grant: %v", pilot, err)
	}
	if allowed {
		t.Fatalf("%s allowed before any grant", pilot)
	}

	// Grant via a per-tenant override — the mechanism an edition token will
	// seed. No tier assignment, no billing involved.
	if _, err := db.Exec(`
		INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, effective_from)
		SELECT $1, id, '{"enabled": true}'::jsonb, NOW()
		FROM billable_items WHERE key = $2`, tenant, pilot); err != nil {
		t.Fatalf("seed tenant entitlement: %v", err)
	}

	allowed, err = svc.CheckFeatureAccess(tenant, pilot)
	if err != nil {
		t.Fatalf("CheckFeatureAccess(%s) post-grant: %v", pilot, err)
	}
	if !allowed {
		t.Errorf("%s still denied after an active tenant_entitlements grant; "+
			"the edition token would have no way to unlock it", pilot)
	}
}

// requireNoTier asserts the test premise: the tenant really has a NULL
// subscription_tier_id. Without this the "Core deployment" tests could pass
// vacuously if testdb.NewTenant ever starts assigning a default tier.
func requireNoTier(t *testing.T, db *sql.DB, tenant uuid.UUID) {
	t.Helper()
	var tier sql.NullString
	if err := db.QueryRow(
		`SELECT subscription_tier_id FROM tenants WHERE id = $1`, tenant,
	).Scan(&tier); err != nil {
		t.Fatalf("look up tenant tier: %v", err)
	}
	if tier.Valid && tier.String != "" {
		t.Fatalf("test premise broken: tenant has tier %q, expected NULL", tier.String)
	}
}
