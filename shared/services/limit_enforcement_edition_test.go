package services_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

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
	requireCoreDatabase(t, db)
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
// This is why the rule belongs in code and not only in data: on an install with
// no licence, no tier row, seeded or hand-edited, may grant an edition-gated
// capability. The resolver's licence step (shared/entitlements/license.go) is
// that code.
func TestIntegration_EditionGate_AdminEditedTierGrantsNothing(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := services.NewLimitEnforcementService(db)

	// A tier of this test's OWN, not the seeded `enterprise` row.
	//
	// The mechanism under test is a tier_entitlements row that grants the
	// capability, which a private tier reproduces exactly. Writing it onto the
	// SEEDED enterprise row instead is seed-row pollution across suites: nothing
	// puts the shipped value back (seed.sql no longer rewrites tier grants at
	// all), and every other package binary on this database would see the
	// seeded enterprise tier granting a paid capability.
	//
	// is_active = false for the same reason: it is not a shipped tier, so
	// shared/entitlements.TestResolve_CoreInstallNeverGrantsGatedCapabilities,
	// which enumerates the active tiers, must not see it. The resolver filters
	// billable_items.is_active, never subscription_tiers.is_active, so the grant
	// path being tested here is unchanged.
	tierName := "it-editiongate-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = db.Exec(`UPDATE tenants SET subscription_tier_id = NULL WHERE subscription_tier_id =
			(SELECT id FROM subscription_tiers WHERE name = $1)`, tierName)
		_, _ = db.Exec(`DELETE FROM tier_entitlements WHERE tier_id =
			(SELECT id FROM subscription_tiers WHERE name = $1)`, tierName)
		_, _ = db.Exec(`DELETE FROM subscription_tiers WHERE name = $1`, tierName)
	})
	if _, err := db.Exec(`
		INSERT INTO subscription_tiers (name, display_name, is_active) VALUES ($1, $1, false)`,
		tierName); err != nil {
		t.Fatalf("create the test's own tier: %v", err)
	}

	// Exactly what the tier editor writes when an admin ticks the box.
	if _, err := db.Exec(`
		INSERT INTO tier_entitlements (tier_id, item_id, included_value)
		SELECT st.id, bi.id, '{"enabled": true}'::jsonb
		FROM subscription_tiers st, billable_items bi
		WHERE st.name = $1 AND bi.key = 'custom_policies'
		ON CONFLICT (tier_id, item_id) DO UPDATE SET included_value = EXCLUDED.included_value`,
		tierName); err != nil {
		t.Fatalf("simulate tier editor write: %v", err)
	}
	if _, err := db.Exec(`
		UPDATE tenants
		SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = $1)
		WHERE id = $2`, tierName, tenant); err != nil {
		t.Fatalf("assign the test's own tier: %v", err)
	}

	// The PREMISE, asserted rather than assumed: the tier row really does grant
	// the capability at the entitlement layer. Without this the test passes just
	// as happily when the tier write silently did nothing — a tier the tenant was
	// never assigned, a renamed billable item — and would then be proving that
	// the gate denies a capability nobody granted. Read under an injected MSP
	// licence, which leaves the SQL layers' answer untouched; the production
	// resolver on this Core database would report the licence step's denial.
	sqlLayer := entitlements.NewPostgresResolver(db, entitlements.WithLicenseSource(
		func(context.Context) (*entitlements.License, error) {
			return &entitlements.License{Edition: entitlements.EditionMSP, ExpiresAt: time.Now().Add(time.Hour)}, nil
		}))
	ent, err := sqlLayer.Resolve(context.Background(), tenant, "custom_policies")
	if err != nil {
		t.Fatalf("Resolve(custom_policies): %v", err)
	}
	if granted, _ := ent.BooleanValue(); !granted || ent.Source != entitlements.SourceTier {
		t.Fatalf("premise failed: the tier row does not grant custom_policies (granted=%v source=%q) — "+
			"this test would pass vacuously", granted, ent.Source)
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

// TestIntegration_EditionGate_OverrideAloneGrantsNothingOnCore: a per-tenant
// override used to be the one layer that COULD switch a paid capability on
// (it was what the old token seeder wrote), which meant anyone able to write
// tenant_entitlements on a Core install — the admin API ships in Core — could
// unlock the paid product. Under the licence model an override is an operator
// exception WITHIN a licence, and on Core there is no licence.
func TestIntegration_EditionGate_OverrideAloneGrantsNothingOnCore(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	requireCoreDatabase(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := services.NewLimitEnforcementService(db)

	if _, err := db.Exec(`
		INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from, expires_at)
		SELECT $1, bi.id, '{"enabled": true}'::jsonb, 'test: operator override', now() - interval '1 hour', now() + interval '30 days'
		FROM billable_items bi WHERE bi.key = 'custom_policies'`, tenant); err != nil {
		t.Fatalf("seed override: %v", err)
	}
	entitlements.FlushLicenseCache()
	allowed, err := svc.CheckFeatureAccess(tenant, "custom_policies")
	if err != nil {
		t.Fatalf("CheckFeatureAccess(custom_policies): %v", err)
	}
	if allowed {
		t.Error("CheckFeatureAccess(custom_policies) = true from an override on a Core install; " +
			"only a licence may unlock a paid capability")
	}
}

// TestIntegration_EditionGate_LicenceDecides walks one capability across every
// licence state through the real enforcement path (LimitEnforcementService →
// PostgresResolver → platform_license), on a database of its own because it
// writes the global licence row.
func TestIntegration_EditionGate_LicenceDecides(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	svc := services.NewLimitEnforcementService(db)
	t.Cleanup(entitlements.FlushLicenseCache)
	const pilot = "custom_policies"

	// A plan that includes the capability and one that does not — an MSP's
	// "Premium" and "Basic".
	premium := planGranting(t, db, pilot, true)
	basic := planGranting(t, db, pilot, false)
	onPremium := tenantOnPlan(t, db, premium)
	onBasic := tenantOnPlan(t, db, basic)
	switchedOff := tenantOnPlan(t, db, premium)
	if _, err := db.Exec(`
		INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from)
		SELECT $1, id, '{"enabled": false}'::jsonb, 'contractor tenant', now() - interval '1 hour'
		FROM billable_items WHERE key = $2`, switchedOff, pilot); err != nil {
		t.Fatalf("switch tenant off: %v", err)
	}

	setLicence := func(edition string) {
		t.Helper()
		if _, err := db.Exec(`DELETE FROM platform_license`); err != nil {
			t.Fatalf("clear licence: %v", err)
		}
		if edition != "" {
			if _, err := db.Exec(`INSERT INTO platform_license (subject, edition, expires_at, token_sha256)
				VALUES ('it', $1, now() + interval '1 day', 'x')`, edition); err != nil {
				t.Fatalf("write %s licence: %v", edition, err)
			}
		}
		entitlements.FlushLicenseCache()
	}
	expect := func(label string, tenant uuid.UUID, want bool) {
		t.Helper()
		got, err := svc.CheckFeatureAccess(tenant, pilot)
		if err != nil {
			t.Fatalf("%s: CheckFeatureAccess: %v", label, err)
		}
		if got != want {
			t.Errorf("%s: CheckFeatureAccess(%s) = %v, want %v", label, pilot, got, want)
		}
	}

	setLicence("")
	expect("Core, Premium plan", onPremium, false)
	expect("Core, Basic plan", onBasic, false)

	// MSP: the plan decides. This is the case the old "must come from an
	// override" rule made impossible.
	setLicence("msp")
	expect("MSP, Premium plan", onPremium, true)
	expect("MSP, Basic plan", onBasic, false)
	expect("MSP, Premium plan switched off", switchedOff, false)

	// Enterprise: every tenant, whatever its plan, unless switched off.
	setLicence("enterprise")
	expect("Enterprise, Premium plan", onPremium, true)
	expect("Enterprise, Basic plan", onBasic, true)
	expect("Enterprise, switched off", switchedOff, false)
}

func planGranting(t *testing.T, db *sql.DB, key string, enabled bool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	name := "it-plan-" + uuid.NewString()[:8]
	if err := db.QueryRow(`INSERT INTO subscription_tiers (name, display_name, is_active) VALUES ($1, $1, true) RETURNING id`, name).Scan(&id); err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tier_entitlements (tier_id, item_id, included_value)
		SELECT $1, id, jsonb_build_object('enabled', $3::boolean) FROM billable_items WHERE key = $2`, id, key, enabled); err != nil {
		t.Fatalf("compose plan: %v", err)
	}
	return id
}

func tenantOnPlan(t *testing.T, db *sql.DB, plan uuid.UUID) uuid.UUID {
	t.Helper()
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`UPDATE tenants SET subscription_tier_id = $1 WHERE id = $2`, plan, tenant); err != nil {
		t.Fatalf("assign plan: %v", err)
	}
	return tenant
}

// requireCoreDatabase asserts the shared test database carries no licence.
// Tests that write platform_license must use testdb.ScratchDatabase; a row here
// would turn every Core assertion into a test of something else.
func requireCoreDatabase(t *testing.T, db *sql.DB) {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_license`).Scan(&n); err != nil {
		t.Fatalf("count platform_license: %v", err)
	}
	if n != 0 {
		t.Fatal("the shared test database carries a platform_license row — a test wrote global licence state outside testdb.ScratchDatabase")
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
