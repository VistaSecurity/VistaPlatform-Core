package entitlements_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// OT active probing moved from Enterprise to Core, as a switch every seeded
// tier ships ON (owner decision). These tests pin the three
// things that decision means, through the real resolver and the real seed:
//
//   - on by default in every edition, on every seeded tier;
//   - a per-tenant override OFF still wins — that override is the off-switch;
//   - its Enterprise neighbour, the OT inventory lens, did NOT move.

var seededTiers = []string{"community", "free", "starter", "pro", "enterprise"}

func resolveEnabled(t *testing.T, r entitlements.Resolver, tenant uuid.UUID, key string) (bool, entitlements.Source) {
	t.Helper()
	ent, err := r.Resolve(context.Background(), tenant, key)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", key, err)
	}
	on, ok := ent.BooleanValue()
	if !ok {
		t.Fatalf("Resolve(%s): value %s is not a boolean entitlement", key, ent.Value)
	}
	return on, ent.Source
}

func TestIntegration_OTActiveProbing_OnByDefaultInEveryEdition(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)

	for _, ed := range []entitlements.Edition{entitlements.EditionCore, entitlements.EditionEnterprise, entitlements.EditionMSP} {
		r := entitlements.NewPostgresResolver(db, entitlements.WithLicenseSource(staticLicense(ed)))
		for _, tier := range seededTiers {
			tenant := makeTenant(t, db, tier)
			on, src := resolveEnabled(t, r, tenant, "ot_active_probing")
			if !on {
				t.Errorf("%s licence, %s tier: ot_active_probing = off (source %s), want on — it is a Core capability, on by default", ed, tier, src)
			}
			if src != entitlements.SourceTier {
				t.Errorf("%s licence, %s tier: ot_active_probing came from %s, want the tier row", ed, tier, src)
			}
		}
	}

	// The neighbour that did NOT move: under Core the OT lens stays denied on
	// every seeded tier, including one an admin edited to grant it.
	core := entitlements.NewPostgresResolver(db, entitlements.WithLicenseSource(staticLicense(entitlements.EditionCore)))
	for _, tier := range seededTiers {
		if on, _ := resolveEnabled(t, core, makeTenant(t, db, tier), "ot_primary_lens"); on {
			t.Errorf("Core, %s tier: ot_primary_lens enabled — only OT active probing moved to Core", tier)
		}
	}
	if on, _ := resolveEnabled(t, core, makeTierGrantingBoolean(t, db, "ot_primary_lens"), "ot_primary_lens"); on {
		t.Error("Core, tier granting ot_primary_lens: enabled — it is still Enterprise-gated")
	}
}

// The production resolver with no injected licence, on a database with no
// platform_license row: what a real Core install resolves.
func TestIntegration_OTActiveProbing_OnForACoreInstall(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	requireNoLicenceRow(t, db)
	entitlements.FlushLicenseCache()
	r := entitlements.NewPostgresResolver(db)

	on, err := entitlements.IsEnabled(context.Background(), r, makeTenant(t, db, "community"), "ot_active_probing")
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if !on {
		t.Error("Core install, community tier: ot_active_probing is off, want on")
	}
}

func TestIntegration_OTActiveProbing_TenantOverrideOffWins(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)

	for _, ed := range []entitlements.Edition{entitlements.EditionCore, entitlements.EditionEnterprise, entitlements.EditionMSP} {
		r := entitlements.NewPostgresResolver(db, entitlements.WithLicenseSource(staticLicense(ed)))
		tenant := makeTenant(t, db, "community")

		// Premise: the tier says on, or the override would be proving nothing.
		if on, src := resolveEnabled(t, r, tenant, "ot_active_probing"); !on || src != entitlements.SourceTier {
			t.Fatalf("%s premise: community tier should grant ot_active_probing (on=%v source=%s)", ed, on, src)
		}
		mustExec(t, db, `
			INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from)
			VALUES ($1, (SELECT id FROM billable_items WHERE key = 'ot_active_probing'),
			        '{"enabled": false}'::jsonb, 'operator switched OT probing off', NOW() - INTERVAL '1 minute')`, tenant)

		on, src := resolveEnabled(t, r, tenant, "ot_active_probing")
		if on {
			t.Errorf("%s licence: tier on + tenant override off resolved ON — the override is the off-switch and must win", ed)
		}
		if src != entitlements.SourceOverride {
			t.Errorf("%s licence: source = %s, want override", ed, src)
		}
	}
}

// TestIntegration_OTActiveProbing_SeedConvergesAPreCoreInstall plants what an
// install seeded while OT active probing was Enterprise carries — every tier
// row false, catalogue default false, add-on price 14900, the features JSON on
// Enterprise only — and re-applies seed.sql, which is exactly what the chart's
// seed-data Job does on helm upgrade.
//
// It runs on a scratch database because it rewrites GLOBAL catalogue rows
// (billable_items, tier_entitlements) that every other test binary resolves
// through.
func TestIntegration_OTActiveProbing_SeedConvergesAPreCoreInstall(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	core := entitlements.NewPostgresResolver(db, entitlements.WithLicenseSource(staticLicense(entitlements.EditionCore)))

	// A fresh install (the scratch database was just seeded from nothing) is
	// born converged — the INSERTs carry the new values, the correction below
	// is not what makes it right.
	for _, tier := range seededTiers {
		if v := tierValue(t, db, tier); v != "true" {
			t.Errorf("fresh install: %s tier ot_active_probing enabled = %s, want true", tier, v)
		}
	}
	if defaultOn, price := catalogueRow(t, db); defaultOn != "true" || price != 0 {
		t.Errorf("fresh install: catalogue default enabled=%s price=%d, want true / 0", defaultOn, price)
	}

	// An MSP's own plan, not one the seed knows by name.
	mustExec(t, db, `INSERT INTO subscription_tiers (name, display_name, is_active) VALUES ('msp-gold', 'MSP Gold', true)`)
	mustExec(t, db, `
		INSERT INTO tier_entitlements (tier_id, item_id, included_value)
		SELECT st.id, bi.id, '{"enabled": false}'::jsonb
		FROM subscription_tiers st, billable_items bi
		WHERE st.name = 'msp-gold' AND bi.key = 'ot_active_probing'`)

	// The pre-change state, as the old seed left it.
	mustExec(t, db, `UPDATE tier_entitlements SET included_value = '{"enabled": false}'::jsonb
		WHERE item_id = (SELECT id FROM billable_items WHERE key = 'ot_active_probing')`)
	mustExec(t, db, `UPDATE billable_items SET default_value = '{"enabled": false}'::jsonb, default_addon_price_cents = 14900
		WHERE key = 'ot_active_probing'`)
	mustExec(t, db, `UPDATE subscription_tiers SET features = features - 'ot_active_probing' WHERE name <> 'enterprise'`)
	mustExec(t, db, `UPDATE subscription_tiers SET features = features || '{"ot_active_probing":true}'::jsonb WHERE name = 'enterprise'`)

	// A tenant whose operator had deliberately switched it off.
	switchedOff := makeTenant(t, db, "community")
	mustExec(t, db, `
		INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from)
		VALUES ($1, (SELECT id FROM billable_items WHERE key = 'ot_active_probing'),
		        '{"enabled": false}'::jsonb, 'operator switched OT probing off', NOW() - INTERVAL '1 minute')`, switchedOff)
	plain := makeTenant(t, db, "community")

	// Premise: the planted state really is "off", or the convergence below
	// would be proving nothing.
	if on, _ := resolveEnabled(t, core, plain, "ot_active_probing"); on {
		t.Fatal("premise: the planted pre-Core state should resolve ot_active_probing off")
	}

	testdb.ForceApplySeed(t, db)

	for _, tier := range append(append([]string(nil), seededTiers...), "msp-gold") {
		if v := tierValue(t, db, tier); v != "true" {
			t.Errorf("after upgrade: %s tier ot_active_probing enabled = %s, want true", tier, v)
		}
	}
	for _, tier := range seededTiers {
		var f sql.NullString
		if err := db.QueryRow(`SELECT features->>'ot_active_probing' FROM subscription_tiers WHERE name = $1`, tier).Scan(&f); err != nil {
			t.Fatalf("read %s features: %v", tier, err)
		}
		if f.String != "true" {
			t.Errorf("after upgrade: %s features.ot_active_probing = %q, want true (the display JSON must agree with the entitlement row)", tier, f.String)
		}
	}
	defaultOn, price := catalogueRow(t, db)
	if defaultOn != "true" || price != 0 {
		t.Errorf("after upgrade: catalogue default enabled=%s price=%d, want true / 0", defaultOn, price)
	}
	if on, _ := resolveEnabled(t, core, plain, "ot_active_probing"); !on {
		t.Error("after upgrade: a Core tenant on community resolves ot_active_probing off, want on")
	}
	if on, src := resolveEnabled(t, core, switchedOff, "ot_active_probing"); on || src != entitlements.SourceOverride {
		t.Errorf("after upgrade: the tenant switched off by override resolves on=%v (source %s) — the upgrade must not override an operator's off-switch", on, src)
	}
	if on, _ := resolveEnabled(t, core, plain, "ot_primary_lens"); on {
		t.Error("after upgrade: ot_primary_lens resolves on under Core — the correction must not touch the lens")
	}

	// After the upgrade an operator switches OT probing off for one plan and
	// re-prices the catalogue item. The next upgrade must leave both alone:
	// the correction is one-shot, not a rule re-imposed on every seed run.
	mustExec(t, db, `UPDATE tier_entitlements SET included_value = '{"enabled": false}'::jsonb
		WHERE item_id = (SELECT id FROM billable_items WHERE key = 'ot_active_probing')
		  AND tier_id = (SELECT id FROM subscription_tiers WHERE name = 'starter')`)
	mustExec(t, db, `UPDATE billable_items SET default_addon_price_cents = 14900 WHERE key = 'ot_active_probing'`)

	testdb.ForceApplySeed(t, db)

	if v := tierValue(t, db, "starter"); v != "false" {
		t.Errorf("second upgrade re-enabled starter's ot_active_probing (%s) — an operator's off-switch was undone", v)
	}
	if v := tierValue(t, db, "pro"); v != "true" {
		t.Errorf("second upgrade changed pro's ot_active_probing to %s", v)
	}
	if _, price := catalogueRow(t, db); price != 14900 {
		t.Errorf("second upgrade re-priced the catalogue item to %d — an operator's price was undone", price)
	}
}

func tierValue(t *testing.T, db *sql.DB, tier string) string {
	t.Helper()
	var v sql.NullString
	if err := db.QueryRow(`
		SELECT te.included_value->>'enabled'
		FROM tier_entitlements te
		JOIN subscription_tiers st ON st.id = te.tier_id
		JOIN billable_items bi ON bi.id = te.item_id
		WHERE st.name = $1 AND bi.key = 'ot_active_probing'`, tier).Scan(&v); err != nil {
		t.Fatalf("read %s tier ot_active_probing: %v", tier, err)
	}
	return v.String
}

func catalogueRow(t *testing.T, db *sql.DB) (defaultEnabled string, priceCents int) {
	t.Helper()
	var p sql.NullInt64
	if err := db.QueryRow(`SELECT default_value->>'enabled', default_addon_price_cents FROM billable_items WHERE key = 'ot_active_probing'`).
		Scan(&defaultEnabled, &p); err != nil {
		t.Fatalf("read ot_active_probing catalogue row: %v", err)
	}
	return defaultEnabled, int(p.Int64)
}
