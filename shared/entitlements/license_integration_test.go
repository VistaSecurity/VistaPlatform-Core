package entitlements_test

// DB-backed tests for the licence step: that Resolve, ResolveMany and
// GetQuantityInTx all apply it to rows the real SQL produced, that the default
// licence source really reads platform_license, and that the schema's v2
// migration removes only what the old token seeder wrote.
//
// The decision table itself is license_internal_test.go (DB-free). These tests
// exist because a correct table proves nothing if a resolution path skips it:
// delete the applyLicense call from Resolve, ResolveMany or GetQuantityInTx and
// one of these goes red.
//
// Tests that WRITE platform_license use testdb.ScratchDatabase — the row is
// global, and on the shared database it would change every other package's
// Core assertions while this test runs. Tests on the shared database inject
// the licence instead (entitlements.WithLicenseSource).
//
// Skip without TEST_DATABASE_URL (make test-integration-db / nightly).

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// tenantShapes builds one tenant per tenant-row state and returns them keyed by
// the state's name. The gated boolean is custom_policies, the capacity item is
// max_sensors.
//
//	nothing       no tier, no override            → catalogue defaults
//	tier grant    a tier granting it (quantity 5)
//	override on   no tier, override enabled / quantity 500
//	override off  the granting tier + override disabled / quantity 0
func tenantShapes(t *testing.T, db *sql.DB) map[string]uuid.UUID {
	t.Helper()
	tierName := "it-lic-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = $1)`, tierName)
		_, _ = db.Exec(`DELETE FROM tier_entitlements WHERE tier_id = (SELECT id FROM subscription_tiers WHERE name = $1)`, tierName)
		_, _ = db.Exec(`DELETE FROM subscription_tiers WHERE name = $1`, tierName)
	})
	mustExec(t, db, `INSERT INTO subscription_tiers (name, display_name, is_active) VALUES ($1, $1, false)`, tierName)
	mustExec(t, db, `
		INSERT INTO tier_entitlements (tier_id, item_id, included_value)
		SELECT st.id, bi.id, CASE bi.key WHEN 'custom_policies' THEN '{"enabled": true}'::jsonb ELSE '{"quantity": 5}'::jsonb END
		FROM subscription_tiers st, billable_items bi
		WHERE st.name = $1 AND bi.key IN ('custom_policies', 'max_sensors')`, tierName)

	onTier := func() uuid.UUID {
		id := testdb.NewTenant(t, db)
		mustExec(t, db, `UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = $1) WHERE id = $2`, tierName, id)
		return id
	}
	override := func(tenant uuid.UUID, boolVal, qty string) {
		mustExec(t, db, `
			INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from)
			SELECT $1, bi.id, CASE bi.key WHEN 'custom_policies' THEN $2::jsonb ELSE $3::jsonb END, 'it: operator exception', now() - interval '1 hour'
			FROM billable_items bi WHERE bi.key IN ('custom_policies', 'max_sensors')`, tenant, boolVal, qty)
	}

	shapes := map[string]uuid.UUID{
		"nothing":    testdb.NewTenant(t, db),
		"tier grant": onTier(),
	}
	on := testdb.NewTenant(t, db)
	override(on, `{"enabled": true}`, `{"quantity": 500}`)
	shapes["override on"] = on
	off := onTier()
	override(off, `{"enabled": false}`, `{"quantity": 0}`)
	shapes["override off"] = off
	return shapes
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

type licenceCase struct {
	name string
	src  entitlements.LicenseSource
}

func licenceCases() []licenceCase {
	expired := func(context.Context) (*entitlements.License, error) {
		return &entitlements.License{Edition: entitlements.EditionEnterprise, ExpiresAt: time.Now().Add(-time.Hour)}, nil
	}
	return []licenceCase{
		{"no licence", staticLicense(entitlements.EditionCore)},
		{"expired", expired},
		{"enterprise", staticLicense(entitlements.EditionEnterprise)},
		{"msp", staticLicense(entitlements.EditionMSP)},
	}
}

// want[licence][shape] = (custom_policies enabled, max_sensors quantity or -1 for unlimited)
var licenceMatrix = map[string]map[string][2]int{
	"no licence": {"nothing": {0, 0}, "tier grant": {0, 5}, "override on": {0, 500}, "override off": {0, 0}},
	"expired":    {"nothing": {0, 0}, "tier grant": {0, 5}, "override on": {0, 500}, "override off": {0, 0}},
	"enterprise": {"nothing": {1, -1}, "tier grant": {1, -1}, "override on": {1, 500}, "override off": {0, 0}},
	"msp":        {"nothing": {0, 0}, "tier grant": {1, 5}, "override on": {1, 500}, "override off": {0, 0}},
}

func checkPair(t *testing.T, label string, gated, capacity *entitlements.EffectiveEntitlement, want [2]int) {
	t.Helper()
	if gated == nil || capacity == nil {
		t.Fatalf("%s: missing result (gated=%v capacity=%v)", label, gated, capacity)
	}
	on, _ := gated.BooleanValue()
	if on != (want[0] == 1) {
		t.Errorf("%s: custom_policies enabled=%v (source %q), want %v", label, on, gated.Source, want[0] == 1)
	}
	qty, ok := capacity.QuantityValue()
	if !ok {
		t.Fatalf("%s: max_sensors value %s is malformed", label, capacity.Value)
	}
	got := -1
	if qty != nil {
		got = *qty
	}
	if got != want[1] {
		t.Errorf("%s: max_sensors=%d (source %q), want %d (-1 = unlimited)", label, got, capacity.Source, want[1])
	}
}

// TestIntegration_Resolver_LicenseStepOverRealRows runs the whole decision
// table against rows the real resolution SQL produced, through BOTH Resolve and
// ResolveMany.
func TestIntegration_Resolver_LicenseStepOverRealRows(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	shapes := tenantShapes(t, db)
	ctx := context.Background()

	for _, lc := range licenceCases() {
		r := entitlements.NewPostgresResolver(db, entitlements.WithLicenseSource(lc.src))
		for shape, tenant := range shapes {
			want := licenceMatrix[lc.name][shape]

			gated, err := r.Resolve(ctx, tenant, "custom_policies")
			if err != nil {
				t.Fatalf("%s × %s: Resolve: %v", lc.name, shape, err)
			}
			capacity, err := r.Resolve(ctx, tenant, "max_sensors")
			if err != nil {
				t.Fatalf("%s × %s: Resolve: %v", lc.name, shape, err)
			}
			checkPair(t, fmt.Sprintf("Resolve %s × %s", lc.name, shape), gated, capacity, want)

			many, err := r.ResolveMany(ctx, tenant, []string{"custom_policies", "max_sensors"})
			if err != nil {
				t.Fatalf("%s × %s: ResolveMany: %v", lc.name, shape, err)
			}
			checkPair(t, fmt.Sprintf("ResolveMany %s × %s", lc.name, shape), many["custom_policies"], many["max_sensors"], want)
		}
	}
}

// TestIntegration_Resolver_ReadsPlatformLicense drives the PRODUCTION licence
// source — no injection — against a database of its own, walking one install
// through Core → Enterprise → expired → MSP → Core.
func TestIntegration_Resolver_ReadsPlatformLicense(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	ctx := context.Background()
	r := entitlements.NewPostgresResolver(db)
	tenant := testdb.NewTenant(t, db) // no tier, no overrides
	t.Cleanup(entitlements.FlushLicenseCache)

	state := func(label string, wantGated bool, wantUnlimited bool) {
		t.Helper()
		entitlements.FlushLicenseCache()
		on, err := entitlements.IsEnabled(ctx, r, tenant, "custom_policies")
		if err != nil {
			t.Fatalf("%s: IsEnabled: %v", label, err)
		}
		if on != wantGated {
			t.Errorf("%s: custom_policies enabled=%v, want %v", label, on, wantGated)
		}
		qty, err := entitlements.GetQuantity(ctx, r, tenant, "max_sensors")
		if err != nil {
			t.Fatalf("%s: GetQuantity: %v", label, err)
		}
		if (qty == nil) != wantUnlimited {
			t.Errorf("%s: max_sensors=%v, want unlimited=%v", label, qty, wantUnlimited)
		}
		// GetQuantityInTx runs the SQL on the caller's transaction and must
		// apply the same step, read on that same transaction.
		err = shareddatabase.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
			q, err := entitlements.GetQuantityInTx(ctx, tx, tenant, "max_sensors")
			if err != nil {
				return err
			}
			if (q == nil) != wantUnlimited {
				t.Errorf("%s: GetQuantityInTx max_sensors=%v, want unlimited=%v", label, q, wantUnlimited)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%s: GetQuantityInTx: %v", label, err)
		}
	}
	writeLicence := func(edition string, expires time.Time) {
		t.Helper()
		mustExec(t, db, `
			INSERT INTO platform_license (subject, edition, licensee, expires_at, token_sha256)
			VALUES ('it-subject', $1, 'IT Licensee', $2, 'deadbeef')
			ON CONFLICT (singleton) DO UPDATE SET edition = EXCLUDED.edition, expires_at = EXCLUDED.expires_at`, edition, expires)
	}

	state("Core (no row)", false, false)

	writeLicence("enterprise", time.Now().Add(24*time.Hour))
	state("Enterprise", true, true)

	// The resolver re-checks expiry itself: an expired row admin-service has
	// not yet removed grants nothing.
	writeLicence("enterprise", time.Now().Add(-time.Minute))
	state("Enterprise, expired", false, false)

	// MSP: the tenant's plan decides, and this tenant has none.
	writeLicence("msp", time.Now().Add(24*time.Hour))
	state("MSP, tenant on no plan", false, false)

	mustExec(t, db, `DELETE FROM platform_license`)
	state("Core again (row removed)", false, false)
}

// The schema accepts exactly one licence row and only the two paid editions.
func TestIntegration_PlatformLicense_Constraints(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	insert := func(edition string) error {
		_, err := db.Exec(`INSERT INTO platform_license (subject, edition, expires_at, token_sha256)
			VALUES ('s', $1, now() + interval '1 day', 'x')`, edition)
		return err
	}
	if err := insert("core"); err == nil {
		t.Error("platform_license accepted edition 'core' — Core is the absence of a row")
	}
	if err := insert("msp"); err != nil {
		t.Fatalf("insert msp licence: %v", err)
	}
	if err := insert("enterprise"); err == nil {
		t.Error("platform_license accepted a second row — the install must have exactly one licence")
	}
	if _, err := db.Exec(`INSERT INTO platform_install (install_id) VALUES ($1)`, uuid.New()); err != nil {
		t.Fatalf("insert install id: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO platform_install (install_id) VALUES ($1)`, uuid.New()); err == nil {
		t.Error("platform_install accepted a second id — 'this install's id' would be ambiguous")
	}
}

// TestIntegration_Schema_LicenceModelV2Migration applies schema.sql over the
// state the previous release left — per-tenant rows written by the old token
// seeder, beside operator exceptions — and asserts the POST-MIGRATIONS block
// removes the seeder's rows and nothing else. Then checks the trial changes.
func TestIntegration_Schema_LicenceModelV2Migration(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	tenant := testdb.NewTenant(t, db)

	seeded := func(key, reason string, from string) {
		mustExec(t, db, `
			INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from, expires_at)
			SELECT $1, id, '{"enabled": true}'::jsonb, $2, `+from+`, now() + interval '300 days'
			FROM billable_items WHERE key = $3`, tenant, reason, key)
	}
	// Exactly what the old seeder wrote, two days running.
	seeded("custom_policies", "edition token: acme-corp-20260101 (Acme Corp)", "date_trunc('day', now())")
	seeded("custom_policies", "edition token: acme-corp-20260101 (Acme Corp)", "date_trunc('day', now()) - interval '1 day'")
	seeded("sso_saml", "edition token: acme-corp-20260101 (Acme Corp)", "date_trunc('day', now())")
	// A platform admin's own rows, including one whose reason merely mentions
	// the phrase further in.
	seeded("cbom_signing", "sales add-on", "now() - interval '1 hour'")
	seeded("cmdb_sync", "contractor: no edition token: access", "now() - interval '1 hour'")

	// The previous release's column default. A fresh apply already has
	// 'active' from CREATE TABLE, which proves nothing about an upgraded
	// database, where CREATE TABLE IF NOT EXISTS is a no-op — only the
	// POST-MIGRATIONS ALTER can change it there.
	mustExec(t, db, `ALTER TABLE tenants ALTER COLUMN payment_status SET DEFAULT 'trial'`)

	testdb.ForceApplySchema(t, db)

	var edition, operator int
	if err := db.QueryRow(`SELECT
		COUNT(*) FILTER (WHERE reason LIKE 'edition token:%'),
		COUNT(*) FILTER (WHERE reason NOT LIKE 'edition token:%')
		FROM tenant_entitlements WHERE tenant_id = $1`, tenant).Scan(&edition, &operator); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if edition != 0 {
		t.Errorf("%d edition-token row(s) survived the migration", edition)
	}
	if operator != 2 {
		t.Errorf("operator exception rows after migration = %d, want 2 — the cleanup deleted something it did not write", operator)
	}

	// No blanket trial: the column has no default, and a tenant on a non-trial
	// tier gets no trial end.
	var def sql.NullString
	if err := db.QueryRow(`SELECT column_default FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'tenants' AND column_name = 'trial_ends_at'`).Scan(&def); err != nil {
		t.Fatalf("read column default: %v", err)
	}
	if def.Valid {
		t.Errorf("tenants.trial_ends_at still has a default (%s)", def.String)
	}
	plain := testdb.NewTenant(t, db)
	mustExec(t, db, `UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community') WHERE id = $1`, plain)
	var ends sql.NullTime
	if err := db.QueryRow(`SELECT trial_ends_at FROM tenants WHERE id = $1`, plain).Scan(&ends); err != nil {
		t.Fatalf("read trial end: %v", err)
	}
	if ends.Valid {
		t.Errorf("a tenant created with no trial tier has trial_ends_at %s", ends.Time)
	}

	// No blanket 'trial' payment status either: a tenant inserted without one
	// (testdb.NewTenant writes only id, name, slug) is 'active'.
	var status string
	if err := db.QueryRow(`SELECT payment_status FROM tenants WHERE id = $1`, plain).Scan(&status); err != nil {
		t.Fatalf("read payment_status: %v", err)
	}
	if status != "active" {
		t.Errorf("a tenant created without a payment status has %q, want \"active\" — the upgraded column default is still 'trial'", status)
	}
}
