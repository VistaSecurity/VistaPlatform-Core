package entitlements_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// These tests need a real Postgres because the resolver is one SQL statement
// whose correctness depends on Postgres jsonb semantics and CTE evaluation
// order. Set TEST_DATABASE_URL to a connection string for a throwaway
// database; the test harness applies schema.sql + seed.sql once per process
// and creates an isolated tenant per test.
//
// Example (local docker):
//   docker run -d --rm --name testpg -e POSTGRES_PASSWORD=p -e POSTGRES_DB=test \
//     -p 15433:5432 postgres:17-alpine
//   TEST_DATABASE_URL='postgres://postgres:p@localhost:15433/test?sslmode=disable' go test ./entitlements/...

const skipMessage = "TEST_DATABASE_URL not set; skipping DB-backed entitlement resolver tests"

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip(skipMessage)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test db: %v", err)
	}
	return db
}

// applySchemaAndSeed primes the test database. Delegates to the shared
// harness, which serializes concurrent appliers across parallel test binaries
// with a Postgres advisory lock (schema.sql's GRANT statements fail with
// "tuple concurrently updated" when applied concurrently).
func applySchemaAndSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	testdb.ApplySchemaAndSeed(t, db)
}

// makeTenant inserts a minimal tenant row keyed to a tier name and returns
// its UUID. Each test gets a fresh tenant so per-tenant override state
// doesn't leak between cases.
func makeTenant(t *testing.T, db *sql.DB, tierName string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name=$4), NOW(), NOW())
	`, id, "test-"+id.String()[:8], "test-"+id.String()[:8], tierName)
	if err != nil {
		t.Fatalf("create tenant on tier %s: %v", tierName, err)
	}
	return id
}

// setupResolver returns a primed DB and a fresh tenant on the named tier.
func setupResolver(t *testing.T, tier string) (*entitlements.PostgresResolver, *sql.DB, uuid.UUID) {
	t.Helper()
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	r := entitlements.NewPostgresResolver(db)
	tenant := makeTenant(t, db, tier)
	return r, db, tenant
}

// makeTierGrantingBoolean creates a throwaway subscription tier that grants
// `key` and returns a fresh tenant on it.
//
// It exists because after the open-core carve NO seeded tier grants ANY boolean
// capability: every boolean item in the catalogue is edition-gated, and the
// seed's "edition-gate correction" UPDATE forces all of them to
// `{"enabled": false}` on every tier (see the invariant pinned by
// TestResolve_EditionGatedCapabilitiesNeverGrantedByTier below). Reading the
// resolver's tier-boolean-true path off the seed is therefore no longer
// possible — and the tests that tried to broke the nightly for a month.
// A private tier keeps this test about the resolver instead of about the seed,
// and cannot leak into other tests the way mutating `pro` would.
func makeTierGrantingBoolean(t *testing.T, db *sql.DB, key string) uuid.UUID {
	t.Helper()
	tierName := "test-tier-" + uuid.New().String()[:8]
	_, err := db.Exec(`
		INSERT INTO subscription_tiers (name, display_name, is_active)
		VALUES ($1, $1, true)
	`, tierName)
	if err != nil {
		t.Fatalf("create throwaway tier: %v", err)
	}
	_, err = db.Exec(`
		INSERT INTO tier_entitlements (tier_id, item_id, included_value)
		VALUES (
		    (SELECT id FROM subscription_tiers WHERE name=$1),
		    (SELECT id FROM billable_items WHERE key=$2),
		    '{"enabled": true}'::jsonb
		)
	`, tierName, key)
	if err != nil {
		t.Fatalf("grant %s on throwaway tier: %v", key, err)
	}
	return makeTenant(t, db, tierName)
}

func TestResolve_TierBoolean_Enabled(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	r := entitlements.NewPostgresResolver(db)
	tenant := makeTierGrantingBoolean(t, db, "ot_active_probing")

	ent, err := r.Resolve(context.Background(), tenant, "ot_active_probing")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ent.Source != entitlements.SourceTier {
		t.Errorf("Source = %s, want %s", ent.Source, entitlements.SourceTier)
	}
	enabled, ok := ent.BooleanValue()
	if !ok || !enabled {
		t.Errorf("tier-granted ot_active_probing should be enabled=true, got enabled=%v ok=%v", enabled, ok)
	}
}

// TestResolve_EditionGatedCapabilitiesNeverGrantedByTier pins the open-core
// invariant that broke the two tests above: no subscription tier may grant an
// edition-gated capability, because seed.sql ships in the public repository and
// a platform admin could otherwise unlock every paid capability from the tier
// editor. Edition-gated capability arrives as a tenant_entitlements override
// written by the entitlement-token seeder, and overrides outrank tiers.
//
// Keep the key list in step with editionByItem in editions.go and with the
// corrective UPDATE at the bottom of scripts/database/seed.sql; `make audit`
// enforces the same partition.
func TestResolve_EditionGatedCapabilitiesNeverGrantedByTier(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	r := entitlements.NewPostgresResolver(db)

	gated := []string{
		"custom_policies", "threshold_overrides",
		"ot_active_probing", "ot_primary_lens",
		"cbom_signing", "sso_saml", "custom_branding",
		"cmdb_sync", "siem_export", "billing_portal",
	}

	rows, err := db.Query(`SELECT name FROM subscription_tiers WHERE is_active`)
	if err != nil {
		t.Fatalf("list tiers: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var tiers []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan tier: %v", err)
		}
		tiers = append(tiers, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate tiers: %v", err)
	}
	if len(tiers) == 0 {
		t.Fatal("no seeded tiers found; seed.sql did not apply")
	}

	for _, tier := range tiers {
		tenant := makeTenant(t, db, tier)
		for _, key := range gated {
			ent, err := r.Resolve(context.Background(), tenant, key)
			if err != nil {
				t.Fatalf("Resolve(%s) on tier %s: %v", key, tier, err)
			}
			if enabled, _ := ent.BooleanValue(); enabled {
				t.Errorf("tier %q grants edition-gated %q — tiers must never grant paid capability", tier, key)
			}
		}
	}
}

func TestResolve_TierBoolean_Disabled(t *testing.T) {
	r, _, tenant := setupResolver(t, "starter")

	ent, err := r.Resolve(context.Background(), tenant, "ot_active_probing")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	enabled, ok := ent.BooleanValue()
	if !ok || enabled {
		t.Errorf("ot_active_probing on Starter should be enabled=false, got enabled=%v ok=%v", enabled, ok)
	}
}

func TestResolve_TierQuantity(t *testing.T) {
	r, _, tenant := setupResolver(t, "pro")

	qty, err := entitlements.GetQuantity(context.Background(), r, tenant, "max_sensors")
	if err != nil {
		t.Fatalf("GetQuantity: %v", err)
	}
	if qty == nil || *qty != 25 {
		t.Errorf("max_sensors on Pro = %v, want 25", qty)
	}
}

func TestResolve_UnlimitedQuantity(t *testing.T) {
	r, _, tenant := setupResolver(t, "enterprise")

	qty, err := entitlements.GetQuantity(context.Background(), r, tenant, "max_sensors")
	if err != nil {
		t.Fatalf("GetQuantity: %v", err)
	}
	if qty != nil {
		t.Errorf("max_sensors on Enterprise should be unlimited (nil), got %v", *qty)
	}
}

func TestResolve_OverrideBeatsTier(t *testing.T) {
	r, db, tenant := setupResolver(t, "starter")

	// Grant ot_active_probing as an active override even though Starter
	// doesn't include it. Sales would do this for a customer add-on.
	_, err := db.Exec(`
		INSERT INTO tenant_entitlements
		    (tenant_id, item_id, override_value, reason, effective_from)
		VALUES (
		    $1,
		    (SELECT id FROM billable_items WHERE key='ot_active_probing'),
		    '{"enabled": true}'::jsonb,
		    'sales addon',
		    NOW() - INTERVAL '1 day'
		)
	`, tenant)
	if err != nil {
		t.Fatalf("insert override: %v", err)
	}

	ent, err := r.Resolve(context.Background(), tenant, "ot_active_probing")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ent.Source != entitlements.SourceOverride {
		t.Errorf("Source = %s, want %s", ent.Source, entitlements.SourceOverride)
	}
	enabled, _ := ent.BooleanValue()
	if !enabled {
		t.Errorf("override should enable ot_active_probing on Starter")
	}
}

func TestResolve_ExpiredOverrideIgnored(t *testing.T) {
	r, db, tenant := setupResolver(t, "starter")

	_, err := db.Exec(`
		INSERT INTO tenant_entitlements
		    (tenant_id, item_id, override_value, reason, effective_from, expires_at)
		VALUES (
		    $1,
		    (SELECT id FROM billable_items WHERE key='ot_active_probing'),
		    '{"enabled": true}'::jsonb,
		    'expired trial',
		    NOW() - INTERVAL '30 days',
		    NOW() - INTERVAL '1 day'
		)
	`, tenant)
	if err != nil {
		t.Fatalf("insert expired override: %v", err)
	}

	ent, err := r.Resolve(context.Background(), tenant, "ot_active_probing")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ent.Source == entitlements.SourceOverride {
		t.Errorf("Source should be tier (not override) for expired override; got %s", ent.Source)
	}
	enabled, _ := ent.BooleanValue()
	if enabled {
		t.Errorf("expired override should not enable ot_active_probing on Starter")
	}
}

func TestResolve_FutureOverrideIgnored(t *testing.T) {
	r, db, tenant := setupResolver(t, "starter")

	_, err := db.Exec(`
		INSERT INTO tenant_entitlements
		    (tenant_id, item_id, override_value, reason, effective_from)
		VALUES (
		    $1,
		    (SELECT id FROM billable_items WHERE key='ot_active_probing'),
		    '{"enabled": true}'::jsonb,
		    'scheduled future grant',
		    NOW() + INTERVAL '1 day'
		)
	`, tenant)
	if err != nil {
		t.Fatalf("insert future override: %v", err)
	}

	ent, err := r.Resolve(context.Background(), tenant, "ot_active_probing")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ent.Source == entitlements.SourceOverride {
		t.Errorf("future override should not yet apply; got Source=%s", ent.Source)
	}
}

func TestResolve_UnknownItem(t *testing.T) {
	r, _, tenant := setupResolver(t, "pro")

	_, err := r.Resolve(context.Background(), tenant, "no_such_item")
	if !errors.Is(err, entitlements.ErrUnknownItem) {
		t.Errorf("want ErrUnknownItem, got %v", err)
	}
}

func TestIsEnabled(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	r := entitlements.NewPostgresResolver(db)
	// Same reason as TestResolve_TierBoolean_Enabled: no seeded tier grants a
	// boolean any more, so the true branch needs a tier of its own.
	tenant := makeTierGrantingBoolean(t, db, "ot_active_probing")

	ok, err := entitlements.IsEnabled(context.Background(), r, tenant, "ot_active_probing")
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if !ok {
		t.Error("IsEnabled(ot_active_probing) on a tier that grants it should be true")
	}

	ok, err = entitlements.IsEnabled(context.Background(), r, tenant, "sso_saml")
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if ok {
		t.Error("IsEnabled(sso_saml) should be false when the tier does not grant it")
	}
}

func TestCheckCap_Allowed(t *testing.T) {
	r, _, tenant := setupResolver(t, "pro")

	cc, err := entitlements.CheckCap(context.Background(), r, tenant, "max_sensors", 5, 1, "upgrade for more")
	if err != nil {
		t.Fatalf("CheckCap: %v", err)
	}
	if !cc.Allowed {
		t.Errorf("5+1 should be allowed under 25; got %+v", cc)
	}
	if cc.Limit == nil || *cc.Limit != 25 {
		t.Errorf("Limit = %v, want 25", cc.Limit)
	}
}

func TestCheckCap_Denied(t *testing.T) {
	r, _, tenant := setupResolver(t, "pro")

	cc, err := entitlements.CheckCap(context.Background(), r, tenant, "max_sensors", 25, 1, "upgrade for more")
	if err != nil {
		t.Fatalf("CheckCap: %v", err)
	}
	if cc.Allowed {
		t.Errorf("25+1 should be denied at cap 25; got %+v", cc)
	}
	if cc.UpgradePrompt == "" {
		t.Errorf("denied result should carry upgrade prompt")
	}
}

func TestCheckCap_Unlimited(t *testing.T) {
	r, _, tenant := setupResolver(t, "enterprise")

	cc, err := entitlements.CheckCap(context.Background(), r, tenant, "max_sensors", 9999, 1, "upgrade for more")
	if err != nil {
		t.Fatalf("CheckCap: %v", err)
	}
	if !cc.Allowed {
		t.Errorf("unlimited cap should always allow; got %+v", cc)
	}
	if cc.Limit != nil {
		t.Errorf("Limit should be nil (unlimited); got %v", *cc.Limit)
	}
}

func TestResolveMany(t *testing.T) {
	r, _, tenant := setupResolver(t, "pro")

	got, err := r.ResolveMany(context.Background(), tenant,
		[]string{"max_sensors", "ot_active_probing", "sso_saml", "no_such_item"})
	if err != nil {
		t.Fatalf("ResolveMany: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("want 3 keys resolved (unknown silently absent); got %d: %v",
			len(got), keysOf(got))
	}
	if _, ok := got["no_such_item"]; ok {
		t.Errorf("unknown key should not appear in result")
	}
	if ent, ok := got["max_sensors"]; !ok {
		t.Errorf("max_sensors should be present")
	} else if qty, _ := ent.QuantityValue(); qty == nil || *qty != 25 {
		t.Errorf("max_sensors quantity = %v, want 25", qty)
	}
}

// TestResolve_OverageFieldsUnseededAfterDemolition pins the post- state:
// the metered-overage billing pipeline was removed and the seed no longer
// populates per-tier overage prices (the overage_price_cents/overage_unit_size
// columns on tier_entitlements are kept only as unread catalog metadata). The
// resolver still SELECTs those columns, so this also proves the read path stays
// error-free — it just resolves to nil now. If overage seed values are ever
// re-added, this guard flags it so the billing side is reconsidered too.
func TestResolve_OverageFieldsUnseededAfterDemolition(t *testing.T) {
	r, _, tenant := setupResolver(t, "pro")

	ent, err := r.Resolve(context.Background(), tenant, "storage_gb")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ent.OveragePriceCents != nil {
		t.Errorf("storage_gb overage price should be unseeded (nil) after the overage-pipeline removal; got %v", *ent.OveragePriceCents)
	}
	if ent.OverageUnitSize != nil {
		t.Errorf("storage_gb overage unit should be unseeded (nil) after the overage-pipeline removal; got %v", *ent.OverageUnitSize)
	}
}

func TestResolve_EnumSupport(t *testing.T) {
	r, _, tenant := setupResolver(t, "enterprise")

	v, err := entitlements.GetEnum(context.Background(), r, tenant, "support_sla_tier")
	if err != nil {
		t.Fatalf("GetEnum: %v", err)
	}
	if v != "premium" {
		t.Errorf("support_sla_tier on Enterprise = %s, want premium", v)
	}
}

func TestResolve_TenantWithoutTier_FallsToDefault(t *testing.T) {
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	r := entitlements.NewPostgresResolver(db)

	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, id, "no-tier-"+id.String()[:8], "no-tier-"+id.String()[:8])
	if err != nil {
		t.Fatalf("create tenant without tier: %v", err)
	}

	ent, err := r.Resolve(context.Background(), id, "ot_active_probing")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ent.Source != entitlements.SourceDefault {
		t.Errorf("Source = %s, want %s (no tier should fall to default_value)", ent.Source, entitlements.SourceDefault)
	}
}

// guards against accidental ExpiresAt regression.
func TestResolve_OverrideExpiryThreshold(t *testing.T) {
	r, db, tenant := setupResolver(t, "starter")

	// expires_at exactly NOW() must be treated as expired (strict inequality
	// in the WHERE clause: expires_at > NOW()).
	at := time.Now().Add(-1 * time.Millisecond)
	_, err := db.Exec(`
		INSERT INTO tenant_entitlements
		    (tenant_id, item_id, override_value, reason, effective_from, expires_at)
		VALUES (
		    $1,
		    (SELECT id FROM billable_items WHERE key='ot_active_probing'),
		    '{"enabled": true}'::jsonb,
		    'just-expired',
		    NOW() - INTERVAL '1 day',
		    $2
		)
	`, tenant, at)
	if err != nil {
		t.Fatalf("insert just-expired override: %v", err)
	}

	ent, err := r.Resolve(context.Background(), tenant, "ot_active_probing")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ent.Source == entitlements.SourceOverride {
		t.Errorf("just-expired override should not apply; got Source=%s", ent.Source)
	}
}

func keysOf(m map[string]*entitlements.EffectiveEntitlement) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
