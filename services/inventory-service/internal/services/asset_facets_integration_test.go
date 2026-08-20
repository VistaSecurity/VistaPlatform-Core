package services

// Guard for B-44b: GetAssetFacets applied the risk_level filter as a HAVING
// over MAX(ci.risk_score) computed across the WHOLE facet bucket, because the
// query grouped straight by the facet key. One asset scoring 75 therefore
// reported every asset in its business unit as matching risk_level=high, and
// buckets vanished entirely for `unknown`. The asset list next to it does the
// right thing (buildAssetListWhereAndHaving returns the same predicate as
// havingConditions over a GROUP BY a.id).
//
// The same query also lacked the asset_status='monitoring' default the asset
// list applies, so facet counts described a different population than the list
// they filter.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AssetFacets_RiskLevelIsPerAsset(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	// riskScore < 0 means "no crypto configuration at all".
	newAsset := func(hostname, bu, status string, riskScore int) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO network_assets (id, tenant_id, hostname, business_unit, asset_type, asset_status,
			                            last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,'server',$5,NOW(),NOW(),NOW(),NOW())`,
			id, tenant, hostname, bu, status); err != nil {
			t.Fatalf("insert asset %s: %v", hostname, err)
		}
		if riskScore >= 0 {
			if _, err := db.Exec(`
				INSERT INTO crypto_implementations (
					id, tenant_id, asset_id, protocol, protocol_version, discovery_method, risk_score,
					last_verified_at, first_discovered_at, created_at, updated_at
				) VALUES ($1,$2,$3,'TLS','TLSv1.2','passive',$4,NOW(),NOW(),NOW(),NOW())`,
				uuid.New(), tenant, id, riskScore); err != nil {
				t.Fatalf("insert implementation on %s: %v", hostname, err)
			}
		}
		return id
	}

	// One business unit, one genuinely High asset (75) and three that are not.
	// Pre-fix, MAX(risk_score) over the whole "payments" bucket was 75, so all
	// four were reported as matching risk_level=high.
	newAsset("pay-1.example.test", "payments", "monitoring", 75)
	newAsset("pay-2.example.test", "payments", "monitoring", 10)
	newAsset("pay-3.example.test", "payments", "monitoring", 10)
	newAsset("pay-4.example.test", "payments", "monitoring", -1) // no crypto config → 0

	bucketFor := func(t *testing.T, riskLevel []string, key string) int {
		t.Helper()
		buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{RiskLevel: riskLevel}, "business_unit", 50)
		if err != nil {
			t.Fatalf("GetAssetFacets(risk_level=%v): %v", riskLevel, err)
		}
		for _, b := range buckets {
			if b.Key == key {
				return b.Count
			}
		}
		return 0
	}

	if got := bucketFor(t, nil, "payments"); got != 4 {
		t.Errorf("unfiltered payments bucket = %d, want 4", got)
	}
	if got := bucketFor(t, []string{"high"}, "payments"); got != 1 {
		t.Errorf("risk_level=high payments bucket = %d, want 1 — the HAVING must "+
			"aggregate per ASSET, not across the whole facet bucket (B-44b)", got)
	}
	if got := bucketFor(t, []string{"low"}, "payments"); got != 2 {
		t.Errorf("risk_level=low payments bucket = %d, want 2 (the two score-10 assets)", got)
	}
	// "unknown" is the Informational band [0,1) — the asset with no crypto
	// configuration at all. Pre-fix the bucket's MAX was 75 and this returned
	// nothing.
	if got := bucketFor(t, []string{"unknown"}, "payments"); got != 1 {
		t.Errorf("risk_level=unknown payments bucket = %d, want 1 — an asset with no "+
			"crypto configuration bands Informational (B-44b)", got)
	}
	// Coarse "high" means high AND ABOVE, so a Critical asset still matches it.
	newAsset("pay-5.example.test", "payments", "monitoring", 95)
	if got := bucketFor(t, []string{"high"}, "payments"); got != 2 {
		t.Errorf("risk_level=high payments bucket after adding a Critical asset = %d, want 2", got)
	}
}

func TestIntegration_AssetFacets_DefaultsToMonitoringScope(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	for _, spec := range []struct{ hostname, status string }{
		{"live-1.example.test", "monitoring"},
		{"live-2.example.test", "monitoring"},
		{"waiting.example.test", "pending_approval"},
	} {
		if _, err := db.Exec(`
			INSERT INTO network_assets (id, tenant_id, hostname, business_unit, asset_type, asset_status,
			                            last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,'ops','server',$4,NOW(),NOW(),NOW(),NOW())`,
			uuid.New(), tenant, spec.hostname, spec.status); err != nil {
			t.Fatalf("insert %s: %v", spec.hostname, err)
		}
	}

	count := func(t *testing.T, filters models.AssetFilters) int {
		t.Helper()
		buckets, err := svc.GetAssetFacets(tenant, filters, "business_unit", 50)
		if err != nil {
			t.Fatalf("GetAssetFacets: %v", err)
		}
		for _, b := range buckets {
			if b.Key == "ops" {
				return b.Count
			}
		}
		return 0
	}

	if got := count(t, models.AssetFilters{}); got != 2 {
		t.Errorf("default ops bucket = %d, want 2 — facets must default to the same "+
			"asset_status='monitoring' scope the asset list uses (B-44b), otherwise a "+
			"facet counts assets the list it filters never returns", got)
	}
	if got := count(t, models.AssetFilters{AssetStatus: []string{"pending_approval"}}); got != 1 {
		t.Errorf("ops bucket with an explicit asset_status = %d, want 1 — an explicit "+
			"filter must still override the default", got)
	}
}
