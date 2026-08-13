package services

// Guards for post-quantum readiness classification.
//
// The old implementation summed per-algorithm-FAMILY counts over a
// per-IMPLEMENTATION denominator (so one implementation contributed to several
// families and the percentage could exceed 100%), and decided "quantum safe"
// from an allowlist of primitives {ae, hash, mac} — which silently treated
// everything it forgot as needing migration, including plain AES128/AES256.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type pqcFixture struct {
	db     *database.DB
	tenant uuid.UUID
	asset  uuid.UUID
}

func newPQCFixture(t *testing.T) pqcFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'pqc.example.test','server','monitoring',NOW(),NOW(),NOW(),NOW())`, asset, tenant); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return pqcFixture{db: db, tenant: tenant, asset: asset}
}

// addImpl creates a crypto implementation and links the named catalogue
// algorithms under the given component roles.
func (f pqcFixture) addImpl(t *testing.T, components map[string]string) uuid.UUID {
	t.Helper()
	implID := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',NOW(),NOW())`, implID, f.tenant, f.asset); err != nil {
		t.Fatalf("insert implementation: %v", err)
	}
	for role, code := range components {
		var algID uuid.UUID
		if err := f.db.QueryRow(`SELECT id FROM algorithms WHERE code = $1`, code).Scan(&algID); err != nil {
			t.Fatalf("catalogue lookup %q (is it seeded?): %v", code, err)
		}
		if _, err := f.db.Exec(`
			INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
			VALUES ($1,$2,$3,false)`, implID, algID, role); err != nil {
			t.Fatalf("link %s=%s: %v", role, code, err)
		}
	}
	return implID
}

// An AES-only implementation uses no asymmetric cryptography, so it needs no
// PQC migration. The allowlist {ae, hash, mac} did not contain 'block-cipher',
// so plain AES counted as NEEDING migration.
func TestIntegration_PQC_SymmetricOnlyIsNotAMigrationTarget(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"symmetric": "AES256"})

	got, err := classifyTenantImplementationsPQC(f.db, f.tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if got.NeedsMigration != 0 {
		t.Errorf("AES256-only implementation counted as needing migration (needs=%d) — "+
			"symmetric ciphers are weakened by Grover, not broken by Shor", got.NeedsMigration)
	}
	if got.SymmetricSafe != 1 {
		t.Errorf("symmetric_safe = %d, want 1", got.SymmetricSafe)
	}
}

// The core precedence rule: ANY classical asymmetric component makes the whole
// implementation quantum-vulnerable, whatever else it uses. The old code counted
// this one's AES toward "symmetric safe" and reported it protected.
func TestIntegration_PQC_ClassicalAsymmetricDominates(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"key_exchange": "ECDHE", "symmetric": "AES256", "hash": "SHA256"})

	got, err := classifyTenantImplementationsPQC(f.db, f.tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if got.NeedsMigration != 1 {
		t.Errorf("needs_migration = %d, want 1 — a classical key exchange is Shor-breakable "+
			"regardless of the bulk cipher", got.NeedsMigration)
	}
	if got.SymmetricSafe != 0 {
		t.Errorf("symmetric_safe = %d, want 0 — the AES component must not mask the classical key exchange", got.SymmetricSafe)
	}
}

// Categories must partition the population, so the percentage is bounded.
func TestIntegration_PQC_CategoriesPartitionAndPercentIsBounded(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"key_exchange": "ECDHE", "symmetric": "AES256"}) // needs migration
	f.addImpl(t, map[string]string{"symmetric": "AES128"})                          // symmetric safe
	f.addImpl(t, map[string]string{"key_exchange": "ML-KEM-768"})                   // pqc ready
	f.addImpl(t, nil)                                                               // unclassified

	got, err := classifyTenantImplementationsPQC(f.db, f.tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	sum := got.NeedsMigration + got.PQCReady + got.SymmetricSafe + got.Unclassified
	if sum != got.Total {
		t.Errorf("categories sum to %d but total = %d (needs=%d pqc=%d sym=%d unclassified=%d)",
			sum, got.Total, got.NeedsMigration, got.PQCReady, got.SymmetricSafe, got.Unclassified)
	}
	if got.Total != 4 {
		t.Fatalf("total = %d, want 4", got.Total)
	}
	if got.NeedsMigration != 1 || got.SymmetricSafe != 1 || got.PQCReady != 1 || got.Unclassified != 1 {
		t.Errorf("want one of each; got needs=%d pqc=%d sym=%d unclassified=%d",
			got.NeedsMigration, got.PQCReady, got.SymmetricSafe, got.Unclassified)
	}
	if p := got.ReadyPercent(); p < 0 || p > 100 {
		t.Errorf("ReadyPercent() = %v, must be within 0..100", p)
	}
}

// A PQC key exchange alongside a classical signature is still vulnerable —
// NIST IR 8547 disallows RSA/ECDSA after 2035, so a hybrid is not "ready".
func TestIntegration_PQC_HybridWithClassicalSignatureIsNotReady(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"key_exchange": "ML-KEM-768", "signature": "RSA-2048"})

	got, err := classifyTenantImplementationsPQC(f.db, f.tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if got.PQCReady != 0 || got.NeedsMigration != 1 {
		t.Errorf("hybrid ML-KEM + RSA signature: pqc_ready=%d needs_migration=%d, want 0 and 1",
			got.PQCReady, got.NeedsMigration)
	}
}

// Container rows (protocol_version, cipher_suite) carry primitive 'other'/NULL.
// If the classifier counted them, virtually every implementation would be
// unclassified, since ingest links one of each.
func TestIntegration_PQC_ContainerRowsDoNotMakeEverythingUnclassified(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{
		"protocol_version": "TLS1.2",
		"symmetric":        "AES256",
	})

	got, err := classifyTenantImplementationsPQC(f.db, f.tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if got.Unclassified != 0 {
		t.Errorf("unclassified = %d, want 0 — a linked protocol_version row must not "+
			"defeat classification of the real components", got.Unclassified)
	}
	if got.SymmetricSafe != 1 {
		t.Errorf("symmetric_safe = %d, want 1", got.SymmetricSafe)
	}
}

// Both PQC endpoints must agree, since they now share one classifier.
func TestIntegration_PQC_ProgressAndSummaryAgree(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"key_exchange": "ECDHE", "symmetric": "AES256"})
	f.addImpl(t, map[string]string{"symmetric": "AES128"})
	f.addImpl(t, map[string]string{"key_exchange": "ML-KEM-768"})

	algSvc := &AlgorithmService{db: f.db}
	assetSvc := &AssetService{db: f.db}

	progress, err := algSvc.GetPQCProgress(f.tenant)
	if err != nil {
		t.Fatalf("GetPQCProgress: %v", err)
	}
	summary, err := assetSvc.GetPQCReadinessSummary(f.tenant)
	if err != nil {
		t.Fatalf("GetPQCReadinessSummary: %v", err)
	}

	if progress.TotalImplementations != summary.TotalImplementations {
		t.Errorf("totals disagree: progress=%d summary=%d",
			progress.TotalImplementations, summary.TotalImplementations)
	}
	if wantReady := progress.PQCReady + progress.SymmetricSafe; wantReady != summary.PQCImplementations {
		t.Errorf("ready counts disagree: progress pqc_ready+symmetric_safe=%d, summary pqc_implementations=%d",
			wantReady, summary.PQCImplementations)
	}
	if progress.PQCPercentage > 100 {
		t.Errorf("pqc_percentage = %v, must not exceed 100", progress.PQCPercentage)
	}
	// Headline counters partition the population; ByFamily is a different unit
	// and is allowed to exceed it.
	if sum := progress.PQCReady + progress.SymmetricSafe + progress.NonPQC + progress.Unclassified; sum != progress.TotalImplementations {
		t.Errorf("headline counters sum to %d, want total %d", sum, progress.TotalImplementations)
	}
}

// M-1: an implementation whose asset is still pending_approval must not count
// toward Total. Before this fix the classifier read crypto_implementations
// with no asset join at all, so it disagreed with crypto-configurations and
// risk/summary's total_crypto — both of which already required a live,
// monitoring-status asset — for the same tenant.
func TestIntegration_PQC_PendingApprovalAssetExcludedFromTotal(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"key_exchange": "ECDHE", "symmetric": "AES256"}) // on the fixture's monitoring asset

	pending := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'pending.example.test','server','pending_approval',NOW(),NOW(),NOW(),NOW())`, pending, f.tenant); err != nil {
		t.Fatalf("insert pending asset: %v", err)
	}
	implID := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',NOW(),NOW())`, implID, f.tenant, pending); err != nil {
		t.Fatalf("insert implementation on pending asset: %v", err)
	}

	got, err := classifyTenantImplementationsPQC(f.db, f.tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if got.Total != 1 {
		t.Errorf("Total = %d, want 1 (the pending-approval asset's implementation must be excluded)", got.Total)
	}
}
