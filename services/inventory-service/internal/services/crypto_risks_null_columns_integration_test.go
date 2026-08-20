package services

// Guard for B-39: the High and Informational severity buckets silently dropped
// rows whose cipher_suite or hash_algorithm is NULL.
//
// Both counters exclude already-classified rows with a hand-written
// `AND NOT ( ... OR UPPER(ci.cipher_suite) LIKE '%RC4%' ... )`. On a NULL
// column each of those disjuncts is NULL, so the OR chain is NULL, NOT NULL is
// NULL, and the row is filtered out even though the positive predicate above
// had already matched it. The generated helpers sitting right beside them
// (singleDESSQL, anyWeakKeySizeSQL) are deliberately NULL-safe via COALESCE /
// IS NOT NULL; the hand-written operands were not.
//
// Every SSH crypto configuration has cipher_suite NULL by construction, so an
// SSH host on diffie-hellman-group14-sha1 — SHA1, unambiguously High — was
// never counted as High, while total_assets_affected still counted the same
// asset.
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

func TestIntegration_CryptoRisksSummary_NullCipherSuiteIsStillCounted(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &CryptoRisksService{db: db}

	insertAsset := func(hostname string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status,
			                            last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW())`, id, tenant, hostname); err != nil {
			t.Fatalf("insert asset %s: %v", hostname, err)
		}
		return id
	}

	// SSH kex diffie-hellman-group14-sha1: cipher_suite and protocol_version are
	// NULL exactly as the SSH ingest path writes them. hash_algorithm SHA1 is
	// what makes the positive High predicate match.
	sshAsset := insertAsset("ssh-sha1.example.test")
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (
			id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
			key_exchange_algorithm, hash_algorithm, key_size, discovery_method, risk_score,
			last_verified_at, first_discovered_at, created_at, updated_at
		) VALUES ($1,$2,$3,'SSH',NULL,NULL,'diffie-hellman-group14-sha1','SHA1',2048,'passive',70,NOW(),NOW(),NOW(),NOW())`,
		uuid.New(), tenant, sshAsset); err != nil {
		t.Fatalf("insert ssh implementation: %v", err)
	}

	summary, err := svc.GetSummary(tenant)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if summary.High != 1 {
		t.Errorf("High = %d, want 1 — a SHA1 SSH configuration with cipher_suite NULL "+
			"must not be dropped by the negated OR chain (B-39). TotalAffected = %d",
			summary.High, summary.TotalAffected)
	}
	if summary.TotalAffected != 1 {
		t.Errorf("TotalAffected = %d, want 1 (this counter never had the NOT chain, "+
			"which is why the buckets and the total disagreed)", summary.TotalAffected)
	}

	// The Informational counter carries the same negated chain. A second SSH
	// host with no weak signature at all — NULL cipher_suite, NULL
	// protocol_version, modern kex/hash — but a positive risk_score belongs in
	// Informational, and vanished for the same reason.
	infoAsset := insertAsset("ssh-modern.example.test")
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (
			id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
			key_exchange_algorithm, hash_algorithm, key_size, discovery_method, risk_score,
			last_verified_at, first_discovered_at, created_at, updated_at
		) VALUES ($1,$2,$3,'SSH',NULL,NULL,'curve25519-sha256','SHA256',256,'passive',10,NOW(),NOW(),NOW(),NOW())`,
		uuid.New(), tenant, infoAsset); err != nil {
		t.Fatalf("insert modern ssh implementation: %v", err)
	}

	summary, err = svc.GetSummary(tenant)
	if err != nil {
		t.Fatalf("GetSummary (2): %v", err)
	}
	if summary.Informational != 1 {
		t.Errorf("Informational = %d, want 1 — an SSH configuration with NULL "+
			"cipher_suite and a positive risk_score must land in the bucket (B-39)",
			summary.Informational)
	}
	if summary.High != 1 {
		t.Errorf("High = %d after adding a modern SSH host, want 1", summary.High)
	}

	// The summary's Informational predicate is pinned byte-for-byte to
	// ListRisks' own severity=informational filter, so the NULL fix has to hold
	// on both sides or the two surfaces disagree again.
	listed, err := svc.ListRisks(tenant, CryptoRiskFilters{Severity: []string{"informational"}, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("ListRisks: %v", err)
	}
	if listed.Total != summary.Informational {
		t.Errorf("ListRisks(informational).Total = %d, GetSummary.Informational = %d — must agree",
			listed.Total, summary.Informational)
	}
}
