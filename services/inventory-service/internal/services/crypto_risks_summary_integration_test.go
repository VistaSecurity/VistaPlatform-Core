package services

// Guards for L-9a: GetSummary's Informational bucket used to be dead code
// (never assigned, always the Go zero value), so /crypto-risks/summary
// reported all-zero severity buckets for a tenant while the unfiltered
// /crypto-risks list returned non-zero rows classified "informational" by
// classifyRisk. This pins that GetSummary.Informational now agrees with
// ListRisks' own `severity=informational` filter for the same data.
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

func TestIntegration_CryptoRisksSummary_InformationalMatchesList(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &CryptoRisksService{db: db}

	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'strong.example.test','server','monitoring',NOW(),NOW(),NOW(),NOW())`, asset, tenant); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	// A strong, modern configuration (TLS1.3 / AES256-GCM / SHA384 / 4096-bit)
	// with a positive risk_score but nothing that matches any Critical/High/
	// Medium weak-crypto signature — classifyRisk's default bucket.
	implID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (
			id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
			hash_algorithm, key_size, discovery_method, risk_score, created_at, updated_at
		) VALUES ($1,$2,$3,'TLS','TLSv1.3','TLS_AES_256_GCM_SHA384','SHA384',4096,'passive',10,NOW(),NOW())`,
		implID, tenant, asset); err != nil {
		t.Fatalf("insert strong implementation: %v", err)
	}

	summary, err := svc.GetSummary(tenant)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if summary.Critical != 0 || summary.High != 0 || summary.Medium != 0 {
		t.Fatalf("strong config classified into a weak bucket: %+v", summary)
	}
	if summary.Informational != 1 {
		t.Errorf("Informational = %d, want 1 — GetSummary must count the same "+
			"row ListRisks(severity=informational) returns", summary.Informational)
	}

	listed, err := svc.ListRisks(tenant, CryptoRiskFilters{Severity: []string{"informational"}, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("ListRisks: %v", err)
	}
	if listed.Total != summary.Informational {
		t.Errorf("ListRisks(informational).Total = %d, GetSummary.Informational = %d — must agree",
			listed.Total, summary.Informational)
	}
}
