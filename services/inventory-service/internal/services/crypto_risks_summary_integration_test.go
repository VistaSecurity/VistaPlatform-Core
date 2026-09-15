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
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'strong.example.test', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, asset, tenant); err != nil {
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

// TestIntegration_CryptoRisksSummary_BucketsAreMutuallyExclusive pins the rule
// CLAUDE.md states and this summary used to break: roll up per ASSET first,
// then band once.
//
// Each counter used to be its own `COUNT(DISTINCT ci.asset_id)` with the band
// decided per CONFIGURATION, so a host with a TLS 1.0 endpoint and a TLS 1.1
// endpoint was counted in Critical AND in High. The buckets summed past the
// number of affected assets and the dashboard's distribution bar exceeded 100%.
//
// Two assertions, because either alone can be satisfied by the wrong query: the
// worst band wins, and the bands sum to the total.
func TestIntegration_CryptoRisksSummary_BucketsAreMutuallyExclusive(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &CryptoRisksService{db: db}

	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'two-bands.example.test', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`,
		asset, tenant); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	// One host, two configurations: TLS 1.0 is Critical, TLS 1.1 is High. This
	// is the ordinary shape of a host serving two ports, not a contrived one.
	for _, version := range []string{"TLSv1.0", "TLSv1.1"} {
		if _, err := db.Exec(`
			INSERT INTO crypto_implementations (
				id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
				hash_algorithm, key_size, discovery_method, risk_score, created_at, updated_at
			) VALUES ($1,$2,$3,'TLS',$4,'TLS_RSA_WITH_AES_128_CBC_SHA256','SHA256',2048,'passive',70,NOW(),NOW())`,
			uuid.New(), tenant, asset, version); err != nil {
			t.Fatalf("insert %s implementation: %v", version, err)
		}
	}

	summary, err := svc.GetSummary(tenant)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if summary.Critical != 1 {
		t.Errorf("Critical = %d, want 1 — the worst band an asset has is the band it is in", summary.Critical)
	}
	if summary.High != 0 {
		t.Errorf("High = %d, want 0 — counting the same asset in two bands is what made the "+
			"distribution exceed 100%%", summary.High)
	}
	if summary.Medium != 0 || summary.Informational != 0 {
		t.Errorf("Medium = %d, Informational = %d, want 0 and 0", summary.Medium, summary.Informational)
	}
	if sum := summary.Critical + summary.High + summary.Medium + summary.Informational; sum != summary.TotalAffected {
		t.Errorf("the bands sum to %d but TotalAffected is %d; they must partition the affected assets",
			sum, summary.TotalAffected)
	}
}
