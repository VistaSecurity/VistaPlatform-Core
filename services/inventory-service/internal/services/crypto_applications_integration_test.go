package services

// End-to-end proof, against a real Postgres with the real schema, that
// ingesting an at-rest cloud finding
//
//  1. produces a crypto_applications row (the table shipped UNWIRED — zero Go
//     references — so its posture lived only in raw_metadata where nothing read
//     it),
//  2. does NOT manufacture a crypto_implementations row (the phantom TLS
//     endpoint: buckets reached Inventory as protocol TLS with no version and
//     no cipher suite),
//  3. is idempotent across re-discovery (the upsert's natural key), and
//  4. reads back through ListCryptoApplications with the contract's fields.
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

func newAtRestFixture(t *testing.T) (*AssetService, uuid.UUID, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'socialupkeep-marketing','service','monitoring',NOW(),NOW(),NOW(),NOW())`, asset, tenant); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return &AssetService{db: db, algorithmService: NewAlgorithmService(db)}, tenant, asset
}

func s3IngestFinding(bucket string, extra map[string]interface{}) IngestFinding {
	raw := map[string]interface{}{
		"resource_type":    "s3_bucket",
		"arn":              "arn:aws:s3:::" + bucket,
		"cloud_provider":   "aws",
		"cloud_region":     "us-east-1",
		"discovery_method": "cloud_api",
	}
	for k, v := range extra {
		raw[k] = v
	}
	name := bucket
	return IngestFinding{Hostname: &name, AssetType: "service", RawData: raw}
}

func TestIntegration_AtRest_ProducesPostureAndNoPhantomTLS(t *testing.T) {
	svc, tenant, asset := newAtRestFixture(t)

	f := s3IngestFinding("socialupkeep-marketing", map[string]interface{}{
		"encrypted":             true,
		"encryption_determined": true,
		"encryption_type":       "sse-s3",
		"algorithm":             "AES-256",
	})
	if err := svc.processDiscoveryCryptoData(tenant, asset, f, nil, nil, nil); err != nil {
		t.Fatalf("processDiscoveryCryptoData: %v", err)
	}

	// (2) No fabricated TLS crypto configuration.
	var implCount int
	if err := svc.db.QueryRow(
		`SELECT COUNT(*) FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, asset).Scan(&implCount); err != nil {
		t.Fatalf("count crypto_implementations: %v", err)
	}
	if implCount != 0 {
		t.Errorf("crypto_implementations rows = %d, want 0 — an S3 bucket is not a TLS endpoint", implCount)
	}

	// (1) The posture row exists, with the resolved catalogue algorithm.
	var (
		resourceType, resourceID, ctx string
		risk                          int
		algoCode                      *string
	)
	if err := svc.db.QueryRow(`
		SELECT ca.resource_type, ca.resource_identifier, ca.encryption_context, ca.risk_score, alg.code
		  FROM crypto_applications ca
		  LEFT JOIN algorithms alg ON alg.id = ca.algorithm_id
		 WHERE ca.tenant_id = $1`, tenant).Scan(&resourceType, &resourceID, &ctx, &risk, &algoCode); err != nil {
		t.Fatalf("read back crypto_applications: %v", err)
	}
	if resourceType != "cloud_storage" || ctx != "at_rest" {
		t.Errorf("got %s/%s, want cloud_storage/at_rest", resourceType, ctx)
	}
	if resourceID != "arn:aws:s3:::socialupkeep-marketing" {
		t.Errorf("resource_identifier = %q, want the bucket ARN", resourceID)
	}
	if risk != 40 {
		t.Errorf("risk_score = %d, want 40 (encrypted under a PROVIDER key)", risk)
	}
	if algoCode == nil || *algoCode != "AES256" {
		t.Errorf("algorithm_id resolved to %v, want the AES256 catalogue row", algoCode)
	}
}

func TestIntegration_AtRest_UpsertIsIdempotent(t *testing.T) {
	svc, tenant, asset := newAtRestFixture(t)

	first := s3IngestFinding("socialupkeep-marketing", map[string]interface{}{
		"encrypted": false, "encryption_determined": true, "encryption_type": "none",
	})
	if err := svc.processDiscoveryCryptoData(tenant, asset, first, nil, nil, nil); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	// The customer turns on SSE-KMS; the next discovery run must UPDATE the
	// same row, not append a second one.
	second := s3IngestFinding("socialupkeep-marketing", map[string]interface{}{
		"encrypted": true, "encryption_determined": true, "encryption_type": "sse-kms",
		"algorithm": "AES-256-KMS", "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
	})
	if err := svc.processDiscoveryCryptoData(tenant, asset, second, nil, nil, nil); err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	var count, risk int
	if err := svc.db.QueryRow(
		`SELECT COUNT(*), MAX(risk_score) FROM crypto_applications WHERE tenant_id = $1`, tenant).
		Scan(&count, &risk); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("crypto_applications rows = %d, want 1 — re-discovery must upsert on (tenant, resource, context)", count)
	}
	if risk != 10 {
		t.Errorf("risk_score = %d, want 10 — the row must reflect the LATEST posture", risk)
	}
}

func TestIntegration_AtRest_ListAndFilters(t *testing.T) {
	svc, tenant, asset := newAtRestFixture(t)

	measured := s3IngestFinding("measured-bucket", map[string]interface{}{
		"encrypted": true, "encryption_determined": true,
		"encryption_type": "sse-s3", "algorithm": "AES-256",
	})
	unmeasured := s3IngestFinding("denied-bucket", map[string]interface{}{
		"encrypted": false, "encryption_determined": false,
		"encryption_type": "unknown", "encryption_error": "AccessDenied",
	})
	plaintext := s3IngestFinding("plaintext-bucket", map[string]interface{}{
		"encrypted": false, "encryption_determined": true, "encryption_type": "none",
	})
	for _, f := range []IngestFinding{measured, unmeasured, plaintext} {
		if err := svc.processDiscoveryCryptoData(tenant, asset, f, nil, nil, nil); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	all, total, err := svc.ListCryptoApplications(tenant, CryptoApplicationFilter{EncryptionContext: "at_rest"})
	if err != nil {
		t.Fatalf("ListCryptoApplications: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("got %d rows / total %d, want 3/3", len(all), total)
	}
	// Highest risk first: the plaintext bucket leads.
	if all[0].ResourceName != "plaintext-bucket" || all[0].RiskScore != 90 || all[0].RiskLevel != "Critical" {
		t.Errorf("first row = %s/%d/%s, want plaintext-bucket/90/Critical",
			all[0].ResourceName, all[0].RiskScore, all[0].RiskLevel)
	}

	// The "could not determine" bucket is isolable, and scores 0 = NOT
	// ASSESSED — never a fail.
	no := false
	undetermined, undeterminedTotal, err := svc.ListCryptoApplications(tenant, CryptoApplicationFilter{
		EncryptionContext: "at_rest", Determined: &no,
	})
	if err != nil {
		t.Fatalf("filter determined=false: %v", err)
	}
	if undeterminedTotal != 1 || len(undetermined) != 1 {
		t.Fatalf("determined=false returned %d rows (total %d), want 1", len(undetermined), undeterminedTotal)
	}
	u := undetermined[0]
	if u.ResourceName != "denied-bucket" || u.EncryptionDetermined || u.RiskScore != 0 {
		t.Errorf("undetermined row = %+v, want denied-bucket with encryption_determined=false and risk 0", u)
	}
	if u.KeyManager != nil {
		t.Errorf("key_manager = %v, want null — there is no key to attribute on an unmeasured resource", *u.KeyManager)
	}

	// The measured one carries the contract's projection.
	yes := true
	measuredRows, _, err := svc.ListCryptoApplications(tenant, CryptoApplicationFilter{
		EncryptionContext: "at_rest", Determined: &yes, Search: "measured",
	})
	if err != nil {
		t.Fatalf("filter determined=true: %v", err)
	}
	if len(measuredRows) != 1 {
		t.Fatalf("search returned %d rows, want 1", len(measuredRows))
	}
	m := measuredRows[0]
	if !m.Encrypted || m.EncryptionType != "sse-s3" || m.RiskScore != 40 || m.RiskLevel != "Medium" {
		t.Errorf("measured row = %+v, want encrypted sse-s3 at 40/Medium", m)
	}
	if m.Algorithm == nil || *m.Algorithm != "AES-256" {
		t.Errorf("algorithm = %v, want AES-256", m.Algorithm)
	}
	if m.KeyManager == nil || *m.KeyManager != "provider" {
		t.Errorf("key_manager = %v, want provider", m.KeyManager)
	}
	if m.CloudProvider == nil || *m.CloudProvider != "aws" || m.CloudRegion == nil || *m.CloudRegion != "us-east-1" {
		t.Errorf("cloud provider/region = %v/%v, want aws/us-east-1", m.CloudProvider, m.CloudRegion)
	}

	// Band filtering goes through models.RiskAtLeastSQL: "Medium and above"
	// takes the 40 and the 90 but not the not-assessed 0.
	atLeastMedium, atLeastMediumTotal, err := svc.ListCryptoApplications(tenant, CryptoApplicationFilter{
		EncryptionContext: "at_rest", RiskAtLeast: "Medium",
	})
	if err != nil {
		t.Fatalf("filter risk_at_least: %v", err)
	}
	if atLeastMediumTotal != 2 || len(atLeastMedium) != 2 {
		t.Errorf("risk_at_least=Medium returned %d rows (total %d), want 2 — a NOT ASSESSED row must not be banded as risky",
			len(atLeastMedium), atLeastMediumTotal)
	}
}
