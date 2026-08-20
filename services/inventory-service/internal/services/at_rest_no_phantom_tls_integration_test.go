package services

// Behavioural guard for B-22, at the layer where the phantom row was actually
// written. The unit tests in at_rest_protocol_no_phantom_tls_test.go pin the two
// decision functions; this one pins the outcome: an AT-REST finding for a cloud
// key store must leave crypto_implementations untouched, rather than adding a
// TLS row with NULL protocol_version and NULL cipher_suite.
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

func TestIntegration_AtRestFinding_CreatesNoPhantomTLSConfiguration(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	assetID := uuid.New()
	mustExec(t, raw, `
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'b22-kms-key.example.test','service','monitoring',NOW(),NOW(),NOW(),NOW())`, assetID, tenant)

	// Exactly what discoverKMSKeys produces today: protocol AT-REST, port 0, and
	// key metadata carrying NO resource_type key — which is why the at-rest
	// producer's own short-circuit does not catch it.
	host := "b22-kms-key.example.test"
	port := 0
	finding := IngestFinding{
		Hostname: &host,
		Port:     &port,
		Protocol: "AT-REST",
		RawData: map[string]interface{}{
			"key_id":           "abc-123",
			"arn":              "arn:aws:kms:us-east-1:111111111111:key/abc-123",
			"key_state":        "Enabled",
			"key_usage":        "ENCRYPT_DECRYPT",
			"key_spec":         "SYMMETRIC_DEFAULT",
			"origin":           "AWS_KMS",
			"rotation_enabled": true,
			"region":           "us-east-1",
		},
	}

	if err := svc.processDiscoveryCryptoData(tenant, assetID, finding, nil, nil, nil); err != nil {
		t.Fatalf("processDiscoveryCryptoData: %v", err)
	}

	var n int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, assetID,
	).Scan(&n); err != nil {
		t.Fatalf("count crypto_implementations: %v", err)
	}
	if n != 0 {
		var protocol, version, suite *string
		_ = raw.QueryRow(
			`SELECT protocol::text, protocol_version, cipher_suite FROM crypto_implementations WHERE asset_id = $1 LIMIT 1`,
			assetID,
		).Scan(&protocol, &version, &suite)
		t.Fatalf("an AT-REST key-store finding produced %d crypto_implementations row(s) "+
			"(protocol=%s version=%s cipher_suite=%s) — a negotiated-protocol measurement that never happened",
			n, derefOrNull(protocol), derefOrNull(version), derefOrNull(suite))
	}

	// Positive polarity: an ordinary TLS finding for the same asset MUST still
	// materialize, or the assertion above would pass for a function that stopped
	// writing anything at all.
	tlsPort := 443
	version := "TLS 1.2"
	suite := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	tlsFinding := IngestFinding{
		Hostname:        &host,
		Port:            &tlsPort,
		Protocol:        "TLS",
		ProtocolVersion: &version,
		CipherSuite:     &suite,
		RawData:         map[string]interface{}{},
	}
	if err := svc.processDiscoveryCryptoData(tenant, assetID, tlsFinding, nil, nil, nil); err != nil {
		t.Fatalf("processDiscoveryCryptoData (TLS): %v", err)
	}
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, assetID,
	).Scan(&n); err != nil {
		t.Fatalf("count crypto_implementations after TLS finding: %v", err)
	}
	if n != 1 {
		t.Fatalf("a genuine TLS finding produced %d crypto_implementations row(s), want 1", n)
	}
}

func derefOrNull(s *string) string {
	if s == nil {
		return "<NULL>"
	}
	return *s
}
