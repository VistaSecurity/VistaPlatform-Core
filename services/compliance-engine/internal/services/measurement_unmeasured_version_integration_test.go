package services

// Unknown stays unknown ( W1.2), at the compliance layer: a TLS
// configuration whose version was never measured contributes NO tls_version
// measurement. A control on the version therefore has nothing in scope for it
// (NOT_ASSESSED), rather than reading an invented "TLS 1.2" as a pass — which
// is what Cisco's and F5's collectors used to hand it.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_TLSVersionMeasurement_SkipsAnUnmeasuredVersion(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	var asset uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO assets (tenant_id, class_key, class_path, hostname, primary_address, asset_status)
		VALUES ($1, 'load_balancer', 'hardware.network.load_balancer', 'vip.example.test', '192.0.2.20'::inet, 'monitoring')
		RETURNING id`, tenant).Scan(&asset); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	for _, version := range []interface{}{nil, "TLS1.0"} {
		if _, err := db.Exec(`
			INSERT INTO crypto_implementations_partitioned
				(tenant_id, asset_id, protocol, protocol_version, cipher_suite, discovery_method, raw_data, last_verified_at)
			VALUES ($1, $2, 'TLS', $3, 'ECDHE-RSA-AES256-GCM-SHA384', 'device_interrogation',
			        '{"unmeasured_components":["protocol_version"]}'::jsonb, NOW())`,
			tenant, asset, version); err != nil {
			t.Fatalf("seed configuration %v: %v", version, err)
		}
	}

	values, err := NewMeasurementExtractor(db).ExtractMeasurements(tenant, "tls_version")
	if err != nil {
		t.Fatalf("extract tls_version: %v", err)
	}
	if len(values) != 1 {
		t.Fatalf("got %d tls_version measurements %v, want only the measured TLS1.0 — an unmeasured version is not a value", len(values), values)
	}
	if v, _ := values[0].Value.(string); v != "TLS1.0" {
		t.Errorf("measurement = %#v, want TLS1.0", values[0].Value)
	}
}
