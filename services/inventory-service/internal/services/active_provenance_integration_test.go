package services

// The last hop of tenant-sensor dispatch: a result the sensor submitted
// through the ordinary discovery route — tagged discovery_method=active, with
// the sensor's id and the job id riding along — materialises as a crypto
// configuration whose provenance is `active` and whose source is that sensor.
// This is what "the asset's configuration is enriched" means in the data.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func TestIntegration_Ingest_DispatchedJobResultCarriesActiveProvenance(t *testing.T) {
	svc, tenant, asset := newIngestFixture(t)
	sensorID := uuid.New()
	if _, err := svc.db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, 'xps16-sensor', 'linux', '1.0.0', 'datacenter_host', 'active')`, sensorID, tenant); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}

	protoVersion := "TLS 1.3"
	suite := "TLS_AES_256_GCM_SHA384"
	sensor := sensorID.String()
	finding := IngestFinding{
		Protocol:        "TLS",
		ProtocolVersion: &protoVersion,
		CipherSuite:     &suite,
		SourceSensorID:  &sensor,
		RawData: map[string]interface{}{
			"source":                        "sensor_discovery",
			"discovery_method":              sensordispatch.DiscoveryMethodActive,
			"discovery_source":              sensordispatch.DiscoverySourceActiveScan,
			sensordispatch.MetadataJobIDKey: "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42",
		},
	}
	if err := svc.processDiscoveryCryptoData(tenant, asset, finding, nil, nil, nil); err != nil {
		t.Fatalf("processDiscoveryCryptoData: %v", err)
	}

	var method string
	var source uuid.NullUUID
	if err := svc.db.QueryRow(`
		SELECT discovery_method::text, source_sensor_id
		  FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, asset).Scan(&method, &source); err != nil {
		t.Fatalf("read back the crypto configuration: %v", err)
	}
	if method != "active" {
		t.Errorf("discovery_method = %q, want active — a dispatched job's result must read as an active probe, not a passive observation", method)
	}
	if !source.Valid || source.UUID != sensorID {
		t.Errorf("source_sensor_id = %v, want the dispatching sensor %s", source, sensorID)
	}
}
