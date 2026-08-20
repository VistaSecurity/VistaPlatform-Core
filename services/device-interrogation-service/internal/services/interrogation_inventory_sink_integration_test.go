package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// B-03: in-cluster device interrogation never wrote sensor_discoveries, so its
// results never reached Inventory.
//
// These are integration tests rather than unit tests because the whole finding
// is a statement about which ROWS exist after a run. The in-cluster executor
// reported success and a materialized count either way; only counting rows in
// the two sinks distinguishes the broken behaviour from the fixed one.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

// seedInterrogationJob creates the discovery job + target an interrogated asset
// hangs off, using the owner connection (which bypasses RLS like the production
// bypass role).
func seedInterrogationJob(t *testing.T, db *sql.DB, tenantID uuid.UUID) (jobID, targetID uuid.UUID) {
	t.Helper()
	jobID, targetID = uuid.New(), uuid.New()
	if _, err := db.Exec(
		`INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status)
		 VALUES ($1, $2, 'sensors', 'running')`, jobID, tenantID); err != nil {
		t.Fatalf("seed discovery_job: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO discovery_targets (id, job_id, tenant_id, input, protocols, ports, status)
		 VALUES ($1, $2, $3, 'fw.example.test', ARRAY['TLS'], ARRAY[443], 'completed')`,
		targetID, jobID, tenantID); err != nil {
		t.Fatalf("seed discovery_target: %v", err)
	}
	return jobID, targetID
}

// interrogatedAsset is the shape a vendor interrogator emits — a TLS service
// with a negotiated version and cipher, which is exactly what has to survive
// into the inventory sink for the asset to be scored at all.
func interrogatedAsset() *di.CryptoAsset {
	version := "TLS 1.2"
	cipher := "ECDHE-RSA-AES256-GCM-SHA384"
	keySize := 256
	hash := "SHA384"
	return &di.CryptoAsset{
		Hostname:         "fw.example.test",
		IPAddress:        "198.51.100.10",
		Port:             443,
		Protocol:         "TLS",
		AssetType:        "firewall",
		ProtocolVersion:  &version,
		CipherSuite:      &cipher,
		KeySize:          &keySize,
		HashAlgorithm:    &hash,
		SupportedCiphers: []string{cipher},
		TLSVersions:      []string{"TLS 1.2", "TLS 1.3"},
	}
}

// TestIntegration_Interrogation_ReachesInventorySink is the direct regression
// guard for B-03: materializing an interrogated asset must land a row in BOTH
// discovery_findings AND sensor_discoveries.
//
// sensor_discoveries is the load-bearing one. discovery-processor polls it and
// is what classifies the asset, applies the tenant's auto-approval rules and
// imports it into Inventory. Nothing downstream reads discovery_findings into
// inventory, so a run that wrote only findings completed successfully, flipped
// the device to 'connected', reported a count — and left Inventory empty and
// Approvals showing nothing pending.
//
// Mutation check: delete the writeSensorDiscovery call in
// materializeInterrogatedAsset and this fails on the sensor_discoveries count
// while every other test in the package still passes — which is precisely how
// the bug survived.
func TestIntegration_Interrogation_ReachesInventorySink(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewDeviceInterrogationService(appDB, owner, "")

	jobID, targetID := seedInterrogationJob(t, owner, tenantID)
	deviceID := uuid.New()

	systemSensorID, err := svc.resultProcessor.lookupSystemSensor(ctx, tenantID)
	if err != nil {
		t.Fatalf("lookupSystemSensor on a fresh tenant: %v", err)
	}

	ok := svc.materializeInterrogatedAsset(
		ctx, tenantID, deviceID, jobID, targetID, systemSensorID, jobID.String(),
		interrogatedAsset(), &di.InterrogateResult{},
	)
	if !ok {
		t.Fatal("materializeInterrogatedAsset reported the asset did not reach the inventory sink")
	}

	var findings int
	if err := owner.QueryRow(
		`SELECT count(*) FROM discovery_findings WHERE job_id = $1`, jobID,
	).Scan(&findings); err != nil {
		t.Fatalf("count discovery_findings: %v", err)
	}
	if findings != 1 {
		t.Errorf("discovery_findings rows = %d, want 1", findings)
	}

	var sensorRows int
	var gotSensor uuid.UUID
	var metadataJSON []byte
	if err := owner.QueryRow(
		`SELECT count(*) OVER (), sensor_id, metadata
		   FROM sensor_discoveries WHERE batch_id = $1 LIMIT 1`, jobID.String(),
	).Scan(&sensorRows, &gotSensor, &metadataJSON); err != nil {
		t.Fatalf("in-cluster interrogation wrote NO sensor_discoveries row — its results cannot reach Inventory: %v", err)
	}
	if sensorRows != 1 {
		t.Errorf("sensor_discoveries rows = %d, want 1", sensorRows)
	}
	if gotSensor != systemSensorID {
		t.Errorf("sensor_id = %v, want the tenant's platform sensor %v", gotSensor, systemSensorID)
	}

	// The pipeline reads the protocol version from "version", not
	// "protocol_version"; a row that loses it cannot be scored for weak TLS at
	// all, so assert the enrichment survived rather than only that a row exists.
	var meta map[string]interface{}
	if err := json.Unmarshal(metadataJSON, &meta); err != nil {
		t.Fatalf("unmarshal sensor_discovery metadata: %v", err)
	}
	if got := meta["version"]; got != "TLS 1.2" {
		t.Errorf("metadata[version] = %v, want TLS 1.2", got)
	}
	if got := meta["cipher_suite"]; got != "ECDHE-RSA-AES256-GCM-SHA384" {
		t.Errorf("metadata[cipher_suite] = %v, want the negotiated suite", got)
	}
	if got := meta["source_device_id"]; got != deviceID.String() {
		t.Errorf("metadata[source_device_id] = %v, want %v", got, deviceID.String())
	}
}

// TestIntegration_Interrogation_FailsWithoutPlatformSensor pins the failure
// posture. Without the tenant's platform sensor there is nowhere to publish, and
// the run must fail loudly rather than degrade to a findings-only pass that
// reports success and produces nothing a user will ever see — on a timer, since
// scheduled scans run this same path.
//
// It also proves the lookup happens BEFORE the device is contacted: the device
// here has no credentials at all, so any ordering that interrogated first would
// surface a credential error instead.
func TestIntegration_Interrogation_FailsWithoutPlatformSensor(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)

	hostname := "fw-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(appDB).CreateDevice(ctx, tenantID, models.CreateDeviceRequest{
		DeviceType: "fortinet",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	if _, err := owner.Exec(
		`UPDATE sensors SET deleted_at = NOW()
		  WHERE tenant_id = $1 AND profile = 'device_interrogation' AND 'system' = ANY(tags)`,
		tenantID); err != nil {
		t.Fatalf("soft-delete platform sensor: %v", err)
	}

	svc := NewDeviceInterrogationService(appDB, owner, "")
	_, materialized, err := svc.InterrogateDevice(ctx, tenantID, uuid.Nil, dev.ID)
	if err == nil {
		t.Fatal("InterrogateDevice succeeded with no platform sensor — results had nowhere to land")
	}
	if materialized != 0 {
		t.Errorf("materialized = %d, want 0", materialized)
	}

	// The reason has to reach the tenant, not just this process's stdout.
	var status, errMsg sql.NullString
	if err := owner.QueryRow(
		`SELECT status, error_message FROM discovery_jobs
		  WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`, tenantID,
	).Scan(&status, &errMsg); err != nil {
		t.Fatalf("read discovery job: %v", err)
	}
	if status.String != "failed" {
		t.Errorf("discovery job status = %q, want failed", status.String)
	}
	if errMsg.String == "" {
		t.Error("discovery job carries no error_message; the tenant sees a bare failure")
	}
}
