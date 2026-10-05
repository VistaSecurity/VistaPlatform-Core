package jobs

// The trigger tick's settle pass, against a real Postgres, through the real
// tenant enumeration on the BYPASS handle and the real store on the RLS app
// role: a tenant with an Active Scan in flight whose job has completed is
// found and settled; a tenant with nothing in flight is not visited.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_FinishInFlight_SettlesATenantsFinishedActiveScan(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	app := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, owner), "postgres")}
	bypass := testdb.ConnectAsBypassRole(t, owner)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	asset, job := uuid.New(), uuid.New()
	exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status,metadata)
	      VALUES($1,$2,'inflight.example.test','10.0.0.71','server','hardware.computer.server','monitoring',
	             jsonb_build_object('last_active_scan_status','scanning','last_active_scan_at','2026-10-01T00:00:00Z','last_active_scan_job_ids',jsonb_build_array($3::text)))`,
		asset, tenant, job.String())
	exec(`INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, started_at, completed_at, metadata) VALUES ($1, $2, 'async', 'completed', NOW(), NOW(), '{"options":{"active_scan":true,"origin":"manual"}}')`, job, tenant)
	exec(`INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports, status) VALUES ($1, $2, '10.0.0.71', '{}', '{443,8443}', 'completed')`, job, tenant)

	j := NewActiveScanFinishJob(autoscan.NewStore(app), bypass)
	inFlight, err := j.tenantsWithActiveScansInFlight()
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	found := false
	for _, id := range inFlight {
		found = found || id == tenant
	}
	if !found {
		t.Fatalf("tenant with an Active Scan in flight not enumerated: %v", inFlight)
	}

	j.FinishInFlight(context.Background())

	var status, scannedAt string
	if err := owner.QueryRow(`SELECT metadata->>'last_active_scan_status', COALESCE(metadata->>'last_scanned_at','') FROM assets WHERE id = $1`, asset).Scan(&status, &scannedAt); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || scannedAt == "" {
		t.Fatalf("after the tick: status %q, last_scanned_at %q — want completed with a scan time", status, scannedAt)
	}
	again, err := j.tenantsWithActiveScansInFlight()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range again {
		if id == tenant {
			t.Fatal("the settled tenant is still enumerated as in flight")
		}
	}
}
