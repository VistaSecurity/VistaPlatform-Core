package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// An automatic scan restricted after it was queued — the asset marked
// sensitive, its range excluded, admission paused — is refused at creation
// and, when the platform runs the job already queued, before any packet: the
// address is never contacted and its unit never finishes as scanned. The job
// is planned (the legacy request shape is translated, WP5); the check
// is the per-unit automatic-scan re-check (unitAuthorizer.authorizeUnit).
func TestIntegration_AutomaticScanPolicyAtQueueAndPlatformClaim(t *testing.T) {
	const addr = "10.186.80.20"
	req := models.CreateDiscoveryJobRequest{Targets: []string{addr}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "async", Options: map[string]interface{}{"origin": "auto_scan"}}
	for _, mode := range []string{"sensitive", "excluded", "paused"} {
		t.Run(mode, func(t *testing.T) {
			f, fake := newUnitFixture(t)
			fake.Host(addr, nil, nil)
			asset := uuid.New()
			if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,'auto-target',$3,'server','hardware.computer.server','monitoring')`, asset, f.tenant, addr); err != nil {
				t.Fatal(err)
			}
			if _, err := f.raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{}') ON CONFLICT(tenant_id) DO UPDATE SET config='{}'`, f.tenant); err != nil {
				t.Fatal(err)
			}
			job, err := f.svc.CreateJob(f.tenant.String(), "system", req)
			if err != nil {
				t.Fatal(err)
			}
			if job.Plan == nil {
				t.Fatal("the automatic scan was not planned")
			}
			value := `{"identity_admission":{"mode":"paused"}}`
			if mode == "sensitive" {
				value = `{"identity_enrichment":{"sensitive_asset_ids":["` + asset.String() + `"]}}`
			}
			if mode == "excluded" {
				value = `{"identity_enrichment":{"excluded_cidrs":["10.186.80.0/24"]}}`
			}
			if _, err := f.raw.Exec(`UPDATE tenant_admin_settings SET config=$2::jsonb WHERE tenant_id=$1`, f.tenant, value); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); err == nil {
				t.Fatal("restricted automatic job created")
			}
			if claimed, err := f.svc.ClaimJob(job.ID); err != nil || !claimed {
				t.Fatal(claimed, err)
			}
			loaded, err := f.svc.GetJob(job.ID)
			if err != nil {
				t.Fatal(err)
			}
			_ = f.jp.processDiscoveryJob(context.Background(), loaded)
			if n := fake.DialedAddrs()[addr]; n != 0 {
				t.Fatalf("the restricted address was dialled %d time(s)", n)
			}
			if st := f.unitStatuses(t, job.ID); st[addr] == unitDone {
				t.Fatalf("units = %v: the restricted address finished as scanned", st)
			}
		})
	}
}

func TestIntegration_AutomaticScanRechecksPolicyBeforeSensorDispatch(t *testing.T) {
	f := newDispatchFixture(t)
	sensor := f.liveSensor(t, "automatic")
	asset := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,'automatic','192.168.80.20','server','hardware.computer.server','monitoring')`, asset, f.tenant); err != nil {
		t.Fatal(err)
	}
	req := models.CreateDiscoveryJobRequest{Targets: []string{"192.168.80.20"}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()}, Options: map[string]interface{}{"origin": "auto_scan"}}
	job, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"paused"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if err := f.jp.dispatchToSensor(job); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.raw.QueryRow(`SELECT count(*) FROM sensor_commands WHERE sensor_id=$1`, sensor).Scan(&count); err != nil || count != 0 {
		t.Fatalf("commands=%d err=%v", count, err)
	}
	if _, err := f.raw.Exec(`UPDATE tenant_admin_settings SET config='{}' WHERE tenant_id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if err := f.jp.dispatchToSensor(job); err != nil {
		t.Fatal(err)
	}
	if err := f.raw.QueryRow(`SELECT count(*) FROM sensor_commands WHERE sensor_id=$1`, sensor).Scan(&count); err != nil || count != 1 {
		t.Fatalf("resumed commands=%d err=%v", count, err)
	}
}
