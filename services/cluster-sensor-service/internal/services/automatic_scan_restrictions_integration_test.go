package services

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

func TestIntegration_AutomaticScanPolicyAtQueueAndPlatformClaim(t *testing.T) {
	f := newDispatchFixture(t)
	asset := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,'auto-target','192.168.80.20','server','hardware.computer.server','monitoring')`, asset, f.tenant); err != nil {
		t.Fatal(err)
	}
	req := models.CreateDiscoveryJobRequest{Targets: []string{"192.168.80.20"}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "async", Options: map[string]interface{}{"origin": "auto_scan"}}
	for _, mode := range []string{"sensitive", "excluded", "paused"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := f.raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{}') ON CONFLICT(tenant_id) DO UPDATE SET config='{}'`, f.tenant); err != nil {
				t.Fatal(err)
			}
			job, err := f.svc.CreateJob(f.tenant.String(), "system", req)
			if err != nil {
				t.Fatal(err)
			}
			var target models.DiscoveryTarget
			if err := f.raw.QueryRow(`SELECT id,input FROM discovery_targets WHERE tenant_id=$1 AND job_id=$2`, f.tenant, job.ID).Scan(&target.ID, &target.Input); err != nil {
				t.Fatal(err)
			}
			target.Protocols = []string{"TLS"}
			target.Ports = []int32{443}
			value := `{"identity_admission":{"mode":"paused"}}`
			if mode == "sensitive" {
				value = `{"identity_enrichment":{"sensitive_asset_ids":["` + asset.String() + `"]}}`
			}
			if mode == "excluded" {
				value = `{"identity_enrichment":{"excluded_cidrs":["192.168.80.0/24"]}}`
			}
			if _, err := f.raw.Exec(`UPDATE tenant_admin_settings SET config=$2::jsonb WHERE tenant_id=$1`, f.tenant, value); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); err == nil {
				t.Fatal("restricted automatic job created")
			}
			// No scanner is installed in this fixture: reaching network work would panic.
			err = f.jp.processTarget(job, &target, req.Options)
			if !errors.Is(err, dispatchguard.ErrDenied) && !errors.Is(err, dispatchguard.ErrPaused) {
				t.Fatalf("claim error=%v", err)
			}
			var started *time.Time
			if err := f.raw.QueryRow(`SELECT started_at FROM discovery_targets WHERE id=$1`, target.ID).Scan(&started); err != nil || started != nil {
				t.Fatalf("restricted target started=%v err=%v", started, err)
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
