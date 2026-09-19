package services

import (
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"testing"
)

func TestIntegration_AutomaticCommandPickupHonorsRestrictionsWithoutIdentityActivation(t *testing.T) {
	for _, mode := range []string{"sensitive", "excluded", "paused", "segment_sensitive"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdentityPickupFixture(t)
			f.svc.enrichmentAvailable = false
			asset := uuid.New()
			f.exec(t, `INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,'automatic','192.168.80.20','server','hardware.computer.server','monitoring')`, asset, f.tenant)
			id := f.queue(t, sensordispatch.CommandType)
			f.exec(t, `UPDATE sensor_commands SET payload=jsonb_set(payload,'{options}','{"origin":"auto_scan"}') WHERE id=$1`, id)
			// An inactive identity rollout must not enable or disable the older scanner;
			// explicit safety restrictions still apply to both paths.
			f.exec(t, `UPDATE tenant_admin_settings SET config='{}' WHERE tenant_id=$1`, f.tenant)
			switch mode {
			case "sensitive":
				f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_build_object('identity_enrichment',jsonb_build_object('sensitive_asset_ids',jsonb_build_array($2::text))) WHERE tenant_id=$1`, f.tenant, asset)
			case "excluded":
				f.exec(t, `UPDATE tenant_admin_settings SET config='{"identity_enrichment":{"excluded_cidrs":["192.168.80.0/24"]}}' WHERE tenant_id=$1`, f.tenant)
			case "paused":
				f.exec(t, `UPDATE tenant_admin_settings SET config='{"identity_admission":{"mode":"paused"}}' WHERE tenant_id=$1`, f.tenant)
			case "segment_sensitive":
				f.exec(t, `UPDATE network_segments SET metadata='{"sensitive":true}' WHERE id=$1`, f.segment)
			}
			got, err := f.svc.GetPendingCommands(f.sensor.String())
			if err != nil || len(got) != 0 {
				t.Fatalf("restricted pickup=%+v err=%v", got, err)
			}
			f.pending(t, id)
			f.exec(t, `UPDATE tenant_admin_settings SET config='{}' WHERE tenant_id=$1`, f.tenant)
			f.exec(t, `UPDATE network_segments SET metadata='{}' WHERE id=$1`, f.segment)
			got, err = f.svc.GetPendingCommands(f.sensor.String())
			if err != nil || len(got) != 1 {
				t.Fatalf("resumed pickup=%+v err=%v", got, err)
			}
		})
	}
}
