package autoscan

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

func TestIntegration_AutomaticScanHonorsSensitiveAndExcludedAssets(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	protected, shared, excluded, normal, ot := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, item := range []struct {
		id                   uuid.UUID
		address, class, path string
	}{{protected, "10.20.30.1", "server", "hardware.computer.server"}, {shared, "10.20.30.2", "server", "hardware.computer.server"}, {excluded, "10.20.31.1", "server", "hardware.computer.server"}, {normal, "10.20.32.1", "server", "hardware.computer.server"}, {ot, "10.20.33.1", "plc", "hardware.ot_device.plc"}} {
		execOrFail(t, db, `INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1::uuid,$2,$1::text,$3,$4,$5,'monitoring')`, item.id, tenant, item.address, item.class, item.path)
	}
	execOrFail(t, db, `INSERT INTO asset_endpoints(id,tenant_id,asset_id,address,port,transport) VALUES($1,$2,$3,'10.20.30.2',443,'tcp')`, uuid.New(), tenant, protected)
	execOrFail(t, db, `INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,jsonb_build_object('identity_enrichment',jsonb_build_object('sensitive_asset_ids',jsonb_build_array($2::text),'excluded_cidrs',jsonb_build_array('10.20.31.0/24'))))`, tenant, protected)
	got, _, err := store.EligibleTargets(context.Background(), tenant, sharedautoscan.DefaultPolicy(), time.Now(), nil)
	if err != nil || len(got) != 1 || got[0].AssetID != normal {
		t.Fatalf("eligible=%+v err=%v", got, err)
	}
	count, err := store.InScope(context.Background(), tenant, nil)
	if err != nil || count != 1 {
		t.Fatalf("in scope=%d err=%v", count, err)
	}
	execOrFail(t, db, `UPDATE tenant_admin_settings SET config=config||'{"identity_admission":{"mode":"paused"}}' WHERE tenant_id=$1`, tenant)
	got, _, err = store.EligibleTargets(context.Background(), tenant, sharedautoscan.DefaultPolicy(), time.Now(), nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("paused=%v err=%v", got, err)
	}
}
