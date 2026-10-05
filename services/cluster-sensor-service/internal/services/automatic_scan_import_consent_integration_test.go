package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// Per-connection scan consent (platform ADR-0002 D10) at the two checkpoints
// this service owns: job creation and the per-unit re-check the platform runs
// before any packet (unitAuthorizer.authorizeUnit). An asset known only from
// a connection's import (assets.import_only_sources) in private space nobody
// declared is admitted while its connection consents; when consent is
// withdrawn after the job was queued, creation refuses and the queued job's
// unit never dials. Inside a segment a person declared, consent is not needed.
//
// MUTATION (goes red): drop the import clause from AuthorizeAutomaticScan's
// target lookup; drop the declared-segment narrowing.
func TestIntegration_AutomaticScanImportConsentAtQueueAndPlatformClaim(t *testing.T) {
	for _, tc := range []struct {
		name, addr, segment string
		wantRefused         bool
	}{
		{name: "undeclared private space", addr: "10.187.80.20", wantRefused: true},
		{name: "declared segment", addr: "10.187.81.20", segment: "10.187.81.0/24"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, fake := newUnitFixture(t)
			fake.Host(tc.addr, nil, nil)
			ref := "cmdb:" + uuid.NewString()
			if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status,import_only_sources) VALUES($1,$2,'imported-target',$3,'server','hardware.computer.server','monitoring',ARRAY[$4::text])`, uuid.New(), f.tenant, tc.addr, ref); err != nil {
				t.Fatal(err)
			}
			if tc.segment != "" {
				if _, err := f.raw.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active) VALUES($1,'declared','cidr',$2,'private','production',true)`, f.tenant, tc.segment); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{}') ON CONFLICT(tenant_id) DO UPDATE SET config='{}'`, f.tenant); err != nil {
				t.Fatal(err)
			}
			if _, err := f.raw.Exec(`INSERT INTO source_scan_consents(tenant_id,source_ref,allow_active_scan) VALUES($1,$2,true)`, f.tenant, ref); err != nil {
				t.Fatal(err)
			}
			req := models.CreateDiscoveryJobRequest{Targets: []string{tc.addr}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "async", Options: map[string]interface{}{"origin": "auto_scan"}}
			job, err := f.svc.CreateJob(f.tenant.String(), "system", req)
			if err != nil {
				t.Fatalf("consent on: automatic job refused: %v", err)
			}
			if _, err := f.raw.Exec(`UPDATE source_scan_consents SET allow_active_scan=false WHERE tenant_id=$1 AND source_ref=$2`, f.tenant, ref); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); (err != nil) != tc.wantRefused {
				t.Fatalf("consent withdrawn: CreateJob err = %v, want refused=%v", err, tc.wantRefused)
			}
			if claimed, err := f.svc.ClaimJob(job.ID); err != nil || !claimed {
				t.Fatal(claimed, err)
			}
			loaded, err := f.svc.GetJob(job.ID)
			if err != nil {
				t.Fatal(err)
			}
			_ = f.jp.processDiscoveryJob(context.Background(), loaded)
			dialled := fake.DialedAddrs()[tc.addr]
			if tc.wantRefused && dialled != 0 {
				t.Fatalf("consent withdrawn: the import-only address was dialled %d time(s)", dialled)
			}
			if !tc.wantRefused && dialled == 0 {
				t.Fatal("declared segment: the import-only address was not scanned")
			}
			if st := f.unitStatuses(t, job.ID); tc.wantRefused && st[tc.addr] == unitDone {
				t.Fatalf("units = %v: the refused address finished as scanned", st)
			}
		})
	}
}
