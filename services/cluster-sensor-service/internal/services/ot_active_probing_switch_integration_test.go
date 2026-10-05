package services

import (
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// TestIntegration_CreateJob_OTActiveProbingSwitch drives the real CreateJob
// against the real seed and the production entitlement resolver (no licence
// row: a Core install). OT active probing is a Core capability that every
// seeded tier switches on; a per-tenant override is the off-switch.
//
//   - switch ON (the community tier's default): the job keeps its explicit OT
//     opt-in — the audit column records it and an OT target row is created;
//   - switch OFF (per-tenant override): the OT probes are dropped exactly as
//     before (logged, the rest of the job still created) — nothing OT is
//     recorded or queued.
func TestIntegration_CreateJob_OTActiveProbingSwitch(t *testing.T) {
	f := newDispatchFixture(t)
	if _, err := f.raw.Exec(`UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community') WHERE id = $1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	req := models.CreateDiscoveryJobRequest{
		Targets:          []string{"10.183.0.10"},
		Protocols:        []string{"TLS"},
		Ports:            []int{443},
		ExecutionMode:    "async",
		OTProbeProtocols: []string{"Modbus"},
	}

	otOf := func(t *testing.T, jobID string) (audit []string, otTargets int) {
		t.Helper()
		var col pq.StringArray
		if err := f.raw.QueryRow(`SELECT COALESCE(ot_probe_protocols, '{}') FROM discovery_jobs WHERE id = $1`, jobID).Scan(&col); err != nil {
			t.Fatalf("read job %s: %v", jobID, err)
		}
		if err := f.raw.QueryRow(`SELECT count(*) FROM discovery_targets WHERE job_id = $1 AND 'Modbus' = ANY(protocols)`, jobID).Scan(&otTargets); err != nil {
			t.Fatalf("count OT targets of %s: %v", jobID, err)
		}
		return []string(col), otTargets
	}

	on, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil {
		t.Fatalf("CreateJob (switch on): %v", err)
	}
	if audit, n := otOf(t, on.ID); len(audit) != 1 || audit[0] != "Modbus" || n != 1 {
		t.Fatalf("switch ON (default): ot_probe_protocols=%v OT targets=%d, want [Modbus] and 1 — the Core default must dispatch the opted-in OT probe", audit, n)
	}
	// The request is planned ( WP5): Modbus's standard port joins the
	// plan beside the requested one.
	if on.Plan == nil || on.Plan.TCPPorts != "443,502" {
		t.Fatalf("switch ON: plan = %+v, want custom on 443,502", on.Plan)
	}

	if _, err := f.raw.Exec(`
		INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, reason, effective_from)
		VALUES ($1, (SELECT id FROM billable_items WHERE key = 'ot_active_probing'),
		        '{"enabled": false}'::jsonb, 'operator switched OT probing off', NOW() - INTERVAL '1 minute')`, f.tenant); err != nil {
		t.Fatal(err)
	}

	off, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil {
		t.Fatalf("CreateJob (switch off): %v — the IT half of the job must still be created", err)
	}
	if audit, n := otOf(t, off.ID); len(audit) != 0 || n != 0 {
		t.Fatalf("switch OFF: ot_probe_protocols=%v OT targets=%d, want none — the off-switch must drop OT probes", audit, n)
	}
	var itTargets int
	if err := f.raw.QueryRow(`SELECT count(*) FROM discovery_targets WHERE job_id = $1 AND 443 = ANY(ports)`, off.ID).Scan(&itTargets); err != nil || itTargets == 0 {
		t.Fatalf("switch OFF: targets on 443=%d err=%v, want the rest of the job kept", itTargets, err)
	}
	// A switched-off OT protocol's port is not even in the plan: nothing
	// connects to it.
	if off.Plan == nil || off.Plan.TCPPorts != "443" {
		t.Fatalf("switch OFF: plan = %+v, want custom on 443 only", off.Plan)
	}

	// OT-only with the switch off: nothing left to scan, refused rather than
	// created as a job that scans nothing.
	before := f.countJobs(t)
	if _, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.183.0.10"}, ExecutionMode: "async", OTProbeProtocols: []string{"Modbus"},
	}); err == nil || !strings.Contains(err.Error(), "OT probe is required") {
		t.Fatalf("OT-only request with the switch off: err=%v, want the refusal", err)
	}
	if after := f.countJobs(t); after != before {
		t.Fatalf("a refused OT-only request wrote %d job(s)", after-before)
	}
}

// With the paywall gone the switch is on by default, so the refusal of OT
// probes on AUTOMATIC jobs is what keeps a PLC from being probed without a
// person asking. Pinned with the switch ON — the state where it is the only
// thing standing in the way.
func TestIntegration_CreateJob_AutomaticScanRefusesOTWithTheSwitchOn(t *testing.T) {
	f := newDispatchFixture(t)
	if _, err := f.raw.Exec(`UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community') WHERE id = $1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	// An eligible tenant asset, so the automatic-scan authorization would
	// otherwise ADMIT this job: the OT refusal must be the only thing that
	// stops it.
	if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES(gen_random_uuid(),$1,'plc-host','10.183.0.10','server','hardware.computer.server','monitoring')`, f.tenant); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets:          []string{"10.183.0.10"},
		Protocols:        []string{"TLS"},
		Ports:            []int{443},
		ExecutionMode:    "async",
		OTProbeProtocols: []string{"Modbus"},
		Options:          map[string]interface{}{"origin": "auto_scan"},
	})
	if err == nil || !strings.Contains(err.Error(), "OT") {
		t.Fatalf("automatic job requesting an OT probe: err=%v, want the OT refusal", err)
	}
	var jobs int
	if err := f.raw.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id = $1`, f.tenant).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("automatic OT job left %d job rows (err %v), want none", jobs, err)
	}
}
