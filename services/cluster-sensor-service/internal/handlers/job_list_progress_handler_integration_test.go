package handlers

// The job LIST the Discovery → Discovery Jobs page polls ( WP4b), driven
// through the real GetJobs handler against a real Postgres. Before this, the
// list carried neither a scan-plan job's plan nor its progress — every row read
// 0% while the single-job read showed the scan moving — so the page could not
// show a running scan's progress, depth or executor without a read per row.
//
//   - a running scan-plan job carries its plan, its per-HOST progress from its
//     work units, and its coverage, exactly as the single-job read does;
//   - a finished scan-plan job carries its plan (depth on the row) but no
//     progress or coverage — those are a detail-read concern, and filling
//     every finished row would cost two reads per row on a 100-row page;
//   - a legacy job's row is unchanged: no plan, progress 0, no coverage.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

const listTestPlan = `{"scan_plan":{"depth":"standard","pace":"normal","tcp_ports":"1-1000","udp_ports":"","tcp_port_count":1000,"udp_port_count":0,
	"run_from_requested":"auto","executor_resolved":"platform","executor_reason":"no sensor observes these targets",
	"depth_adjustments":[],"targets":[{"target":"10.45.0.0/30","class":"private","depth":"standard","addresses":4,
	"tcp_ports":"1-1000","udp_ports":"","tcp_port_count":1000,"udp_port_count":0,"estimated_probes":4000}],
	"estimated_probes":4000,"probe_limit":25000000}}`

// seedPlanJob writes a scan-plan job in status with one target and one work
// unit per entry of units (a unit status; "done" units answered on one port).
func seedPlanJob(t *testing.T, db *sqlx.DB, tenant uuid.UUID, status string, units ...string) string {
	t.Helper()
	jobID := seedDiscoveryJob(t, db, tenant)
	if _, err := db.Exec(`UPDATE discovery_jobs SET status = $2, execution_mode = 'async', metadata = $3::jsonb WHERE id = $1`,
		jobID, status, listTestPlan); err != nil {
		t.Fatalf("make plan job: %v", err)
	}
	var targetID string
	if err := db.QueryRow(`
		INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports, status)
		VALUES ($1, $2, '10.45.0.0/30', ARRAY[]::text[], ARRAY[]::int[], 'running') RETURNING id`, jobID, tenant).Scan(&targetID); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	for i, u := range units {
		open := 0
		if u == "done" {
			open = 1
		}
		if _, err := db.Exec(`
			INSERT INTO discovery_job_units (tenant_id, job_id, target_id, address, status, liveness_state, ports_requested, open_count, closed_count)
			VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 = 'done' THEN 'up' END, 1000, $6, CASE WHEN $5 = 'done' THEN 999 ELSE 0 END)`,
			tenant, jobID, targetID, "10.45.0."+string(rune('1'+i)), u, open); err != nil {
			t.Fatalf("insert unit: %v", err)
		}
	}
	return jobID
}

func TestIntegration_DiscoveryHandler_ListCarriesLivePlanProgress(t *testing.T) {
	h, db, tenant := lifecycleHandler(t)

	running := seedPlanJob(t, db, tenant, "running", "done", "pending", "pending", "running")
	finished := seedPlanJob(t, db, tenant, "completed", "done", "done", "done", "done")
	legacy := seedDiscoveryJob(t, db, tenant)
	setJobStatus(t, db, legacy, "running")
	addTargets(t, db, tenant, legacy, "completed", "pending")

	c, w := newTestContext(tenant, "")
	c.Request.URL.RawQuery = "page=1&page_size=100"
	h.GetJobs(c)
	if w.Code != http.StatusOK {
		t.Fatalf("GetJobs = %d %s", w.Code, w.Body)
	}
	var resp models.DiscoveryJobsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	byID := map[string]models.DiscoveryJob{}
	for _, j := range resp.Jobs {
		byID[j.ID] = j
	}

	r := byID[running]
	if r.Plan == nil || r.Plan.Depth != "standard" || r.Plan.ExecutorResolved != "platform" {
		t.Fatalf("running plan job: plan = %+v, want the stored plan (depth and executor for the row)", r.Plan)
	}
	// 1 of 4 hosts finished — per HOST from the units, not per target (the
	// single target is still running, which would read 0).
	if r.Progress != 25 {
		t.Errorf("running plan job: progress = %d, want 25 (1 of 4 hosts finished)", r.Progress)
	}
	if r.Coverage == nil || r.Coverage.HostsTotal != 4 || r.Coverage.HostsResponded != 1 || r.Coverage.HostsPending != 3 || r.Coverage.PortsOpen != 1 {
		t.Errorf("running plan job: coverage = %+v, want 4 hosts, 1 responded, 3 pending, 1 open port", r.Coverage)
	}

	// The single-job read and the list agree on the running job.
	c, w = newTestContext(tenant, running)
	h.GetJob(c)
	var single models.DiscoveryJob
	if err := json.Unmarshal(w.Body.Bytes(), &single); err != nil {
		t.Fatal(err)
	}
	if single.Progress != r.Progress || single.Coverage == nil || single.Coverage.HostsTotal != r.Coverage.HostsTotal {
		t.Errorf("list and single read disagree: list %d %+v, single %d %+v", r.Progress, r.Coverage, single.Progress, single.Coverage)
	}

	f := byID[finished]
	if f.Plan == nil || f.Plan.Depth != "standard" {
		t.Errorf("finished plan job: plan = %+v, want it on the row", f.Plan)
	}
	if f.Coverage != nil || f.Progress != 0 {
		t.Errorf("finished plan job: progress %d coverage %+v — the list fills only jobs that have not ended", f.Progress, f.Coverage)
	}

	l := byID[legacy]
	if l.Plan != nil || l.Coverage != nil || l.Progress != 0 || l.TargetCounts != nil {
		t.Errorf("legacy job's row changed: plan %+v coverage %+v progress %d counts %+v", l.Plan, l.Coverage, l.Progress, l.TargetCounts)
	}
}
