package services

// A planned scan's per-host reports ( WP2b) through sensor-manager's
// service, against a real Postgres: only the sensor the job was dispatched to
// may report; a host is stored once however often it is re-sent; a report
// of a cancelled job is answered "cancelled" and stores nothing; and when the
// sensor reports the job finished, a host it never reported is failed with
// the reason (so the coverage says so, and a Retry scans it).
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// plannedJob is a scan-plan job dispatched to the fixture's sensor at attempt
// 1, with one target and a pending unit per address.
func (f *completionFixture) plannedJob(t *testing.T, addrs ...string) (uuid.UUID, string) {
	t.Helper()
	jobID := f.dispatchedJob(t, sensordispatch.StatusAwaitingSensor)
	if _, err := f.db.Exec(`UPDATE discovery_jobs SET metadata = jsonb_build_object('scan_plan', jsonb_build_object('depth', 'custom')) WHERE id = $1`, jobID); err != nil {
		t.Fatal(err)
	}
	var targetID string
	if err := f.db.QueryRow(`
		INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports)
		VALUES ($1, $2, '10.183.9.0/30', '{}', ARRAY[22]) RETURNING id`, jobID, f.tenant).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if _, err := f.db.Exec(`INSERT INTO discovery_job_units (tenant_id, job_id, target_id, address, attempts) VALUES ($1, $2, $3, $4, 1)`,
			f.tenant, jobID, targetID, a); err != nil {
			t.Fatal(err)
		}
	}
	return jobID, targetID
}

func sshHost(targetID, addr string) sensordispatch.UnitResult {
	a := netip.MustParseAddr(addr)
	return sensordispatch.NewUnitResult(targetID, addr, 1, discovery.UnitOutput{
		Host: discovery.HostScan{Addr: a, Liveness: discovery.LivenessUp, LivenessEvidence: "tcp-open:22", PortsRequested: 1, Open: []int{22}, OpenCount: 1},
		TCP:  []discovery.Observation{{Addr: a, Port: 22, Transport: "tcp", State: "open", Protocol: "SSH", Identified: true}},
	})
}

func (f *completionFixture) unitStatus(t *testing.T, jobID uuid.UUID, addr string) string {
	t.Helper()
	var s string
	if err := f.db.QueryRow(`SELECT status FROM discovery_job_units WHERE job_id = $1 AND address = $2`, jobID, addr).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *completionFixture) count(t *testing.T, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntegration_RecordSensorUnits_StoresEachHostOnce(t *testing.T) {
	f := newCompletionFixture(t)
	jobID, targetID := f.plannedJob(t, "10.183.9.1", "10.183.9.2")
	batch := sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sshHost(targetID, "10.183.9.1")}}

	resp, err := f.svc.RecordSensorUnits(context.Background(), f.tenant, f.sensor, jobID, batch)
	if err != nil || resp.Accepted != 1 || resp.Code != "" {
		t.Fatalf("first report = %+v %v", resp, err)
	}
	findings := `SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1`
	queued := `SELECT COUNT(*) FROM sensor_discoveries WHERE batch_id = $1 AND sensor_id = $2`
	if f.count(t, findings, jobID) != 1 || f.count(t, queued, jobID, f.sensor) != 1 {
		t.Fatalf("after one host: %d finding(s), %d queued", f.count(t, findings, jobID), f.count(t, queued, jobID, f.sensor))
	}
	// Re-sent (the answer was lost): nothing stored twice.
	resp, err = f.svc.RecordSensorUnits(context.Background(), f.tenant, f.sensor, jobID, batch)
	if err != nil || resp.Duplicate != 1 || resp.Accepted != 0 {
		t.Fatalf("re-sent report = %+v %v", resp, err)
	}
	if f.count(t, findings, jobID) != 1 || f.count(t, queued, jobID, f.sensor) != 1 {
		t.Fatal("a re-sent report was stored again")
	}
	// Another attempt's report, and an address the job does not have.
	stale := sshHost(targetID, "10.183.9.2")
	stale.Attempt = 7
	unknown := sshHost(targetID, "10.183.9.3")
	resp, err = f.svc.RecordSensorUnits(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{stale, unknown}})
	if err != nil || resp.Stale != 1 || resp.Unknown != 1 || resp.Accepted != 0 {
		t.Fatalf("stale/unknown = %+v %v", resp, err)
	}
	// Another sensor of the same tenant may not report it.
	other := uuid.New()
	if _, err := f.db.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status) VALUES ($1, $2, 'other', 'linux', '1', 'datacenter_host', 'active')`, other, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RecordSensorUnits(context.Background(), f.tenant, other, jobID, batch); !errors.Is(err, ErrJobNotAssignedToSensor) {
		t.Fatalf("another sensor's report = %v", err)
	}
}

func TestIntegration_RecordSensorUnits_CancelledJobAnswersStopAndStoresNothing(t *testing.T) {
	f := newCompletionFixture(t)
	jobID, targetID := f.plannedJob(t, "10.183.9.1")
	if _, err := f.db.Exec(`UPDATE discovery_jobs SET status = 'cancelled' WHERE id = $1`, jobID); err != nil {
		t.Fatal(err)
	}
	resp, err := f.svc.RecordSensorUnits(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sshHost(targetID, "10.183.9.1")}})
	if err != nil || resp.Code != sensordispatch.UnitsCodeJobCancelled || !resp.Stop() {
		t.Fatalf("report of a cancelled job = %+v %v", resp, err)
	}
	if f.unitStatus(t, jobID, "10.183.9.1") != "pending" || f.count(t, `SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1`, jobID) != 0 {
		t.Fatal("a report of a cancelled job was stored")
	}
}

func TestIntegration_CompleteSensorJob_FailsThePlannedHostsNeverReported(t *testing.T) {
	f := newCompletionFixture(t)
	jobID, targetID := f.plannedJob(t, "10.183.9.1", "10.183.9.2")
	if _, err := f.svc.RecordSensorUnits(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sshHost(targetID, "10.183.9.1")}}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CompleteSensorJob(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.Completion{Status: "completed", TotalTargets: 2, SuccessfulTargets: 1, FailedTargets: 1}); err != nil {
		t.Fatalf("CompleteSensorJob: %v", err)
	}
	if s := f.unitStatus(t, jobID, "10.183.9.1"); s != "done" {
		t.Fatalf("reported host = %s", s)
	}
	var status, msg string
	if err := f.db.QueryRow(`SELECT status, error_message FROM discovery_job_units WHERE job_id = $1 AND address = '10.183.9.2'`, jobID).Scan(&status, &msg); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || msg != unreportedHostMessage {
		t.Fatalf("unreported host = %s %q", status, msg)
	}
	var target string
	if err := f.db.QueryRow(`SELECT status FROM discovery_targets WHERE id = $1`, targetID).Scan(&target); err != nil {
		t.Fatal(err)
	}
	if target != "completed" {
		t.Fatalf("target = %s, want completed (one host done)", target)
	}
}

func TestIntegration_RecordSensorUnits_RefusesALegacyJob(t *testing.T) {
	f := newCompletionFixture(t)
	jobID := f.dispatchedJob(t, sensordispatch.StatusAwaitingSensor)
	if _, err := f.svc.RecordSensorUnits(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.UnitBatch{}); err == nil {
		t.Fatal("a protocols × ports job took a unit report")
	}
}
