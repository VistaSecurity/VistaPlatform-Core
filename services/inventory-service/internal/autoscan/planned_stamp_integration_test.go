package autoscan

// The automatic-scan freshness stamp for a PLANNED job ( WP3, spec V6),
// against a real Postgres. The job's hosts are stored the way the planned path
// stores them — jobunits.RecordSensorBatch for a tenant sensor's report,
// jobunits.Commit for the Platform Sensor's run — and the real store methods
// read them:
//
//   - StampCompletedScans stamps the endpoint the completed job found, and
//     not one it did not;
//   - ClearUnstartedScanStamps hands back the enqueue stamp of a planned job
//     that failed before its sensor reported anything, and keeps it for one
//     that failed after the sensor began (its first report set started_at);
//   - the in-flight gate and the recent-runs list see a planned job as they
//     see a legacy one.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const plannedScanAddr = "10.0.0.30"

type plannedScan struct {
	jobID    uuid.UUID
	unit     jobunits.Unit
	assetID  uuid.UUID
	endpoint map[int]uuid.UUID // port → asset_endpoints.id
}

// seedPlannedAutoScan writes a monitoring asset with endpoints on 443 and 22,
// the planned automatic job its enqueue stamp names (RecordScanned), the
// job's target and its one unit at attempt 1. platform selects the executor:
// a job the Platform Sensor is running, or one dispatched to sensor and
// awaiting it.
func seedPlannedAutoScan(t *testing.T, store *Store, db *sql.DB, tenant, sensor uuid.UUID, platform bool) plannedScan {
	t.Helper()
	s := plannedScan{jobID: uuid.New(), assetID: uuid.New(), endpoint: map[int]uuid.UUID{443: uuid.New(), 22: uuid.New()}}
	execOrFail(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, primary_address, metadata,
		                    last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'planned.example.test', 'server', 'hardware.computer.server', 'monitoring', $3::inet, '{"keep_me":"yes"}'::jsonb,
		        NOW(), NOW(), NOW(), NOW())`, s.assetID, tenant, plannedScanAddr)
	for port, id := range s.endpoint {
		execOrFail(t, db, `
			INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4::inet, $5, 'tcp', NOW(), NOW())`, id, tenant, s.assetID, plannedScanAddr, port)
	}
	options := JobOptions()
	meta, _ := json.Marshal(map[string]any{shareddisc.ScanPlanMetadataKey: map[string]any{"depth": "custom"}, "options": options})
	if platform {
		execOrFail(t, db, `INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, started_at, metadata) VALUES ($1, $2, 'platform', 'running', NOW(), $3::jsonb)`,
			s.jobID, tenant, string(meta))
	} else {
		execOrFail(t, db, `
			INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, requested_sensor_ids, assigned_sensor_id, dispatched_at, metadata)
			VALUES ($1, $2, 'sensors', $3, ARRAY[$4::text], $4::uuid, NOW(), $5::jsonb)`,
			s.jobID, tenant, sensordispatch.StatusAwaitingSensor, sensor.String(), string(meta))
	}
	s.unit = jobunits.Unit{JobID: s.jobID.String(), TenantID: tenant.String(), TargetInput: plannedScanAddr, Address: plannedScanAddr}
	if err := db.QueryRow(`INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports) VALUES ($1, $2, $3, '{}', ARRAY[22, 443]) RETURNING id`,
		s.jobID, tenant, plannedScanAddr).Scan(&s.unit.TargetID); err != nil {
		t.Fatal(err)
	}
	status := "pending"
	if platform {
		status = "running"
	}
	if err := db.QueryRow(`INSERT INTO discovery_job_units (tenant_id, job_id, target_id, address, attempts, status) VALUES ($1, $2, $3, $4, 1, $5) RETURNING id`,
		tenant, s.jobID, s.unit.TargetID, plannedScanAddr, status).Scan(&s.unit.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordScanned(context.Background(), tenant, []uuid.UUID{s.assetID}, s.jobID.String(), time.Now()); err != nil {
		t.Fatalf("RecordScanned: %v", err)
	}
	return s
}

// tlsOn443 is the host's engine output: TLS answered on 443, 22 refused.
func tlsOn443() shareddisc.UnitOutput {
	a := netip.MustParseAddr(plannedScanAddr)
	return shareddisc.UnitOutput{
		Host: shareddisc.HostScan{Addr: a, Liveness: shareddisc.LivenessUp, LivenessEvidence: "tcp-open:443", PortsRequested: 2, Open: []int{443}, OpenCount: 1, Closed: 1},
		TCP: []shareddisc.Observation{
			{Addr: a, Port: 443, Transport: "tcp", State: "open", Protocol: "TLS", Identified: true,
				Result: &shareddisc.ProbeResult{Protocol: "TLS", Port: 443, TLSVersions: []string{"TLS 1.3"}, SelectedCipher: "TLS_AES_128_GCM_SHA256"}},
			{Addr: a, Port: 22, Transport: "tcp", State: "closed"},
		},
	}
}

func newPlannedStampFixture(t *testing.T) (*Store, *sql.DB, uuid.UUID, uuid.UUID) {
	t.Helper()
	store, db, tenant := newStampFixture(t)
	testdb.ApplySchemaAndSeed(t, db)
	sensor := uuid.New()
	execOrFail(t, db, `INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, last_heartbeat) VALUES ($1, $2, 'planned-sensor', 'linux', '1.0.0', 'datacenter_host', 'active', NOW())`, sensor, tenant)
	return store, db, tenant, sensor
}

func TestIntegration_StampCompletedScans_PlannedJob(t *testing.T) {
	for _, executor := range []string{"sensor", "platform"} {
		t.Run(executor, func(t *testing.T) {
			store, db, tenant, sensor := newPlannedStampFixture(t)
			ctx := context.Background()
			platform := executor == "platform"
			s := seedPlannedAutoScan(t, store, db, tenant, sensor, platform)

			inFlight, err := store.AddressesWithScanInFlight(ctx, tenant)
			if err != nil || !inFlight[plannedScanAddr] {
				t.Fatalf("in-flight gate missed the planned job: %v %v", inFlight, err)
			}

			if platform {
				err = shareddatabase.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
					return jobunits.Commit(tx, s.unit, tlsOn443(), jobunits.CommitOptions{From: "running", Attempt: 1, ActiveScan: true})
				})
				if err != nil {
					t.Fatalf("platform commit: %v", err)
				}
			} else {
				resp, err := jobunits.RecordSensorBatch(ctx, db, tenant, sensor, s.jobID,
					sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sensordispatch.NewUnitResult(s.unit.TargetID, plannedScanAddr, 1, tlsOn443())}})
				if err != nil || resp.Accepted != 1 {
					t.Fatalf("sensor report = %+v %v", resp, err)
				}
			}
			// Not completed yet: nothing is stamped.
			if n, err := store.StampCompletedScans(ctx, tenant); err != nil || n != 0 {
				t.Fatalf("stamped %d (%v) before the job completed", n, err)
			}
			execOrFail(t, db, `UPDATE discovery_jobs SET status = 'completed', completed_at = NOW() WHERE id = $1`, s.jobID)

			n, err := store.StampCompletedScans(ctx, tenant)
			if err != nil || n != 1 {
				t.Fatalf("StampCompletedScans = %d %v, want the one endpoint the job found", n, err)
			}
			if at, status := readStamp(t, db, tenant, s.endpoint[443]); !at.Valid || status.String != "completed" {
				t.Fatalf("443 = %v %v, want stamped", at, status)
			}
			if at, _ := readStamp(t, db, tenant, s.endpoint[22]); at.Valid {
				t.Fatalf("22 was stamped (%v) though the job found nothing there", at)
			}

			inFlight, err = store.AddressesWithScanInFlight(ctx, tenant)
			if err != nil || inFlight[plannedScanAddr] {
				t.Fatalf("a completed planned job still reads in flight: %v %v", inFlight, err)
			}
			recent, err := store.RecentJobs(ctx, tenant, 10)
			if err != nil || len(recent) != 1 || recent[0].ID != s.jobID.String() || recent[0].Status != "completed" || recent[0].TargetCount != 1 {
				t.Fatalf("recent runs = %+v %v", recent, err)
			}
			if want := map[bool]string{true: "platform", false: "sensor"}[platform]; recent[0].Executor != want {
				t.Fatalf("executor = %s, want %s", recent[0].Executor, want)
			}
		})
	}
}

// A planned sensor job the stale-dispatch sweep failed. Whether its enqueue
// stamp is handed back depends on whether the sensor ever began: its first
// report — a host or an empty ping — sets started_at (jobunits.RecordSensorBatch).
func TestIntegration_ClearUnstartedScanStamps_PlannedJob(t *testing.T) {
	for _, c := range []struct {
		name      string
		report    func(t *testing.T, db *sql.DB, tenant, sensor uuid.UUID, s plannedScan)
		wantClear bool
	}{
		{"never reported", nil, true},
		{"pinged, then stalled", func(t *testing.T, db *sql.DB, tenant, sensor uuid.UUID, s plannedScan) {
			if resp, err := jobunits.RecordSensorBatch(context.Background(), db, tenant, sensor, s.jobID, sensordispatch.UnitBatch{}); err != nil || resp.Code != "" {
				t.Fatalf("ping = %+v %v", resp, err)
			}
		}, false},
		{"reported a host, then stalled", func(t *testing.T, db *sql.DB, tenant, sensor uuid.UUID, s plannedScan) {
			resp, err := jobunits.RecordSensorBatch(context.Background(), db, tenant, sensor, s.jobID,
				sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sensordispatch.NewUnitResult(s.unit.TargetID, plannedScanAddr, 1, tlsOn443())}})
			if err != nil || resp.Accepted != 1 {
				t.Fatalf("report = %+v %v", resp, err)
			}
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			store, db, tenant, sensor := newPlannedStampFixture(t)
			s := seedPlannedAutoScan(t, store, db, tenant, sensor, false)
			if c.report != nil {
				c.report(t, db, tenant, sensor, s)
			}
			// What the sweep's failDispatch writes: the verdict, never a start.
			execOrFail(t, db, `UPDATE discovery_jobs SET status = 'failed', completed_at = NOW(),
			    error_message = 'the sensor stopped reporting progress' WHERE id = $1`, s.jobID)

			n, err := store.ClearUnstartedScanStamps(context.Background(), tenant)
			if err != nil {
				t.Fatalf("ClearUnstartedScanStamps: %v", err)
			}
			at, job, keep := readScanStamp(t, db, tenant, s.assetID)
			if c.wantClear {
				if n != 1 || at.Valid || job.Valid || keep.String != "yes" {
					t.Fatalf("cleared %d; stamp %v/%v keep=%v — want the stamp handed back, nothing else touched", n, at, job, keep)
				}
				return
			}
			if n != 0 || !at.Valid || job.String != s.jobID.String() {
				t.Fatalf("cleared %d; stamp %v/%v — the sensor began the job, so its stamp stays", n, at, job)
			}
		})
	}
}
