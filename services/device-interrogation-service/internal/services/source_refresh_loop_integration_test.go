package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// refreshJobCount is how many interrogations identity enrichment has started
// for the tenant: every source-refresh device job, whatever became of it.
func refreshJobCount(t *testing.T, db *sql.DB, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM device_jobs WHERE tenant_id=$1 AND parameters?'identity_refresh_source_key'`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestIntegration_SourceRefresh_NoSelfFeedingLoop is the reported loop, end to
// end on the real producer and the real planner: a UniFi controller's
// interrogation, under enforced admission, leaves peers unresolved
// (network_scope_unresolved); the enrichment coordinator asks for a source
// refresh of every unresolved observation once per cycle; each refresh is
// another interrogation of the controller, whose answer — the same peers — is
// persisted under that run's own `interrogation:<run>` source ref, which is a
// new set of unresolved observations for the next tick.
//
// The tick here is what the coordinator does for an observation it has not
// asked about yet in the cycle: one Refresh with a new request id. Each run a
// refresh starts is "executed" by persisting the controller's same answer under
// the run's id and marking the job completed. Between ticks every clock the
// planner reads is moved fifteen minutes into the past — past the five-minute
// reuse window, well inside minSourceRefreshInterval.
//
// Mutations performed, each observed red, then restored:
//   - plan withholds only a LINKED observation from its own source (the old
//     `fromSource && linked.Valid`) → one refresh on the first tick, then the
//     per-source bound holds it at one: 1 job, not 0.
//   - that, AND sourceRefreshedRecentlyTx always false (both properties gone,
//     the shipped behaviour) → one new interrogation per tick: 6 jobs.
func TestIntegration_SourceRefresh_NoSelfFeedingLoop(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", testMasterKey)
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	ctx := context.Background()
	run := interrogateUniFiFixture(t, db, func(tenant uuid.UUID) {
		if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
			SELECT $1,id,'{"quantity":100}'::jsonb,'source refresh loop' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
			ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
			t.Fatal(err)
		}
	})
	if run.persistErr != nil {
		t.Fatalf("fixture interrogation: %v", run.persistErr)
	}
	tenant, controller := run.tenant, run.controller

	// Make the controller a source a refresh could actually run against: a
	// scoped https management address in the run's own network, monitored,
	// platform re-checks allowed, enrichment on. Every gate the planner applies
	// passes, so only the properties under test can stop it.
	const managementURL = "https://192.0.2.2"
	if _, err := db.Exec(`UPDATE asset_management SET management_url=$3 WHERE tenant_id=$1 AND asset_id=$2`, tenant, controller, managementURL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, controller); err != nil {
		t.Fatal(err)
	}
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	if _, err := devices.UpdateDevice(ctx, tenant, controller, models.UpdateDeviceRequest{PlatformReinterrogationAllowed: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}
	enableSourceRefresh(t, db, tenant)
	queue := NewJobQueueService(db, db, nil)
	service := NewConfiguredSourceRefresh(db, queue, devices, func(context.Context, uuid.UUID, uuid.UUID) (models.CreateDeviceJobRequest, error) {
		return models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &controller, Parameters: map[string]interface{}{"asset_id": controller.String(), "management_url": managementURL}}, nil
	})
	sink := &DeviceInterrogationService{db: db, observations: NewObservationSink(db)}

	// The first run is a person's interrogation (a device job with no refresh
	// receipt), persisted the way the platform executor persists it.
	first := completedJob(t, db, queue, tenant, controller, nil)
	if err := sink.persistObservations(ctx, tenant, controller, first, run.result); err != nil {
		t.Fatalf("first run: %v", err)
	}
	var held int
	if err := db.QueryRow(`SELECT count(*) FROM identity_observations WHERE tenant_id=$1 AND source_ref=$2 AND state='unresolved' AND asset_id IS NULL`,
		tenant, interrogationSource(first).Ref).Scan(&held); err != nil {
		t.Fatal(err)
	}
	// Without held peers the loop has nothing to feed on and the test proves
	// nothing.
	if held == 0 {
		t.Fatal("precondition: the controller's run left no unresolved peer")
	}

	asked := map[uuid.UUID]bool{}
	selfPlanned := 0
	const ticks = 6
	for tick := 1; tick <= ticks; tick++ {
		before := time.Now()
		rows, err := db.Query(`SELECT id,evidence FROM identity_observations WHERE tenant_id=$1 AND state='unresolved' AND asset_id IS NULL ORDER BY id`, tenant)
		if err != nil {
			t.Fatal(err)
		}
		var due []SourceRefreshRequest
		for rows.Next() {
			var id uuid.UUID
			var raw []byte
			if err := rows.Scan(&id, &raw); err != nil {
				t.Fatal(err)
			}
			if asked[id] {
				continue
			}
			var evidence identity.Observation
			if err := json.Unmarshal(raw, &evidence); err != nil {
				t.Fatal(err)
			}
			due = append(due, SourceRefreshRequest{RequestID: uuid.New(), TenantID: tenant, ObservationID: id, Evidence: evidence})
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		for _, req := range due {
			asked[req.ObservationID] = true
			result, err := service.Refresh(ctx, req)
			if err != nil {
				t.Fatalf("tick %d refresh: %v", tick, err)
			}
			if result.State == "blocked" || result.State == "failed" {
				t.Fatalf("tick %d: a gate other than the ones under test stopped the refresh: %+v", tick, result)
			}
			// Counted rather than fatal, so a regression still shows how the
			// job count moves below.
			if strings.HasPrefix(req.Evidence.Source.Ref, "interrogation:") && req.Evidence.Source.Ref != interrogationSource(run.jobID).Ref &&
				(result.State != "completed" || result.Reason != reasonSourceAlreadyReportedPeer) {
				selfPlanned++
			}
		}
		// Execute every run started this tick: the controller says the same
		// thing again, under the run's id.
		started, err := db.Query(`SELECT id FROM device_jobs WHERE tenant_id=$1 AND parameters?'identity_refresh_source_key' AND status<>'completed'`, tenant)
		if err != nil {
			t.Fatal(err)
		}
		var runs []uuid.UUID
		for started.Next() {
			var id uuid.UUID
			if err := started.Scan(&id); err != nil {
				t.Fatal(err)
			}
			runs = append(runs, id)
		}
		if err := started.Close(); err != nil {
			t.Fatal(err)
		}
		for _, id := range runs {
			if err := sink.persistObservations(ctx, tenant, controller, id, run.result); err != nil {
				t.Fatalf("tick %d run %s: %v", tick, id, err)
			}
			if _, err := db.Exec(`UPDATE device_jobs SET status='completed',completed_at=now() WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
		}
		// Fifteen minutes pass.
		if _, err := db.Exec(`UPDATE device_jobs SET created_at=created_at-interval '15 minutes',completed_at=completed_at-interval '15 minutes' WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE identity_source_refreshes SET created_at=created_at-interval '15 minutes',next_attempt_at=next_attempt_at-interval '15 minutes' WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
		t.Logf("tick %d: %d observations asked, %d runs started, %d refresh jobs in all (%s)", tick, len(due), len(runs), refreshJobCount(t, db, tenant), time.Since(before).Round(time.Millisecond))
	}
	if n := refreshJobCount(t, db, tenant); n != 0 || selfPlanned != 0 {
		t.Fatalf("identity enrichment started %d interrogations of the controller (%d of its own unresolved peers planned against it), want 0", n, selfPlanned)
	}
	// The outcome is durable on the receipt the coordinator polls, so the next
	// poll does not re-plan it.
	var reason string
	if err := db.QueryRow(`SELECT r.reason FROM identity_source_refreshes r JOIN identity_observations o ON o.tenant_id=r.tenant_id AND o.id=r.observation_id
	  WHERE r.tenant_id=$1 AND o.source_ref=$2 AND r.state='completed' LIMIT 1`, tenant, interrogationSource(first).Ref).Scan(&reason); err != nil || reason != reasonSourceAlreadyReportedPeer {
		t.Fatalf("receipt reason %q: %v", reason, err)
	}
}

// TestIntegration_SourceRefresh_PerSourceInterval: a sensor's sighting linked
// to a managed controller still gets a refresh of the controller (the case a
// source refresh is for), but the controller is asked at most once per
// minSourceRefreshInterval however many observations want it, and a person's
// own interrogation is not limited by that and does not count toward it.
//
// Mutations performed, each observed red, then restored:
//   - sourceRefreshedRecentlyTx always false → the third observation, past the
//     five-minute reuse window, starts a second interrogation.
//   - report the withheld refresh as "blocked" instead of "completed" → state
//     "blocked" (and the coordinator would retry it on backoff for ever).
//
// Counting only completed runs in sourceRefreshedRecentlyTx is caught by
// TestIntegration_SourceRefreshAtomicReplayAndCompletion, whose recent run
// FAILED.
func TestIntegration_SourceRefresh_PerSourceInterval(t *testing.T) {
	f := newConsentFixture(t)
	ctx := context.Background()
	if _, err := f.devices.UpdateDevice(ctx, f.tenant, f.device.ID, models.UpdateDeviceRequest{PlatformReinterrogationAllowed: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}

	// One sighting: one refresh of the controller.
	first := refreshObservation(t, f.db, f.tenant, "sensor:"+uuid.NewString(), &f.device.ID)
	result, err := f.service.Refresh(ctx, first)
	if err != nil || result.State != "queued" {
		t.Fatalf("first sighting: %+v %v", result, err)
	}
	// A second while that run is pending shares it.
	second := refreshObservation(t, f.db, f.tenant, "sensor:"+uuid.NewString(), &f.device.ID)
	if result, err = f.service.Refresh(ctx, second); err != nil || result.State != "queued" {
		t.Fatalf("second sighting: %+v %v", result, err)
	}
	if n := refreshJobCount(t, f.db, f.tenant); n != 1 {
		t.Fatalf("two sightings started %d interrogations, want 1 shared", n)
	}

	// The run finished ten minutes ago: outside the reuse window, inside the
	// interval. A third sighting completes its source stage without asking.
	if _, err := f.db.Exec(`UPDATE device_jobs SET status='completed',completed_at=now()-interval '10 minutes',created_at=now()-interval '15 minutes'
	  WHERE tenant_id=$1 AND parameters?'identity_refresh_source_key'`, f.tenant); err != nil {
		t.Fatal(err)
	}
	third := refreshObservation(t, f.db, f.tenant, "sensor:"+uuid.NewString(), &f.device.ID)
	if result, err = f.service.Refresh(ctx, third); err != nil || result.State != "completed" || result.Reason != reasonSourceRefreshedRecently {
		t.Fatalf("third sighting inside the interval: %+v %v", result, err)
	}
	assertNoRefreshJob(t, f.db, f.tenant, third)
	// The coordinator's poll of that receipt reads the same settled answer.
	if status, err := f.service.Status(ctx, f.tenant, third.RequestID); err != nil || status.State != "completed" || status.Reason != reasonSourceRefreshedRecently {
		t.Fatalf("receipt %+v: %v", status, err)
	}

	// A person's Interrogate (InterrogateDevice queues a plain device job) is
	// neither refused by the bound nor counted by it.
	operator, err := f.queue.CreateJob(ctx, models.CreateDeviceJobRequest{TenantID: f.tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &f.device.ID})
	if err != nil {
		t.Fatalf("operator interrogation inside the interval: %v", err)
	}
	if err := f.queue.validateRefreshClaim(ctx, operator); err != nil {
		t.Fatalf("operator interrogation refused at claim: %v", err)
	}
	if n := refreshJobCount(t, f.db, f.tenant); n != 1 {
		t.Fatalf("refresh jobs %d after an operator interrogation, want 1", n)
	}

	// Once the interval has passed, the controller may be asked again — once.
	if _, err := f.db.Exec(`UPDATE device_jobs SET created_at=now()-$2*interval '1 second'-interval '1 minute'
	  WHERE tenant_id=$1 AND parameters?'identity_refresh_source_key'`, f.tenant, int64(minSourceRefreshInterval/time.Second)); err != nil {
		t.Fatal(err)
	}
	fourth := refreshObservation(t, f.db, f.tenant, "sensor:"+uuid.NewString(), &f.device.ID)
	if result, err = f.service.Refresh(ctx, fourth); err != nil || result.State != "queued" {
		t.Fatalf("after the interval: %+v %v", result, err)
	}
	fifth := refreshObservation(t, f.db, f.tenant, "sensor:"+uuid.NewString(), &f.device.ID)
	if result, err = f.service.Refresh(ctx, fifth); err != nil || result.State != "queued" {
		t.Fatalf("shares the new run: %+v %v", result, err)
	}
	if n := refreshJobCount(t, f.db, f.tenant); n != 2 {
		t.Fatalf("refresh jobs %d after the interval, want 2", n)
	}
}
