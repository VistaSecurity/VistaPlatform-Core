package services

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func sourceClaimFixture(t *testing.T, db *sql.DB, agentLane bool) (*JobQueueService, uuid.UUID, *uuid.UUID, *models.DeviceJob) {
	t.Helper()
	tenant := testdb.NewTenant(t, db)
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	device, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", ManagementURL: strptr("https://192.0.2.2"), Metadata: map[string]interface{}{"identity_enrichment_executor": "platform"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active) VALUES($1,$2,'Claim guard network','cidr','192.0.2.0/24','production',true)`, uuid.New(), tenant); err != nil {
		t.Fatal(err)
	}
	var agent *uuid.UUID
	executor := "platform"
	if agentLane {
		id := insertDeviceAgent(t, db, tenant)
		agent = &id
		executor = id.String()
		if _, err = db.Exec(`UPDATE device_agents SET last_heartbeat=now() WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	enableSourceRefresh(t, db, tenant)
	queue := NewJobQueueService(db, db, nil)
	receipt := refreshObservation(t, db, tenant, "sensor:"+uuid.NewString(), nil)
	job, err := queue.CreateJob(context.Background(), models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &device.ID, AgentID: agent, Parameters: map[string]interface{}{"identity_refresh_request_id": receipt.RequestID.String(), "identity_refresh_executor": executor, "management_url": "https://192.0.2.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO identity_source_refreshes(tenant_id,id,observation_id,fingerprint,state,device_job_id) VALUES($1,$2,$3,'claim-guard','queued',$4)`, tenant, receipt.RequestID, receipt.ObservationID, job.ID); err != nil {
		t.Fatal(err)
	}
	return queue, tenant, agent, job
}

func waitSourcePolicyLock(t *testing.T, db *sql.DB, tenant uuid.UUID) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%SELECT config FROM tenant_admin_settings%' AND query LIKE '%FOR SHARE%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("claim did not wait for tenant %s policy", tenant)
}

func TestIntegration_SourceClaimPolicyAndAssignmentAreAtomic(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	for _, agentLane := range []bool{false, true} {
		t.Run(map[bool]string{false: "platform", true: "agent"}[agentLane], func(t *testing.T) {
			queue, tenant, agent, job := sourceClaimFixture(t, db, agentLane)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			if _, err = tx.ExecContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR UPDATE`, tenant); err != nil {
				t.Fatal(err)
			}
			type result struct {
				job *models.DeviceJob
				err error
			}
			done := make(chan result, 1)
			go func() { j, e := queue.claimAuthorizedJob(ctx, agent, &tenant); done <- result{j, e} }()
			waitSourcePolicyLock(t, db, tenant)
			// The claimant waits for policy before claiming or locking the job.
			var status string
			if err = tx.QueryRowContext(ctx, `SELECT status FROM device_jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT`, tenant, job.ID).Scan(&status); err != nil || status != "pending" {
				t.Fatalf("premature claim %s: %v", status, err)
			}
			if _, err = tx.ExecContext(ctx, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,enabled}','false') WHERE tenant_id=$1`, tenant); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			got := <-done
			if got.err != nil || got.job != nil {
				t.Fatalf("paused work claimed: %v %v", got.job, got.err)
			}
			if err = db.QueryRow(`SELECT status FROM device_jobs WHERE id=$1`, job.ID).Scan(&status); err != nil || status != "pending" {
				t.Fatalf("pause lost queued work: %s %v", status, err)
			}
			enableSourceRefresh(t, db, tenant)
			got.job, got.err = queue.claimAuthorizedJob(ctx, agent, &tenant)
			if got.err != nil || got.job == nil || got.job.ID != job.ID {
				t.Fatalf("resume claim %v %v", got.job, got.err)
			}
			again, err := queue.claimAuthorizedJob(ctx, agent, &tenant)
			if err != nil || again != nil {
				t.Fatalf("repeat claim %v %v", again, err)
			}
		})
	}
}

func TestIntegration_SourceClaimExpiryUsesCurrentClock(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	queue, tenant, agent, job := sourceClaimFixture(t, db, true)
	if _, err := db.Exec(`UPDATE device_jobs SET expires_at=clock_timestamp()+interval '400 milliseconds' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR UPDATE`, tenant); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		j, e := queue.claimAuthorizedJob(ctx, agent, &tenant)
		if e == nil && j != nil {
			e = errSourceRefreshDenied
		}
		done <- e
	}()
	waitSourcePolicyLock(t, db, tenant)
	if _, err = tx.ExecContext(ctx, `SELECT pg_sleep(0.5)`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatalf("expired while policy locked was claimed: %v", err)
	}
	var status string
	if err = db.QueryRow(`SELECT status FROM device_jobs WHERE id=$1`, job.ID).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("expired state %s: %v", status, err)
	}
}

func TestIntegration_PausedSourcesDoNotStarveOrdinaryJobs(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	queue, tenant, agent, job := sourceClaimFixture(t, db, true)
	for range 32 {
		if _, err := queue.CreateJob(context.Background(), models.CreateDeviceJobRequest{TenantID: tenant, JobType: job.JobType, AssetID: job.AssetID, AgentID: agent, Parameters: job.Parameters}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,enabled}','false') WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	ordinary, err := queue.CreateJob(context.Background(), models.CreateDeviceJobRequest{TenantID: tenant, JobType: job.JobType, AssetID: job.AssetID, AgentID: agent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE device_jobs SET parameters=NULL WHERE id=$1`, ordinary.ID); err != nil {
		t.Fatal(err)
	}
	got, err := queue.claimAuthorizedJob(context.Background(), agent, &tenant)
	if err != nil || got == nil || got.ID != ordinary.ID {
		t.Fatalf("paused jobs starved ordinary work: %v %v", got, err)
	}
}

func TestIntegration_SourceInsertionRechecksPolicyAfterPreparation(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	queue, tenant, _, previous := sourceClaimFixture(t, db, false)
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	prepare := func(ctx context.Context, tenant, id uuid.UUID) (models.CreateDeviceJobRequest, error) {
		_, err := db.ExecContext(ctx, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,enabled}','false') WHERE tenant_id=$1`, tenant)
		return models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &id, Parameters: map[string]interface{}{"management_url": "https://192.0.2.2"}}, err
	}
	service := NewConfiguredSourceRefresh(db, queue, devices, prepare)
	req := refreshObservation(t, db, tenant, "interrogation:"+previous.ID.String(), nil)
	got, err := service.Refresh(context.Background(), req)
	if err != nil || got.State != "blocked" || got.Reason != "enrichment_paused" {
		t.Fatalf("paused insert %+v: %v", got, err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM device_jobs WHERE tenant_id=$1 AND parameters->>'identity_refresh_request_id'=$2`, tenant, req.RequestID.String()).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unauthorized job inserted: %d %v", count, err)
	}
}

func TestIntegration_SourceClaimExpiryAfterAssetLockWait(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	queue, tenant, agent, job := sourceClaimFixture(t, db, true)
	if _, err := db.Exec(`UPDATE device_jobs SET expires_at=clock_timestamp()+interval '400 milliseconds' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `SELECT id FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, *job.AssetID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		j, e := queue.claimAuthorizedJob(ctx, agent, &tenant)
		if e == nil && j != nil {
			e = errSourceRefreshDenied
		}
		done <- e
	}()
	waiting := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%SELECT a.class_key,%FOR SHARE OF a,m%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("claim did not wait for source asset")
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_sleep(0.5)`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatalf("expired during asset authorization was claimed: %v", err)
	}
}

func TestIntegration_SourceClaimHonorsCurrentSensitiveAsset(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	queue, tenant, agent, job := sourceClaimFixture(t, db, true)
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,sensitive_asset_ids}',jsonb_build_array($2::text)) WHERE tenant_id=$1`, tenant, job.AssetID.String()); err != nil {
		t.Fatal(err)
	}
	got, err := queue.claimAuthorizedJob(context.Background(), agent, &tenant)
	if err != nil || got != nil {
		t.Fatalf("sensitive source dispatched: %v %v", got, err)
	}
	var status string
	if err = db.QueryRow(`SELECT status FROM device_jobs WHERE id=$1`, job.ID).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("denied queued source state %s: %v", status, err)
	}
}
