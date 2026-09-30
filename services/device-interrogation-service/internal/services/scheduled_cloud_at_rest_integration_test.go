package services

// Scheduled (worker-run) cloud discovery delivers at-rest resources (W14,
// integrations review B6 second half).
//
// The worker used to turn devices into DiscoveredAssets through their crypto
// configs. A bucket, a database or a key store has none, so a scheduled run
// delivered none of them, in any identity mode; and the rows it did write
// carried no provider resource id, which is what inventory keys the platform
// collector's enforce-mode authority on. The worker now writes through
// the same CloudDiscoveryService.WriteSensorDiscoveries the interactive run
// uses. These tests drive the REAL executeCloudDiscovery and the REAL
// storeJobOutcome the worker runs after it; only the provider API is faked.
//
// Mutations (each run, then restored — see the PR):
//
//	executeCloudDiscovery back to the crypto-config → DiscoveredAsset loop
//	    → WritesThroughTheInteractiveWriter (no bucket or database row) and
//	      Refresh/full + /partial (the refresh never completes)
//	shouldProcessResults without `|| materializedByExecutor`
//	    → Refresh/partial (no processing block; waits forever)
//	statusTx without the outcome=failed branch
//	    → Refresh/failed reads "completed"
//	processing log without the executor-row count
//	    → WritesThroughTheInteractiveWriter (materialized 0)
//
// The inventory half — that exactly these rows become an object_storage /
// managed_database asset under enforce admission, matched on the next run —
// is the cloud-scheduled hop chain under
// shared/deviceinterrogation/testdata/pipeline/cloud-aws-scheduled/.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newScheduledCloudWorker is NewPlatformAgentWorker's cloud half without the
// NATS subscription: the real sink, the real result processor, a fake provider.
func newScheduledCloudWorker(owner, appDB *sql.DB, d cloudJobDiscoverer) *PlatformAgentWorker {
	jobQueue := NewJobQueueService(appDB, owner, nil)
	return &PlatformAgentWorker{
		db:           appDB,
		bypassDB:     owner,
		jobQueue:     jobQueue,
		cloudService: d,
		cloudSink: &platformCloudRunSink{
			cloud:     NewCloudDiscoveryService(appDB, owner, testMasterKey),
			discovery: NewDiscoveryIntegrationService(appDB, owner),
			queue:     jobQueue,
		},
		resultProcessor: NewResultProcessor(appDB, owner),
	}
}

// runWorkerCloudJob executes one queued cloud job exactly as processNextJob
// does once it has claimed it.
func runWorkerCloudJob(t *testing.T, w *PlatformAgentWorker, jobID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	t.Setenv("ENCRYPTION_MASTER_KEY", testMasterKey)
	job, err := w.jobQueue.GetJobByID(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJobByID: %v", err)
	}
	result, execErr := w.executeCloudDiscovery(ctx, job)
	w.storeJobOutcome(ctx, job, result, execErr)
}

type scheduledCloudRow struct {
	Hostname string
	Protocol string
	Port     int
	Sensor   uuid.UUID
	Meta     map[string]interface{}
}

func cloudRowsInBatch(t *testing.T, owner *sql.DB, tenant uuid.UUID, batch string) map[string]scheduledCloudRow {
	t.Helper()
	rows, err := owner.Query(`SELECT COALESCE(hostname,''), COALESCE(protocol,''), COALESCE(port,0), sensor_id, metadata
		FROM sensor_discoveries WHERE tenant_id=$1 AND batch_id=$2`, tenant, batch)
	if err != nil {
		t.Fatalf("read rows: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]scheduledCloudRow{}
	for rows.Next() {
		var r scheduledCloudRow
		var raw []byte
		if err := rows.Scan(&r.Hostname, &r.Protocol, &r.Port, &r.Sensor, &raw); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		if err := json.Unmarshal(raw, &r.Meta); err != nil {
			t.Fatalf("row metadata: %v", err)
		}
		out[r.Hostname] = r
	}
	return out
}

func deviceJobResults(t *testing.T, owner *sql.DB, jobID uuid.UUID) (status string, params, results map[string]interface{}) {
	t.Helper()
	var p, r []byte
	if err := owner.QueryRow(`SELECT status, parameters, COALESCE(results,'{}'::jsonb) FROM device_jobs WHERE id=$1`, jobID).Scan(&status, &p, &r); err != nil {
		t.Fatalf("read device job: %v", err)
	}
	_ = json.Unmarshal(p, &params)
	_ = json.Unmarshal(r, &results)
	return status, params, results
}

func TestIntegration_ScheduledCloudJob_WritesThroughTheInteractiveWriter(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	ctx := context.Background()
	integration := seedCloudIntegration(t, owner, tenant)

	// The collectors' own shapes (storage_encryption_service.go): no crypto
	// configs, the ARN in metadata. The SAME device values feed both writers
	// below, so any difference in the rows is a difference in the paths.
	bucket, database := s3Bucket("example-audit-logs"), rdsInstance("orders-db")
	d := &fixedCloudDiscoverer{provider: "aws", byType: map[string][]models.Device{
		"s3":  {bucket},
		"rds": {database},
	}}
	w := newScheduledCloudWorker(owner, appDB, d)

	var platformSensor uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM sensors WHERE tenant_id=$1 AND profile='device_interrogation'
		AND platform_managed AND deleted_at IS NULL ORDER BY created_at, id LIMIT 1`, tenant).Scan(&platformSensor); err != nil {
		t.Fatalf("the tenant has no platform-managed device-interrogation sensor: %v", err)
	}

	runOnce := func() (uuid.UUID, map[string]scheduledCloudRow) {
		t.Helper()
		job, err := w.jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
			TenantID: tenant, JobType: models.JobTypeCloudDiscovery, IntegrationID: &integration,
			Parameters: map[string]interface{}{"resource_types": []string{"s3", "rds"}, "regions": []string{"us-east-1"}},
		})
		if err != nil {
			t.Fatalf("CreateJob: %v", err)
		}
		runWorkerCloudJob(t, w, job.ID)

		status, params, results := deviceJobResults(t, owner, job.ID)
		if status != string(models.JobStatusCompleted) {
			t.Fatalf("device job status = %s, want completed", status)
		}
		batch, _ := params["discovery_job_id"].(string)
		if batch == "" {
			t.Fatal("the device job carries no discovery_job_id — ProcessJobResults would mint a second, empty discovery job")
		}

		// Honest counts: two rows reached the ingestion queue, and the job
		// list (assets_discovered reads processing.materialized) says so.
		processing, _ := results["processing"].(map[string]interface{})
		if processing == nil {
			t.Fatal("no processing block was written")
		}
		if processing["materialized"] != float64(2) || processing["discoveries_written"] != float64(2) || processing["fully_materialized"] != true {
			t.Errorf("processing = materialized %v, discoveries_written %v, fully %v; want 2 / 2 / true",
				processing["materialized"], processing["discoveries_written"], processing["fully_materialized"])
		}
		if processing["discovery_job_id"] != batch {
			t.Errorf("processing.discovery_job_id = %v, want the stamped %s", processing["discovery_job_id"], batch)
		}

		// The discovery job is a cloud job the run finished.
		var jobStatus, mode string
		if err := owner.QueryRow(`SELECT status, execution_mode FROM discovery_jobs WHERE id=$1`, batch).Scan(&jobStatus, &mode); err != nil {
			t.Fatalf("discovery job: %v", err)
		}
		if jobStatus != "completed" || mode != "cloud" {
			t.Errorf("discovery job = %s / %s, want completed / cloud", jobStatus, mode)
		}
		// And no second one: the processor reused it.
		var jobs int
		if err := owner.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id=$1 AND metadata->>'device_job_id'=$2`, tenant, job.ID.String()).Scan(&jobs); err != nil || jobs != 1 {
			t.Errorf("discovery jobs for this device job = %d (%v), want 1", jobs, err)
		}
		id, _ := uuid.Parse(batch)
		return id, cloudRowsInBatch(t, owner, tenant, batch)
	}

	firstBatch, rows := runOnce()
	if len(rows) != 2 {
		t.Fatalf("scheduled run wrote %d row(s), want the bucket and the database", len(rows))
	}
	for name, arn := range map[string]string{
		"example-audit-logs": "arn:aws:s3:::example-audit-logs",
		"orders-db":          "arn:aws:rds:us-east-1:123456789012:db:orders-db",
	} {
		r, ok := rows[name]
		if !ok {
			t.Fatalf("no row for %s", name)
		}
		raw, _ := r.Meta["raw_metadata"].(map[string]interface{})
		if raw["arn"] != arn {
			t.Errorf("%s: raw_metadata.arn = %v, want %s (the resource id enforce admission keys on)", name, raw["arn"], arn)
		}
		if r.Meta["at_rest"] != true || r.Protocol != "" || r.Port != 0 {
			t.Errorf("%s: at_rest=%v protocol=%q port=%d, want an at-rest row with no protocol and no port", name, r.Meta["at_rest"], r.Protocol, r.Port)
		}
		if r.Meta["discovery_method"] != "cloud_api" || r.Meta["cloud_provider"] != "aws" || r.Meta["cloud_region"] != "us-east-1" {
			t.Errorf("%s: discovery_method=%v cloud_provider=%v cloud_region=%v", name, r.Meta["discovery_method"], r.Meta["cloud_provider"], r.Meta["cloud_region"])
		}
		if r.Sensor != platformSensor {
			t.Errorf("%s: written under sensor %s, want the platform-managed one %s (inventory trusts no other)", name, r.Sensor, platformSensor)
		}
	}

	// Parity: the interactive handler's writer, handed the same devices,
	// writes the same rows.
	interactive := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	manualBatch := uuid.NewString()
	if _, err := interactive.WriteSensorDiscoveries(ctx, tenant, manualBatch, integration, "aws", []models.Device{bucket, database}); err != nil {
		t.Fatalf("interactive WriteSensorDiscoveries: %v", err)
	}
	manual := cloudRowsInBatch(t, owner, tenant, manualBatch)
	names := func(m map[string]scheduledCloudRow) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if !reflect.DeepEqual(names(manual), names(rows)) {
		t.Fatalf("interactive rows %v, scheduled rows %v", names(manual), names(rows))
	}
	for name, m := range manual {
		if !reflect.DeepEqual(m, rows[name]) {
			t.Errorf("%s: scheduled row differs from the interactive row\n scheduled:   %+v\n interactive: %+v", name, rows[name], m)
		}
	}

	// A second scheduled run is a new receipt carrying the same resource ids.
	secondBatch, again := runOnce()
	if secondBatch == firstBatch {
		t.Fatal("the second run reused the first run's discovery job")
	}
	for name, r := range rows {
		raw1, _ := r.Meta["raw_metadata"].(map[string]interface{})
		raw2, _ := again[name].Meta["raw_metadata"].(map[string]interface{})
		if raw2 == nil || raw1["arn"] != raw2["arn"] {
			t.Errorf("%s: second run carries resource id %v, first carried %v", name, raw2["arn"], raw1["arn"])
		}
	}

	// Hop 1 of the scheduled-cloud chain: these two runs' rows are what
	// discovery-processor (hop 2) and inventory under enforce admission
	// (hop 3) are tested against.
	dir := pipelinetest.Dir(t, vendorPipelineDir)
	handoff := pipelinetest.CloudHop1Handoff{
		Scenario: pipelinetest.CloudScheduledScenario,
		Runs: [][]pipelinetest.SensorDiscoveryRow{
			cloudHop1Rows(t, owner, tenant, firstBatch.String(), integration),
			cloudHop1Rows(t, owner, tenant, secondBatch.String(), integration),
		},
	}
	pipelinetest.CompareGolden(t, filepath.Join(dir, pipelinetest.CloudScheduledScenario, pipelinetest.Hop1HandoffFile), handoff)
}

// cloudHop1Rows reads one batch in the pipeline chain's row shape, sorted by
// hostname, with the run's integration id replaced by its placeholder.
func cloudHop1Rows(t *testing.T, owner *sql.DB, tenant uuid.UUID, batch string, integration uuid.UUID) []pipelinetest.SensorDiscoveryRow {
	t.Helper()
	rows, err := owner.Query(`SELECT COALESCE(protocol,''), host(dest_ip), port, confidence::text, hostname, host(source_ip), metadata
		FROM sensor_discoveries WHERE tenant_id=$1 AND batch_id=$2 ORDER BY hostname`, tenant, batch)
	if err != nil {
		t.Fatalf("read batch: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []pipelinetest.SensorDiscoveryRow
	for rows.Next() {
		var r pipelinetest.SensorDiscoveryRow
		var port sql.NullInt64
		var confidence string
		var raw []byte
		if err := rows.Scan(&r.Protocol, &r.DestIP, &port, &confidence, &r.Hostname, &r.SourceIP, &raw); err != nil {
			t.Fatalf("scan batch row: %v", err)
		}
		r.Port = port.Int64
		r.Confidence = json.Number(confidence)
		if err := json.Unmarshal(raw, &r.Metadata); err != nil {
			t.Fatalf("row metadata: %v", err)
		}
		out = append(out, r)
	}
	var normalized []pipelinetest.SensorDiscoveryRow
	walked := pipelinetest.Walk(pipelinetest.Canonical(t, out), pipelinetest.Replacer(integration.String(), pipelinetest.PlaceholderIntegrationID))
	if err := json.Unmarshal(pipelinetest.Marshal(t, walked), &normalized); err != nil {
		t.Fatalf("normalize batch: %v", err)
	}
	return normalized
}

// A configured-source refresh of an at-rest resource completes for a full and
// a partial run, and fails for a run whose collector failed. Before the fix a
// bucket could not be refreshed at all (boundedCloudResourceType mapped
// aws_s3_bucket to nothing), and when one could, a partial run wrote no
// processing block and the refresh read "running" forever.
func TestIntegration_ScheduledCloudRefresh_CompletesForFullPartialAndFailed(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)

	for _, tc := range []struct {
		name       string
		discoverer func(bucket models.Device) *fixedCloudDiscoverer
		wantRows   int
		want       string // the refresh's final state
	}{
		{"full", func(b models.Device) *fixedCloudDiscoverer {
			return &fixedCloudDiscoverer{provider: "aws", byType: map[string][]models.Device{"s3": {b}}}
		}, 1, "completed"},
		{"partial", func(b models.Device) *fixedCloudDiscoverer {
			// Answered in the resource's region, denied in another.
			return &fixedCloudDiscoverer{provider: "aws", byType: map[string][]models.Device{"s3": {b}}, failScope: map[string]string{"s3": "eu-west-1"}}
		}, 1, "completed"},
		{"failed", func(models.Device) *fixedCloudDiscoverer {
			return &fixedCloudDiscoverer{provider: "aws", byType: map[string][]models.Device{}, failTypes: map[string]error{"s3": errAccessDenied}}
		}, 0, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			tenant := testdb.NewTenant(t, owner)
			appDB := testdb.ConnectAsAppRole(t, owner)
			integration := uuid.New()
			if _, err := owner.Exec(`INSERT INTO platform_integrations(id,tenant_id,integration_name,integration_type,provider,config,is_active)
				VALUES($1,$2,'Refresh AWS','aws','cloud','{"region":"us-east-1"}',true)`, integration, tenant); err != nil {
				t.Fatal(err)
			}
			devices := NewDeviceServiceWithKey(owner, testMasterKey)
			bucket := s3Bucket("example-refresh-bucket")
			device, err := devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
				DeviceType: bucket.DeviceType, Hostname: bucket.Hostname, CredentialID: &integration,
				Metadata: map[string]interface{}{"region": "us-east-1", "arn": "arn:aws:s3:::example-refresh-bucket"},
			})
			if err != nil {
				t.Fatal(err)
			}
			// After the record exists: enforce admission would retain a
			// hand-created device instead of creating it.
			enableSourceRefresh(t, owner, tenant)
			refresh := NewConfiguredSourceRefresh(owner, NewJobQueueService(owner, owner, nil), devices, nil)
			req := refreshObservation(t, owner, tenant, "cloud:aws", &device.ID)
			status, err := refresh.Refresh(ctx, req)
			if err != nil || status.State != "queued" {
				t.Fatalf("an S3 bucket's refresh was not dispatched: %+v, %v", status, err)
			}
			var child uuid.UUID
			if err := owner.QueryRow(`SELECT device_job_id FROM identity_source_refreshes WHERE tenant_id=$1 AND id=$2`, tenant, req.RequestID).Scan(&child); err != nil {
				t.Fatal(err)
			}

			w := newScheduledCloudWorker(owner, appDB, tc.discoverer(bucket))
			runWorkerCloudJob(t, w, child)

			_, params, _ := deviceJobResults(t, owner, child)
			batch, _ := params["discovery_job_id"].(string)
			if got := len(cloudRowsInBatch(t, owner, tenant, batch)); got != tc.wantRows {
				t.Fatalf("refresh run wrote %d row(s), want %d", got, tc.wantRows)
			}

			status, err = refresh.Status(ctx, tenant, req.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "failed" {
				if status.State != "failed" {
					t.Fatalf("a refresh whose collector failed reads %+v, want failed", status)
				}
				return
			}
			// Rows still queued: the refresh waits for ingestion, not forever
			// for a processing block.
			if status.State != "running" || status.Reason != "waiting_for_result_ingestion" {
				t.Fatalf("before ingestion the refresh reads %+v, want running / waiting_for_result_ingestion", status)
			}
			// discovery-processor ingests the batch.
			if _, err := owner.Exec(`UPDATE sensor_discoveries SET processed_at=now() WHERE tenant_id=$1 AND batch_id=$2`, tenant, batch); err != nil {
				t.Fatal(err)
			}
			status, err = refresh.Status(ctx, tenant, req.RequestID)
			if err != nil || status.State != "completed" {
				t.Fatalf("after ingestion the refresh reads %+v (%v), want completed", status, err)
			}
		})
	}
}
