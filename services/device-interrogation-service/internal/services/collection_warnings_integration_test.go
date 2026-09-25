package services

// Collection warnings reach the stored job from BOTH executors (finding P-17).
//
// A device interrogation runs on whichever executor claims it — the in-cluster
// platform worker or a customer-hosted agent — and the job detail must say the
// same thing about the same device either way. These drive the real wiring on
// each side against one fake FortiGate whose API profile is refused
// `system/interface`, and compare what each stored:
//
//   - in-cluster: PlatformAgentWorker.executeDeviceInterrogation, then the same
//     UpdateJobStatus + ProcessJobResults sequence processNextJob runs;
//   - agent: the shared collector through the Registry (what the device-agent
//     executor runs), the payload round-tripped through JSON as it would be
//     POSTed, then AgentService.SubmitJobResult.
//
// MUTATION: drop `Warnings: report.Warnings` from the worker's JobResult, or
// the `Warnings:` line from ProcessJobResults' ProcessingLog, and the matching
// subtest fails.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newRestrictedFortiGate answers system/status and refuses system/interface
// with a 403, the way a FortiOS admin profile without network read access does.
// Every other endpoint answers an empty, successful list.
func newRestrictedFortiGate(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/cmdb/system/status"):
			_, _ = w.Write([]byte(`{"status":"success","serial":"FGT60F0000000001","version":"v7.4.4",
				"results":[{"hostname":"fw-branch-01","model_name":"FortiGate 60F","serial":"FGT60F0000000001","version":"v7.4.4"}]}`))
		case strings.HasSuffix(r.URL.Path, "/cmdb/system/interface"):
			w.WriteHeader(http.StatusForbidden)
			// The refusal body carries a PSK by name and a secret in free
			// text. Neither may reach the stored job (review B1 on).
			_, _ = w.Write([]byte(`{"http_status":403,"status":"error","error":-37,` +
				`"psksecret":"ENC ` + fortiBodyPSK + `","error_message":"denied for ` + fortiBodyFreeText + `"}`))
		default:
			_, _ = w.Write([]byte(`{"status":"success","results":[]}`))
		}
	}))
	t.Cleanup(srv.Close)
	devicetest.AllowListener(t, srv.Listener.Addr().String())
	return srv
}

// Secrets the restricted FortiGate plants in its refusal body.
const (
	fortiBodyPSK      = "FGPSKSECRET1"
	fortiBodyFreeText = "FGFREETEXT9"
)

// storedJob is the part of device_jobs.results these tests read.
type storedJob struct {
	Warnings   []di.CollectionWarning `json:"warnings"`
	Processing *struct {
		CollectionWarnings []di.CollectionWarning `json:"collection_warnings"`
		Errors             []any                  `json:"errors"`
	} `json:"processing"`
}

func TestIntegration_CollectionWarnings_BothExecutorsReachTheStoredJob(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	t.Setenv("ENCRYPTION_MASTER_KEY", testMasterKey)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srv := newRestrictedFortiGate(t)

	read := func(t *testing.T, jobID uuid.UUID) storedJob {
		t.Helper()
		var body []byte
		if err := owner.QueryRowContext(ctx, `SELECT results FROM device_jobs WHERE id = $1`, jobID).Scan(&body); err != nil {
			t.Fatalf("read job %s: %v", jobID, err)
		}
		var out storedJob
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode stored results %s: %v", body, err)
		}
		if out.Processing == nil {
			t.Fatalf("job %s has no processing block: %s", jobID, body)
		}
		return out
	}

	// The device the job interrogates, with embedded credentials as Discovery
	// → Devices creates it.
	deviceSvc := NewDeviceServiceWithKey(owner, testMasterKey)
	hostname := "fw-" + uuid.NewString()[:8] + ".corp.example.test"
	mgmt := srv.URL
	user, pass := "readonly", "readonly-password"
	dev, err := deviceSvc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType:    "fortigate",
		Hostname:      &hostname,
		ManagementURL: &mgmt,
		Username:      &user,
		Password:      &pass,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	jobQueue := NewJobQueueService(app, owner, nil)
	var inCluster, agent []di.CollectionWarning

	t.Run("in-cluster executor", func(t *testing.T) {
		created, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
			TenantID: tenant,
			JobType:  models.JobTypeDeviceInterrogation,
			AssetID:  &dev.ID,
		})
		if err != nil {
			t.Fatalf("CreateJob: %v", err)
		}
		job, err := jobQueue.GetJobByID(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetJobByID: %v", err)
		}

		worker := &PlatformAgentWorker{
			db:                  app,
			bypassDB:            owner,
			jobQueue:            jobQueue,
			deviceService:       NewDeviceServiceWithKey(app, testMasterKey),
			deviceInterrogation: NewDeviceInterrogationService(app, owner, testMasterKey),
			resultProcessor:     NewResultProcessor(app, owner),
		}
		result, err := worker.executeDeviceInterrogation(ctx, job)
		if err != nil {
			t.Fatalf("executeDeviceInterrogation: %v", err)
		}
		// What processNextJob does with a successful result.
		if err := jobQueue.UpdateJobStatus(ctx, job.ID, models.JobStatusCompleted, result, nil); err != nil {
			t.Fatalf("UpdateJobStatus: %v", err)
		}
		if !shouldProcessResults(result) {
			t.Fatal("the worker would not process this result; the processing block would never be written")
		}
		if err := worker.resultProcessor.ProcessJobResults(ctx, job.ID, result); err != nil {
			t.Fatalf("ProcessJobResults: %v", err)
		}

		inCluster = read(t, job.ID).Processing.CollectionWarnings
		assertRefusedInterfaceWarning(t, inCluster)
		assertNoBodySecrets(t, ctx, owner, job.ID)
	})

	t.Run("agent executor", func(t *testing.T) {
		agentID := insertDeviceAgent(t, owner, tenant)
		jobID := uuid.New()
		if _, err := owner.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
			VALUES ($1, $2, 'device_interrogation', $3, $4, 'in_progress')`, jobID, tenant, agentID, dev.ID); err != nil {
			t.Fatalf("seed agent job: %v", err)
		}

		// What the device-agent executor runs: the shared collector through the
		// Registry, with the credentials it decrypted locally.
		interrogator, err := di.NewRegistry().Get("fortigate")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		collected, err := interrogator.Interrogate(ctx,
			di.DeviceInfo{DeviceType: "fortigate", Hostname: hostname, ManagementURL: mgmt},
			di.Credentials{Username: user, Password: pass})
		if err != nil {
			t.Fatalf("Interrogate: %v", err)
		}

		// Over the wire as the agent POSTs it (the agent's JobResult JSON tags).
		posted, err := json.Marshal(map[string]any{
			"job_id":        jobID,
			"success":       true,
			"facts":         collected.Facts,
			"relationships": collected.Relationships,
			"warnings":      collected.Warnings,
			"metadata":      collected.DeviceInfo,
			"completed_at":  time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("marshal agent payload: %v", err)
		}
		var received models.JobResult
		if err := json.Unmarshal(posted, &received); err != nil {
			t.Fatalf("decode agent payload: %v", err)
		}
		if err := NewAgentService(app, owner, nil).SubmitJobResult(ctx, agentID, &received); err != nil {
			t.Fatalf("SubmitJobResult: %v", err)
		}

		agent = read(t, jobID).Processing.CollectionWarnings
		assertRefusedInterfaceWarning(t, agent)
		assertNoBodySecrets(t, ctx, owner, jobID)
	})

	// The two-executor rule: the same failure reads the same on both.
	if inCluster != nil && agent != nil && !reflect.DeepEqual(inCluster, agent) {
		t.Errorf("the executors stored different warnings for the same refusal:\n in-cluster: %+v\n agent:      %+v", inCluster, agent)
	}

	// An agent build that predates warnings sends no field. It still works,
	// and absent reads as none — not as an empty list, not as an error.
	t.Run("agent without a warnings field", func(t *testing.T) {
		agentID := insertDeviceAgent(t, owner, tenant)
		jobID := uuid.New()
		if _, err := owner.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
			VALUES ($1, $2, 'device_interrogation', $3, $4, 'in_progress')`, jobID, tenant, agentID, dev.ID); err != nil {
			t.Fatalf("seed agent job: %v", err)
		}
		legacy := `{"job_id":"` + jobID.String() + `","success":true,"completed_at":"2026-09-24T00:00:00Z",
			"facts":[{"key":"hw.model","value":"FortiGate 60F","confidence":1}]}`
		var received models.JobResult
		if err := json.Unmarshal([]byte(legacy), &received); err != nil {
			t.Fatalf("decode legacy payload: %v", err)
		}
		if err := NewAgentService(app, owner, nil).SubmitJobResult(ctx, agentID, &received); err != nil {
			t.Fatalf("SubmitJobResult: %v", err)
		}
		if got := read(t, jobID); got.Processing.CollectionWarnings != nil || got.Warnings != nil {
			t.Errorf("a payload with no warnings stored some: %+v", got)
		}
	})

	// An agent is not a boundary we own: what it sends is scrubbed on receipt,
	// BEFORE the payload is stored, not only on the way out.
	t.Run("agent warnings are re-sanitized on receipt", func(t *testing.T) {
		agentID := insertDeviceAgent(t, owner, tenant)
		jobID := uuid.New()
		if _, err := owner.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
			VALUES ($1, $2, 'device_interrogation', $3, $4, 'in_progress')`, jobID, tenant, agentID, dev.ID); err != nil {
			t.Fatalf("seed agent job: %v", err)
		}
		hostile := `{"job_id":"` + jobID.String() + `","success":true,"completed_at":"2026-09-24T00:00:00Z",
			"warnings":[{"collector":"paloalto","endpoint":"/api/?type=op&key=LUFRPT1-AGENT-LEAK","reason":"invented",
			  "effect":"ARP neighbours not collected",
			  "detail":"Get \"https://198.51.100.7/api/?type=op&key=LUFRPT1-AGENT-LEAK\": EOF"}]}`
		var received models.JobResult
		if err := json.Unmarshal([]byte(hostile), &received); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if err := NewAgentService(app, owner, nil).SubmitJobResult(ctx, agentID, &received); err != nil {
			t.Fatalf("SubmitJobResult: %v", err)
		}

		var body string
		if err := owner.QueryRowContext(ctx, `SELECT results::text FROM device_jobs WHERE id = $1`, jobID).Scan(&body); err != nil {
			t.Fatalf("read job: %v", err)
		}
		if strings.Contains(body, "LUFRPT1-AGENT-LEAK") {
			t.Fatalf("an agent-supplied API key was stored: %s", body)
		}
		got := read(t, jobID).Processing.CollectionWarnings
		if len(got) != 1 || got[0].Reason != di.WarningError || got[0].Endpoint != "/api/" {
			t.Errorf("the warning was not normalised on receipt (reason folded, query stripped): %+v", got)
		}
	})
}

// assertRefusedInterfaceWarning checks the one warning the restricted
// FortiGate must produce.
func assertRefusedInterfaceWarning(t *testing.T, got []di.CollectionWarning) {
	t.Helper()
	for _, w := range got {
		if w.Endpoint == "/api/v2/cmdb/system/interface" {
			if w.Collector != "fortinet" || w.Reason != di.WarningPermissionDenied || w.Effect == "" {
				t.Errorf("the refused endpoint's warning is wrong: %+v", w)
			}
			return
		}
	}
	t.Errorf("the refused system/interface endpoint left no warning on the stored job: %+v", got)
}

// assertNoBodySecrets fails if anything the device put in its error body was
// stored anywhere on the job row, and checks the vendor code that is the
// diagnosis survived.
func assertNoBodySecrets(t *testing.T, ctx context.Context, db *sql.DB, jobID uuid.UUID) {
	t.Helper()
	var row string
	if err := db.QueryRowContext(ctx, `SELECT row_to_json(j)::text FROM device_jobs j WHERE id = $1`, jobID).Scan(&row); err != nil {
		t.Fatalf("read job row: %v", err)
	}
	for _, secret := range []string{fortiBodyPSK, fortiBodyFreeText} {
		if strings.Contains(row, secret) {
			t.Errorf("%q from the device's error body was stored on job %s", secret, jobID)
		}
	}
	if !strings.Contains(row, "FortiOS error -37") {
		t.Errorf("the FortiOS error code did not survive into the stored warning: %s", row)
	}
}
