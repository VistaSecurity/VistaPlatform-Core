package handlers

// Collection warnings, from the write path to the job detail (finding P-17).
//
// The services package proves both executors store the same warnings in the
// processing block (TestIntegration_CollectionWarnings_BothExecutorsReachTheStoredJob).
// This is the other half: a result submitted through the REAL agent intake is
// served by the REAL GET /jobs/:id/results handler over the REAL repository,
// typed, with the warning intact. It lives here because the repository and the
// projection are unexported to the services package.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_JobResults_ServesTheStoredCollectionWarnings(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	agentID := seedIntakeAgent(t, owner, tenant)
	assetID := uuid.New()
	if _, err := owner.ExecContext(ctx, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status)
		VALUES ($1, $2, 'fw-warnings.corp.example.test', 'network_device', 'hardware.network_device', 'monitoring')`,
		assetID, tenant); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	jobID := uuid.New()
	if _, err := owner.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
		VALUES ($1, $2, 'device_interrogation', $3, $4, 'in_progress')`, jobID, tenant, agentID, assetID); err != nil {
		t.Fatalf("seed job: %v", err)
	}

	// The payload as an agent POSTs it: the refusal a read-only FortiOS profile
	// produces, and nothing else collected.
	posted := `{"job_id":"` + jobID.String() + `","success":true,"completed_at":"2026-09-24T00:00:00Z",
		"warnings":[{"collector":"fortinet","endpoint":"/api/v2/cmdb/system/interface","reason":"permission_denied",
		  "effect":"Configured interfaces and VLANs not collected","detail":"API returned status 403"}]}`
	var result models.JobResult
	if err := json.Unmarshal([]byte(posted), &result); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if err := services.NewAgentService(app, owner, nil).SubmitJobResult(ctx, agentID, &result); err != nil {
		t.Fatalf("SubmitJobResult: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
	h := NewJobHandlers(app, owner)
	r.GET("/jobs/:id/results", h.GetJobResults)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/jobs/"+jobID.String()+"/results", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET results = %d: %s", w.Code, w.Body.String())
	}
	var got JobResultsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.CollectionWarningsUnreadable {
		t.Fatal("the stored warnings were reported unreadable")
	}
	if len(got.CollectionWarnings) != 1 {
		t.Fatalf("job detail served %d collection warnings, want 1: %s", len(got.CollectionWarnings), w.Body.String())
	}
	want := JobResultCollectionWarning{
		Collector: "fortinet",
		Endpoint:  "/api/v2/cmdb/system/interface",
		Reason:    "permission_denied",
		Effect:    "Configured interfaces and VLANs not collected",
		Detail:    "API returned status 403",
	}
	if got.CollectionWarnings[0] != want {
		t.Errorf("served warning = %+v, want %+v", got.CollectionWarnings[0], want)
	}
}
