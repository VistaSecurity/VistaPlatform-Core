package handlers

// Contract test for the interrogation-jobs HTTP surface.
//
// First slice for device-interrogation-service. Its job handlers used to query
// *sql.DB inline; this slice landed a behaviour-preserving refactor first (the
// SQL moved verbatim into jobRepository behind the jobStore interface), so the
// real gin handlers can now be exercised over httptest with an in-memory stub —
// no database — and their response bodies asserted against
// api/openapi/device-interrogation-service.openapi.yaml.
//
// OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so we validate response bodies
// directly with santhosh-tekuri/jsonschema/v6 — same approach as the other
// contract tests.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const specBaseURI = "https://vistaplatform.local/device-interrogation-service.openapi.yaml"

// --- spec loading + response validation -----------------------------------

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// handlers -> internal -> device-interrogation-service -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "device-interrogation-service.openapi.yaml",
	)
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec %s: %v", specPath, err)
	}
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatalf("yaml unmarshal spec: %v", err)
	}
	jsonBytes, err := json.Marshal(asAny)
	if err != nil {
		t.Fatalf("re-marshal spec to json: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatalf("jsonschema unmarshal spec: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(specBaseURI, doc); err != nil {
		t.Fatalf("add spec resource: %v", err)
	}
	return &specValidator{compiler: c}
}

func (sv *specValidator) assertConforms(t *testing.T, schemaName string, body []byte) {
	t.Helper()
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/" + schemaName)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaName, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unmarshal response body: %v\nbody: %s", err, string(body))
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("response violates schema %q:\n%v\n--- body ---\n%s", schemaName, err, string(body))
	}
}

// --- in-memory stub jobStore -----------------------------------------------

type stubJobStore struct {
	list        []InterrogationJob
	total       int
	listErr     error
	job         *InterrogationJob
	jobErr      error
	stats       JobStats
	statsErr    error
	active      []InterrogationJob
	activeErr   error
	resultFound bool
	resultErr   error
	mutStatus   string // status returned by GetJobStatus (retry/cancel gating)
	mutFound    bool
	adminList   []AdminInterrogationJob
	adminTotal  int
	adminErr    error
	adminFilter JobListFilters // captures the filter passed to ListAdminJobs
}

func (s *stubJobStore) ListJobs(context.Context, uuid.UUID, JobListFilters) ([]InterrogationJob, int, error) {
	return s.list, s.total, s.listErr
}
func (s *stubJobStore) ListAdminJobs(_ context.Context, f JobListFilters) ([]AdminInterrogationJob, int, error) {
	s.adminFilter = f
	return s.adminList, s.adminTotal, s.adminErr
}
func (s *stubJobStore) GetJob(context.Context, uuid.UUID, uuid.UUID) (*InterrogationJob, error) {
	return s.job, s.jobErr
}
func (s *stubJobStore) GetJobStats(context.Context, uuid.UUID) (JobStats, error) {
	return s.stats, s.statsErr
}
func (s *stubJobStore) GetActiveJobs(context.Context, uuid.UUID) ([]InterrogationJob, error) {
	return s.active, s.activeErr
}
func (s *stubJobStore) GetJobResultStatus(context.Context, uuid.UUID, uuid.UUID) (string, bool, error) {
	return "completed", s.resultFound, s.resultErr
}
func (s *stubJobStore) GetJobStatus(context.Context, uuid.UUID, uuid.UUID) (string, bool, error) {
	return s.mutStatus, s.mutFound, nil
}
func (s *stubJobStore) GetJobStatusAdmin(context.Context, uuid.UUID) (string, uuid.UUID, bool, error) {
	return s.mutStatus, uuid.Nil, s.mutFound, nil
}
func (s *stubJobStore) ResetJobToPending(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (s *stubJobStore) CancelJobByID(context.Context, uuid.UUID, uuid.UUID) error     { return nil }

// --- test harness ----------------------------------------------------------

func newJobEngine(store *stubJobStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/device-interrogation-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	h := &JobHandlers{store: store}
	grp.GET("/jobs", h.ListJobs)
	grp.GET("/jobs/stats", h.GetJobStats)
	grp.GET("/jobs/active", h.GetActiveJobs)
	grp.GET("/jobs/:id", h.GetJob)
	grp.GET("/jobs/:id/results", h.GetJobResults)
	grp.POST("/jobs/:id/retry", h.RetryJob)
	grp.POST("/jobs/:id/cancel", h.CancelJob)
	// Platform-admin (Support cockpit) cross-tenant retry/cancel. In production these
	// are gated by RequirePlatformAdmin in router.go; here we exercise the handlers.
	grp.GET("/admin/jobs", h.ListAdminJobs)
	grp.POST("/admin/jobs/:id/retry", h.RetryJobAdmin)
	grp.POST("/admin/jobs/:id/cancel", h.CancelJobAdmin)
	return r
}

func do(engine *gin.Engine, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func strPtr(s string) *string { return &s }

func sampleJob() InterrogationJob {
	now := time.Now().UTC()
	did := uuid.New()
	started := now.Add(-10 * time.Minute)
	dur := 600
	assets := 12
	return InterrogationJob{
		ID:               uuid.New(),
		TenantID:         uuid.New(),
		JobType:          "device_interrogation",
		Status:           "completed",
		DeviceID:         &did,
		DeviceName:       strPtr("fw-01"),
		DeviceType:       strPtr("palo_alto"),
		StartedAt:        &started,
		CompletedAt:      &now,
		DurationSeconds:  &dur,
		AssetsDiscovered: &assets,
		CreatedAt:        started,
		UpdatedAt:        now,
	}
}

// minimalJob leaves all omitempty fields unset (absent, not null).
func minimalJob() InterrogationJob {
	now := time.Now().UTC()
	return InterrogationJob{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		JobType:   "cloud_discovery",
		Status:    "pending",
		CreatedAt: now,
		UpdatedAt: now,
	}
}

const aUUID = "11111111-1111-1111-1111-111111111111"
const base = "/api/v1/device-interrogation-service"

// --- the contract tests ----------------------------------------------------

func TestContract_ListJobs_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{list: []InterrogationJob{sampleJob(), minimalJob()}, total: 2})
	w := do(eng, http.MethodGet, base+"/jobs?page=1&page_size=20", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "JobListResponse", w.Body.Bytes())
}

func TestContract_GetJobStats_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{stats: JobStats{
		Total: 10, Pending: 2, InProgress: 1, Completed: 6, Failed: 1,
		Last24h: Last24hStats{Completed: 3, Failed: 1},
	}})
	w := do(eng, http.MethodGet, base+"/jobs/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "JobStatsResponse", w.Body.Bytes())
}

func TestContract_GetActiveJobs_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{active: []InterrogationJob{minimalJob()}})
	w := do(eng, http.MethodGet, base+"/jobs/active", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActiveJobsResponse", w.Body.Bytes())
}

func TestContract_GetJob_200(t *testing.T) {
	sv := loadSpec(t)
	j := sampleJob()
	eng := newJobEngine(&stubJobStore{job: &j})
	w := do(eng, http.MethodGet, base+"/jobs/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "JobResponse", w.Body.Bytes())
}

func TestContract_GetJob_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{})
	w := do(eng, http.MethodGet, base+"/jobs/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A nil job (no error) maps to 404.
func TestContract_GetJob_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{job: nil})
	w := do(eng, http.MethodGet, base+"/jobs/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetJobResults_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{resultFound: true})
	w := do(eng, http.MethodGet, base+"/jobs/"+aUUID+"/results", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "JobResultsResponse", w.Body.Bytes())
}

func TestContract_RetryJob_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{mutStatus: "failed", mutFound: true})
	w := do(eng, http.MethodPost, base+"/jobs/"+aUUID+"/retry", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetryJobResponse", w.Body.Bytes())
}

// A non-failed/cancelled job cannot be retried → 400.
func TestContract_RetryJob_400_wrongState(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{mutStatus: "completed", mutFound: true})
	w := do(eng, http.MethodPost, base+"/jobs/"+aUUID+"/retry", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RetryJob_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{mutFound: false})
	w := do(eng, http.MethodPost, base+"/jobs/"+aUUID+"/retry", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CancelJob_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{mutStatus: "in_progress", mutFound: true})
	w := do(eng, http.MethodPost, base+"/jobs/"+aUUID+"/cancel", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// Platform-admin (Support cockpit) cross-tenant retry/cancel — same response shapes
// and state gating as the tenant endpoints, but reached via /admin/jobs/{id}/*.
func TestContract_RetryJobAdmin_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{mutStatus: "failed", mutFound: true})
	w := do(eng, http.MethodPost, base+"/admin/jobs/"+aUUID+"/retry", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetryJobResponse", w.Body.Bytes())
}

func TestContract_RetryJobAdmin_400_wrongState(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{mutStatus: "completed", mutFound: true})
	w := do(eng, http.MethodPost, base+"/admin/jobs/"+aUUID+"/retry", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RetryJobAdmin_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{mutFound: false})
	w := do(eng, http.MethodPost, base+"/admin/jobs/"+aUUID+"/retry", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CancelJobAdmin_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newJobEngine(&stubJobStore{mutStatus: "in_progress", mutFound: true})
	w := do(eng, http.MethodPost, base+"/admin/jobs/"+aUUID+"/cancel", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_Job_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/InterrogationJob")
	if err != nil {
		t.Fatalf("compile InterrogationJob: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted InterrogationJob, but it passed — the guardrail is not actually checking")
	}
}

// --- server-side tenant scope ---------------------------------------

// A tenant_id query param on the cross-tenant admin list must flow through to the
// store filter, so the narrowing happens in SQL (server-side) — not by shipping
// every tenant's rows to the client and filtering in the browser.
func TestListAdminJobs_TenantScopeFilter(t *testing.T) {
	store := &stubJobStore{adminList: []AdminInterrogationJob{}, adminTotal: 0}
	eng := newJobEngine(store)

	w := do(eng, http.MethodGet, base+"/admin/jobs?tenant_id="+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if store.adminFilter.TenantID != aUUID {
		t.Fatalf("expected store filter TenantID=%q, got %q", aUUID, store.adminFilter.TenantID)
	}

	// Omitting tenant_id leaves the roll-up cross-tenant (empty filter).
	store2 := &stubJobStore{}
	eng2 := newJobEngine(store2)
	if w := do(eng2, http.MethodGet, base+"/admin/jobs", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unscoped list, got %d", w.Code)
	}
	if store2.adminFilter.TenantID != "" {
		t.Fatalf("expected empty TenantID for unscoped list, got %q", store2.adminFilter.TenantID)
	}
}

// A malformed tenant_id is rejected with 400 rather than reaching the store (and
// surfacing as a 500 from the uuid-typed column).
func TestListAdminJobs_InvalidTenantID(t *testing.T) {
	store := &stubJobStore{}
	eng := newJobEngine(store)

	w := do(eng, http.MethodGet, base+"/admin/jobs?tenant_id=not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed tenant_id, got %d", w.Code)
	}
}
