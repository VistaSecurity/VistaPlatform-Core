package api

// Contract test for the onboarding read surface (status / workflow / progress) —
// the first-run onboarding wizard + banner. Extends the auth-service spec-first
// contract (ADR-0001) and reuses the shared harness (loadSpec / assertConforms /
// do / aTenantID / aUserID) from cross_cutter_contract_test.go.
//
// GetOnboardingStatus / GetOnboardingWorkflow / GetOnboardingProgress (and the
// calculateProgress helper) were refactored onto the onboardingStore interface
// via *WithStore variants, so these tests drive the real handlers with an
// in-memory stub — no database. The write handlers (complete/skip) are a separate
// slice.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type stubOnboardingStore struct {
	completedAt    sql.NullTime
	completedErr   error
	settingsConfig []byte
	settingsErr    error
	workflowID     uuid.UUID
	workflowName   string
	stepsJSON      []byte
	workflowErr    error
	progCompleted  []byte
	progSkipped    []byte
	progErr        error
	stepTimestamp  sql.NullTime
	stepData       []byte
	stepErr        error
	// writes
	upsertCompletedErr error
	upsertSkippedErr   error
	markCompleteErr    error
	dismissedAt        sql.NullTime
	dismissedErr       error
	dismissForUserErr  error
	setTenantReqErr    error
	// auto-completion evidence (reconcileAutoSteps); evidenceErr short-circuits
	// detection so the stored manual state is used as-is.
	evidenceSegments  bool
	evidenceLocations bool
	evidenceAgents    bool
	evidenceErr       error
	// call tracking for the reconcile behavior test
	upsertCompletedIDs []string
	markCompleteCalled bool
}

func (s *stubOnboardingStore) GetUserOnboardingCompletedAt(_ context.Context, _ uuid.UUID) (sql.NullTime, error) {
	return s.completedAt, s.completedErr
}
func (s *stubOnboardingStore) GetTenantAdminSettingsConfig(_ context.Context, _ uuid.UUID) ([]byte, error) {
	return s.settingsConfig, s.settingsErr
}
func (s *stubOnboardingStore) GetOnboardingWorkflowConfig(_ context.Context, _ uuid.UUID) (uuid.UUID, string, []byte, error) {
	return s.workflowID, s.workflowName, s.stepsJSON, s.workflowErr
}
func (s *stubOnboardingStore) GetUserWorkflowProgress(_ context.Context, _, _ uuid.UUID) ([]byte, []byte, error) {
	return s.progCompleted, s.progSkipped, s.progErr
}
func (s *stubOnboardingStore) GetStepTimestamp(_ context.Context, _, _ uuid.UUID, _ string) (sql.NullTime, []byte, error) {
	return s.stepTimestamp, s.stepData, s.stepErr
}
func (s *stubOnboardingStore) UpsertCompletedStep(_ context.Context, _, _ uuid.UUID, stepID string, _ []byte) error {
	if s.upsertCompletedErr == nil {
		s.upsertCompletedIDs = append(s.upsertCompletedIDs, stepID)
	}
	return s.upsertCompletedErr
}
func (s *stubOnboardingStore) UpsertSkippedStep(_ context.Context, _, _ uuid.UUID, _ string) error {
	return s.upsertSkippedErr
}
func (s *stubOnboardingStore) MarkOnboardingComplete(_ context.Context, _ uuid.UUID) error {
	if s.markCompleteErr == nil {
		s.markCompleteCalled = true
	}
	return s.markCompleteErr
}
func (s *stubOnboardingStore) GetUserOnboardingDismissedAt(_ context.Context, _ uuid.UUID) (sql.NullTime, error) {
	return s.dismissedAt, s.dismissedErr
}
func (s *stubOnboardingStore) DismissOnboardingForUser(_ context.Context, _ uuid.UUID) error {
	return s.dismissForUserErr
}
func (s *stubOnboardingStore) SetTenantOnboardingRequired(_ context.Context, _, _ uuid.UUID, _ bool) error {
	return s.setTenantReqErr
}
func (s *stubOnboardingStore) TenantOnboardingEvidence(_ context.Context, _ uuid.UUID) (bool, bool, bool, error) {
	return s.evidenceSegments, s.evidenceLocations, s.evidenceAgents, s.evidenceErr
}

func newOnboardingEngine(store onboardingStore, authenticated bool, tenantID, userID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if store == nil {
		store = &stubOnboardingStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", tenantID)
			c.Set("userID", userID)
		}
		c.Next()
	})
	grp.GET("/onboarding/status", GetOnboardingStatusWithStore(store))
	grp.GET("/onboarding/workflow", GetOnboardingWorkflowWithStore(store))
	grp.GET("/onboarding/progress", GetOnboardingProgressWithStore(store))
	grp.POST("/onboarding/steps/:id/complete", CompleteOnboardingStepWithStore(store))
	grp.POST("/onboarding/steps/:id/skip", SkipOnboardingStepWithStore(store))
	grp.POST("/onboarding/dismiss", DismissOnboardingWithStore(store))
	grp.PUT("/onboarding/settings", UpdateOnboardingSettingsWithStore(store))
	return r
}

// sampleWorkflowStore returns a store populated for a healthy workflow/progress
// response: a 2-step workflow with one completed step (with a timestamp).
func sampleWorkflowStore() *stubOnboardingStore {
	return &stubOnboardingStore{
		workflowID:    uuid.New(),
		workflowName:  "Get started",
		stepsJSON:     []byte(`[{"id":"s1","title":"Welcome","description":"Intro","required":true},{"id":"s2","title":"Invite team","description":"Add users","required":false}]`),
		progCompleted: []byte(`["s1"]`),
		progSkipped:   []byte(`[]`),
		stepTimestamp: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
}

// --- GET /onboarding/status -------------------------------------------------

func TestContract_GetOnboardingStatus_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubOnboardingStore{
		completedAt:    sql.NullTime{Valid: false},
		settingsConfig: []byte(`{"onboarding_required":true}`),
	}
	eng := newOnboardingEngine(store, true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "OnboardingStatusResponse", w.Body.Bytes())
}

func TestContract_GetOnboardingStatus_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, false, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/status", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetOnboardingStatus_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{completedErr: errors.New("db down")}, true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/status", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetOnboardingStatus_Dismissed(t *testing.T) {
	sv := loadSpec(t)
	store := &stubOnboardingStore{
		completedAt:    sql.NullTime{Valid: false},
		settingsConfig: []byte(`{"onboarding_required":true}`),
		dismissedAt:    sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	eng := newOnboardingEngine(store, true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "OnboardingStatusResponse", w.Body.Bytes())
	// Dismissed => banner suppressed even though required && !completed.
	if !strings.Contains(w.Body.String(), `"dismissed":true`) || !strings.Contains(w.Body.String(), `"show_banner":false`) {
		t.Fatalf("expected dismissed=true and show_banner=false; body=%s", w.Body.String())
	}
}

// --- POST /onboarding/dismiss -----------------------------------------------

func TestContract_DismissOnboarding_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/dismiss", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "OnboardingDismissResponse", w.Body.Bytes())
}

func TestContract_DismissOnboarding_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, false, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/dismiss", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- PUT /onboarding/settings -----------------------------------------------

func TestContract_UpdateOnboardingSettings_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, true, aTenantID, aUserID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/onboarding/settings", strings.NewReader(`{"enabled":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "OnboardingSettingsResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("expected enabled=false echoed; body=%s", w.Body.String())
	}
}

func TestContract_UpdateOnboardingSettings_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, true, aTenantID, aUserID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/onboarding/settings", strings.NewReader(`not-json`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- GET /onboarding/workflow -----------------------------------------------

func TestContract_GetOnboardingWorkflow_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(sampleWorkflowStore(), true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/workflow", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "OnboardingWorkflowResponse", w.Body.Bytes())
}

func TestContract_GetOnboardingWorkflow_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, false, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/workflow", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetOnboardingWorkflow_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{workflowErr: sql.ErrNoRows}, true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/workflow", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetOnboardingWorkflow_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{workflowErr: errors.New("db down")}, true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/workflow", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- GET /onboarding/progress -----------------------------------------------

func TestContract_GetOnboardingProgress_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(sampleWorkflowStore(), true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/progress", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "OnboardingProgress", w.Body.Bytes())
}

func TestContract_GetOnboardingProgress_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, false, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/progress", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetOnboardingProgress_404(t *testing.T) {
	sv := loadSpec(t)
	// User fetch ok, workflow missing -> 404.
	eng := newOnboardingEngine(&stubOnboardingStore{workflowErr: sql.ErrNoRows}, true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/progress", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetOnboardingProgress_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{completedErr: errors.New("db down")}, true, aTenantID, aUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/onboarding/progress", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /onboarding/steps/{id}/complete -----------------------------------

// completeStore is a workflow with one required step "s1", no prior progress.
func completeStore() *stubOnboardingStore {
	return &stubOnboardingStore{
		workflowID:    uuid.New(),
		stepsJSON:     []byte(`[{"id":"s1","title":"Welcome","description":"d","required":true}]`),
		progCompleted: []byte(`[]`),
		progSkipped:   []byte(`[]`),
	}
}

func TestContract_CompleteOnboardingStep_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(completeStore(), true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s1/complete", strings.NewReader(`{"data":{"k":"v"}}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StepResponse", w.Body.Bytes())
}

func TestContract_CompleteOnboardingStep_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, false, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s1/complete", strings.NewReader(`{}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CompleteOnboardingStep_404_workflow(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{workflowErr: sql.ErrNoRows}, true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s1/complete", strings.NewReader(`{}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Step id not present in the workflow -> 404.
func TestContract_CompleteOnboardingStep_404_step(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(completeStore(), true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/nope/complete", strings.NewReader(`{}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Step already completed -> 400.
func TestContract_CompleteOnboardingStep_400_already(t *testing.T) {
	sv := loadSpec(t)
	store := completeStore()
	store.progCompleted = []byte(`["s1"]`)
	eng := newOnboardingEngine(store, true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s1/complete", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CompleteOnboardingStep_500(t *testing.T) {
	sv := loadSpec(t)
	store := completeStore()
	store.upsertCompletedErr = errors.New("db down")
	eng := newOnboardingEngine(store, true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s1/complete", strings.NewReader(`{}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /onboarding/steps/{id}/skip ---------------------------------------

// skipStore has a non-required step "s2", no prior progress.
func skipStore() *stubOnboardingStore {
	return &stubOnboardingStore{
		workflowID:    uuid.New(),
		stepsJSON:     []byte(`[{"id":"s1","title":"One","description":"d","required":true},{"id":"s2","title":"Two","description":"d","required":false}]`),
		progCompleted: []byte(`[]`),
		progSkipped:   []byte(`[]`),
	}
}

func TestContract_SkipOnboardingStep_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(skipStore(), true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s2/skip", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SkipStepResponse", w.Body.Bytes())
}

func TestContract_SkipOnboardingStep_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{}, false, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s2/skip", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_SkipOnboardingStep_404_workflow(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(&stubOnboardingStore{workflowErr: sql.ErrNoRows}, true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s2/skip", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Skipping a required step -> 400.
func TestContract_SkipOnboardingStep_400_required(t *testing.T) {
	sv := loadSpec(t)
	eng := newOnboardingEngine(skipStore(), true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s1/skip", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_SkipOnboardingStep_500(t *testing.T) {
	sv := loadSpec(t)
	store := skipStore()
	store.upsertSkippedErr = errors.New("db down")
	eng := newOnboardingEngine(store, true, aTenantID, aUserID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/onboarding/steps/s2/skip", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
