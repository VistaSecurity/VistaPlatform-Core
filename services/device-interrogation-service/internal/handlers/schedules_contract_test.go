package handlers

// Contract test for the schedules full-CRUD surface. Extends the
// device-interrogation-service spec-first contract (ADR-0001) and reuses the
// shared harness (loadSpec / assertConforms / do / strPtr / aUUID / base /
// deviceTestTenant) from the jobs + devices contract tests — only the schedule
// stub + engine + cases live here.
//
// ScheduleHandlers was made testable by depending on the scheduleStore
// interface for its schedulerService field (the concrete
// *services.SchedulerService still satisfies it), so these tests drive the real
// handlers with an in-memory stub — no database.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
)

// --- stub scheduleStore ----------------------------------------------------

type stubScheduleStore struct {
	list      []*services.InterrogationSchedule
	listErr   error
	getResult *services.InterrogationSchedule
	getErr    error
	created   *services.InterrogationSchedule
	updated   *services.InterrogationSchedule
	job       *models.DeviceJob
	history   []*services.ScheduleHistory
}

func (s *stubScheduleStore) CreateSchedule(context.Context, uuid.UUID, services.CreateScheduleRequest) (*services.InterrogationSchedule, error) {
	return s.created, nil
}
func (s *stubScheduleStore) GetSchedule(context.Context, uuid.UUID, uuid.UUID) (*services.InterrogationSchedule, error) {
	return s.getResult, s.getErr
}
func (s *stubScheduleStore) ListSchedules(context.Context, uuid.UUID) ([]*services.InterrogationSchedule, error) {
	return s.list, s.listErr
}
func (s *stubScheduleStore) UpdateSchedule(context.Context, uuid.UUID, uuid.UUID, services.UpdateScheduleRequest) (*services.InterrogationSchedule, error) {
	return s.updated, nil
}
func (s *stubScheduleStore) DeleteSchedule(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (s *stubScheduleStore) TriggerSchedule(context.Context, uuid.UUID, uuid.UUID) (*models.DeviceJob, error) {
	return s.job, nil
}
func (s *stubScheduleStore) GetScheduleHistory(context.Context, uuid.UUID, uuid.UUID, int) ([]*services.ScheduleHistory, error) {
	return s.history, nil
}

func newScheduleEngine(store *stubScheduleStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/device-interrogation-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", deviceTestTenant)
		c.Next()
	})
	h := &ScheduleHandlers{schedulerService: store}
	grp.GET("/schedules", h.ListSchedules)
	grp.POST("/schedules", h.CreateSchedule)
	grp.GET("/schedules/:id", h.GetSchedule)
	grp.PUT("/schedules/:id", h.UpdateSchedule)
	grp.DELETE("/schedules/:id", h.DeleteSchedule)
	grp.POST("/schedules/:id/trigger", h.TriggerSchedule)
	grp.POST("/schedules/:id/enable", h.EnableSchedule)
	grp.POST("/schedules/:id/disable", h.DisableSchedule)
	grp.GET("/schedules/:id/history", h.GetScheduleHistory)
	return r
}

func sampleSchedule() *services.InterrogationSchedule {
	now := time.Now().UTC()
	return &services.InterrogationSchedule{
		ID:             uuid.New(),
		TenantID:       deviceTestTenant,
		Name:           "nightly F5 sweep",
		Description:    "Interrogate all F5 devices nightly",
		CronExpression: "0 2 * * *",
		TargetType:     "device",
		TargetID:       uuid.New(),
		IsEnabled:      true,
		SuccessCount:   12,
		FailureCount:   1,
		Parameters:     map[string]interface{}{"deep": true},
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func sampleHistory() *services.ScheduleHistory {
	now := time.Now().UTC()
	return &services.ScheduleHistory{
		ID:          uuid.New(),
		ScheduleID:  uuid.New(),
		JobID:       uuid.New(),
		Status:      "success",
		StartedAt:   now.Add(-time.Hour),
		CompletedAt: &now,
		AssetsFound: 7,
	}
}

const validScheduleBody = `{"name":"s","cron_expression":"0 2 * * *","target_type":"device","target_id":"` + aUUID + `"}`

// --- the contract tests ----------------------------------------------------

func TestContract_ListSchedules_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{list: []*services.InterrogationSchedule{sampleSchedule()}})
	w := do(eng, http.MethodGet, base+"/schedules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ScheduleListResponse", w.Body.Bytes())
}

func TestContract_CreateSchedule_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{created: sampleSchedule()})
	w := do(eng, http.MethodPost, base+"/schedules", strings.NewReader(validScheduleBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterrogationSchedule", w.Body.Bytes())
}

func TestContract_CreateSchedule_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{})
	// Missing required cron_expression / target_type / target_id.
	w := do(eng, http.MethodPost, base+"/schedules", strings.NewReader(`{"name":"s"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetSchedule_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{getResult: sampleSchedule()})
	w := do(eng, http.MethodGet, base+"/schedules/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterrogationSchedule", w.Body.Bytes())
}

func TestContract_GetSchedule_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{})
	w := do(eng, http.MethodGet, base+"/schedules/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetSchedule_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{getErr: context.DeadlineExceeded})
	w := do(eng, http.MethodGet, base+"/schedules/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateSchedule_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{getResult: sampleSchedule(), updated: sampleSchedule()})
	w := do(eng, http.MethodPut, base+"/schedules/"+aUUID, strings.NewReader(`{"name":"renamed"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterrogationSchedule", w.Body.Bytes())
}

func TestContract_DeleteSchedule_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{getResult: sampleSchedule()})
	w := do(eng, http.MethodDelete, base+"/schedules/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_TriggerSchedule_202(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{getResult: sampleSchedule(), job: &models.DeviceJob{ID: uuid.New()}})
	w := do(eng, http.MethodPost, base+"/schedules/"+aUUID+"/trigger", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TriggerScheduleResponse", w.Body.Bytes())
}

func TestContract_EnableSchedule_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{getResult: sampleSchedule(), updated: sampleSchedule()})
	w := do(eng, http.MethodPost, base+"/schedules/"+aUUID+"/enable", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterrogationSchedule", w.Body.Bytes())
}

func TestContract_DisableSchedule_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{getResult: sampleSchedule(), updated: sampleSchedule()})
	w := do(eng, http.MethodPost, base+"/schedules/"+aUUID+"/disable", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "InterrogationSchedule", w.Body.Bytes())
}

func TestContract_GetScheduleHistory_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newScheduleEngine(&stubScheduleStore{getResult: sampleSchedule(), history: []*services.ScheduleHistory{sampleHistory()}})
	w := do(eng, http.MethodGet, base+"/schedules/"+aUUID+"/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ScheduleHistoryResponse", w.Body.Bytes())
}

func TestContract_Schedule_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/InterrogationSchedule")
	if err != nil {
		t.Fatalf("compile InterrogationSchedule: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted InterrogationSchedule, but it passed — the guardrail is not actually checking")
	}
}
