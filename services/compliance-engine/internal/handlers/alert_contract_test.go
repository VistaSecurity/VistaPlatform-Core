package handlers

// Contract test for the compliance-engine stateful-alert HTTP surface —
// the tenant-facing reads + lifecycle mutations (/alerts*) and the platform-track
// read (/admin/alerts) the admin-ui-v2 System Health → Alerts panel consumes.
//
// Same pattern as ticket_contract_test.go: exercise the REAL gin handlers over
// httptest driven by an in-memory stub satisfying `alertEngine` (no database /
// NATS), asserting every response body conforms to the schema in
// api/openapi/compliance-engine.openapi.yaml. Shares loadSpec / assertConforms /
// do with framework_contract_test, and reuses sampleTicket() from
// ticket_contract_test for the create-ticket-from-alert response.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// --- in-memory stub engine -------------------------------------------------

// stubAlertEngine satisfies alertEngine. All four lifecycle mutations share the
// mutated/mutateErr fields since they return the same (*Alert, error) shape.
type stubAlertEngine struct {
	list      []models.Alert
	listErr   error
	stats     *models.AlertStats
	statsErr  error
	getAlert  *models.Alert
	getEvents []models.AlertEvent
	getErr    error
	mutated   *models.Alert
	mutateErr error
	ticket    *models.Ticket
	ticketErr error
}

func (s *stubAlertEngine) List(context.Context, uuid.UUID, models.AlertFilters) ([]models.Alert, error) {
	return s.list, s.listErr
}
func (s *stubAlertEngine) Stats(context.Context, uuid.UUID) (*models.AlertStats, error) {
	return s.stats, s.statsErr
}
func (s *stubAlertEngine) Get(context.Context, uuid.UUID, uuid.UUID) (*models.Alert, []models.AlertEvent, error) {
	return s.getAlert, s.getEvents, s.getErr
}
func (s *stubAlertEngine) Acknowledge(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*models.Alert, error) {
	return s.mutated, s.mutateErr
}
func (s *stubAlertEngine) Snooze(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, time.Time, string) (*models.Alert, error) {
	return s.mutated, s.mutateErr
}
func (s *stubAlertEngine) Unsnooze(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*models.Alert, error) {
	return s.mutated, s.mutateErr
}
func (s *stubAlertEngine) ResolveManual(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (*models.Alert, error) {
	return s.mutated, s.mutateErr
}
func (s *stubAlertEngine) CreateTicketFromAlert(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*models.Ticket, error) {
	return s.ticket, s.ticketErr
}

// --- test harness ----------------------------------------------------------

// newAlertEngine mounts the alert routes on /api/v1/compliance-engine (tenant
// reads + mutations) and the platform-track read on
// /api/v1/compliance-engine/admin/alerts (no tenant context — mirrors main.go).
func newAlertEngine(s *stubAlertEngine) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AlertHandlers{engine: s}

	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/alerts", h.ListAlerts)
	grp.GET("/alerts/stats", h.GetAlertStats)
	grp.GET("/alerts/:id", h.GetAlert)
	grp.POST("/alerts/:id/acknowledge", h.AcknowledgeAlert)
	grp.POST("/alerts/:id/snooze", h.SnoozeAlert)
	grp.POST("/alerts/:id/unsnooze", h.UnsnoozeAlert)
	grp.POST("/alerts/:id/resolve", h.ResolveAlert)
	grp.POST("/alerts/:id/ticket", h.CreateTicketFromAlert)

	// Platform-track read: no tenant/user middleware, the handler always scopes
	// to services.PlatformAlertTenantID.
	admin := r.Group("/api/v1/compliance-engine/admin")
	admin.GET("/alerts", h.ListPlatformAlerts)
	return r
}

// --- sample data ----------------------------------------------------------

func sampleAlert() models.Alert {
	now := time.Now().UTC()
	label := "auth-service"
	msg := "No heartbeat for 3 consecutive scans."
	return models.Alert{
		ID:            uuid.New(),
		TenantID:      services.PlatformAlertTenantID,
		AlertType:     "service_down",
		Source:        "service-down-detector",
		SubjectLabel:  &label,
		Severity:      "high",
		Status:        "active",
		Title:         "Service auth-service is down",
		Message:       &msg,
		Metadata:      map[string]interface{}{"consecutive_misses": 3},
		FirstRaisedAt: now,
		LastEventAt:   now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func sampleAlertEvent() models.AlertEvent {
	return models.AlertEvent{
		ID:        uuid.New(),
		AlertID:   uuid.New(),
		TenantID:  uuid.New(),
		EventType: "raised",
		ActorType: "system",
		Details:   map[string]interface{}{"scan": "heartbeat"},
		CreatedAt: time.Now().UTC(),
	}
}

func sampleAlertStats() *models.AlertStats {
	return &models.AlertStats{Active: 3, Acknowledged: 1, Snoozed: 0, Resolved: 5, Critical: 1, High: 2}
}

const anAlertUUID = "33333333-3333-3333-3333-333333333333"

// --- the contract tests ----------------------------------------------------

func TestContract_ListAlerts_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{list: []models.Alert{sampleAlert(), sampleAlert()}})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alerts?status=active", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertListResponse", w.Body.Bytes())
}

// Empty list serializes as `"alerts": []` (the handler passes the engine's
// non-nil slice through) — guards against the null-collection regression.
func TestContract_ListAlerts_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{list: []models.Alert{}})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alerts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertListResponse", w.Body.Bytes())
}

func TestContract_ListAlerts_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{listErr: errors.New("db down")})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alerts", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetAlertStats_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{stats: sampleAlertStats()})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alerts/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertStats", w.Body.Bytes())
}

func TestContract_GetAlertStats_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{statsErr: errors.New("db down")})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alerts/stats", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetAlert_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAlert()
	eng := newAlertEngine(&stubAlertEngine{getAlert: &a, getEvents: []models.AlertEvent{sampleAlertEvent()}})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alerts/"+anAlertUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertDetailResponse", w.Body.Bytes())
}

func TestContract_GetAlert_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alerts/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetAlert_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{getErr: services.ErrAlertNotFound})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/alerts/"+anAlertUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_AcknowledgeAlert_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAlert()
	eng := newAlertEngine(&stubAlertEngine{mutated: &a})
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/alerts/"+anAlertUUID+"/acknowledge", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertMutationResponse", w.Body.Bytes())
}

// Spec-quirk regression: an invalid state transition maps to 409 via
// writeEngineError (ErrInvalidTransition).
func TestContract_AcknowledgeAlert_409(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{mutateErr: services.ErrInvalidTransition})
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/alerts/"+anAlertUUID+"/acknowledge", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_SnoozeAlert_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAlert()
	eng := newAlertEngine(&stubAlertEngine{mutated: &a})
	body := strings.NewReader(`{"until":"2030-01-01T00:00:00Z","reason":"planned maintenance"}`)
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/alerts/"+anAlertUUID+"/snooze", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertMutationResponse", w.Body.Bytes())
}

// Spec-quirk regression: `until` is required — a body without it fails binding
// with 400 (not 500).
func TestContract_SnoozeAlert_400_missingUntil(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{})
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/alerts/"+anAlertUUID+"/snooze", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UnsnoozeAlert_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAlert()
	eng := newAlertEngine(&stubAlertEngine{mutated: &a})
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/alerts/"+anAlertUUID+"/unsnooze", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertMutationResponse", w.Body.Bytes())
}

// Resolve with an empty body is valid (the note is optional).
func TestContract_ResolveAlert_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAlert()
	eng := newAlertEngine(&stubAlertEngine{mutated: &a})
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/alerts/"+anAlertUUID+"/resolve", strings.NewReader(`{"note":"restarted"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertMutationResponse", w.Body.Bytes())
}

func TestContract_CreateTicketFromAlert_201(t *testing.T) {
	sv := loadSpec(t)
	tk := sampleTicket()
	eng := newAlertEngine(&stubAlertEngine{ticket: &tk})
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/alerts/"+anAlertUUID+"/ticket", nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertTicketResponse", w.Body.Bytes())
}

func TestContract_CreateTicketFromAlert_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{ticketErr: services.ErrAlertNotFound})
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/alerts/"+anAlertUUID+"/ticket", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- platform-track read (/admin/alerts) -----------------------------------

func TestContract_ListPlatformAlerts_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{list: []models.Alert{sampleAlert()}})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/admin/alerts?status=active", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertListResponse", w.Body.Bytes())
}

func TestContract_ListPlatformAlerts_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{list: []models.Alert{}})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/admin/alerts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertListResponse", w.Body.Bytes())
}

func TestContract_ListPlatformAlerts_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertEngine{listErr: errors.New("db down")})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/admin/alerts", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
