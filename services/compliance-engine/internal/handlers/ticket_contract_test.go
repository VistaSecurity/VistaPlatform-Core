package handlers

// Contract test for the compliance-engine tenant-facing tickets HTTP surface.
//
// Sixth vertical slice for the spec-first API contract (ADR-0001), and the
// second slice for compliance-engine. The pattern is the same as
// framework_contract_test.go: exercise the REAL gin handlers over httptest
// (driven by an in-memory stub satisfying `ticketStore`, no database / NATS)
// and assert every response body conforms to the schema in
// `api/openapi/compliance-engine.openapi.yaml`.
//
// Spec loading + JSON-Schema validation is shared with framework_contract_test
// (loadSpec / specValidator / assertConforms), so this file focuses on the
// ticket-specific stub, the route mount, and the per-response assertions.

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// --- in-memory stub store --------------------------------------------------

// stubTicketStore satisfies ticketStore. Only the methods the handlers call
// behind the in-scope routes carry meaningful behavior; everything else is a
// no-op return so the type compiles against the interface.
type stubTicketStore struct {
	listTickets    []models.Ticket
	listTotal      int
	listErr        error
	createResult   *models.Ticket
	createErr      error
	getResult      *models.Ticket
	getErr         error
	updateResult   *models.Ticket
	updateErr      error
	deleteErr      error
	progressResult *models.TicketProgress
	progressErr    error
	statsResult    *models.TicketStats
	statsErr       error
	commentsResult []models.TicketComment
	commentsErr    error
	addCommentRes  *models.TicketComment
	addCommentErr  error
}

func (s *stubTicketStore) List(_ uuid.UUID, _ models.TicketFilters) ([]models.Ticket, int, error) {
	return s.listTickets, s.listTotal, s.listErr
}
func (s *stubTicketStore) Create(_, _ uuid.UUID, _ models.CreateTicketInput) (*models.Ticket, error) {
	return s.createResult, s.createErr
}
func (s *stubTicketStore) GetByID(_, _ uuid.UUID) (*models.Ticket, error) {
	return s.getResult, s.getErr
}
func (s *stubTicketStore) Update(_, _ uuid.UUID, _ models.UpdateTicketInput) (*models.Ticket, error) {
	return s.updateResult, s.updateErr
}
func (s *stubTicketStore) Delete(_, _ uuid.UUID) error { return s.deleteErr }
func (s *stubTicketStore) GetProgress(_ uuid.UUID, _ int, _ string) (*models.TicketProgress, error) {
	return s.progressResult, s.progressErr
}
func (s *stubTicketStore) GetStats(_ uuid.UUID) (*models.TicketStats, error) {
	return s.statsResult, s.statsErr
}
func (s *stubTicketStore) ListComments(_, _ uuid.UUID) ([]models.TicketComment, error) {
	return s.commentsResult, s.commentsErr
}
func (s *stubTicketStore) AddComment(_, _, _ uuid.UUID, _ string) (*models.TicketComment, error) {
	return s.addCommentRes, s.addCommentErr
}

// --- test harness ----------------------------------------------------------

// newTicketEngine mounts the in-scope ticket routes on
// /api/v1/compliance-engine with the same tenant/user injection middleware as
// newEngine (framework_contract_test). Production routes are registered in
// cmd/main.go; this mirrors them 1:1 for the contract surface only.
func newTicketEngine(s *stubTicketStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})

	h := &TicketHandlers{ticketService: s}
	grp.GET("/tickets", h.ListTickets)
	grp.POST("/tickets", h.CreateTicket)
	grp.GET("/tickets/stats", h.GetTicketStats)
	grp.GET("/tickets/progress", h.GetTicketProgress)
	grp.GET("/tickets/:id", h.GetTicket)
	grp.PUT("/tickets/:id", h.UpdateTicket)
	grp.DELETE("/tickets/:id", h.DeleteTicket)
	grp.GET("/tickets/:id/comments", h.ListComments)
	grp.POST("/tickets/:id/comments", h.AddComment)
	return r
}

// --- sample data ----------------------------------------------------------

func sampleTicket() models.Ticket {
	now := time.Now().UTC()
	return models.Ticket{
		ID:                 uuid.New(),
		TenantID:           uuid.New(),
		Category:           "remediation",
		Title:              "Rotate weak certificate for api.example.com",
		Status:             "open",
		Priority:           "high",
		Source:             "manual",
		ExternalSyncStatus: "none",
		CreatedBy:          uuid.New(),
		CreatedAt:          now,
		UpdatedAt:          now,
		// pq.StringArray serializes as a JSON array, matching the spec's
		// `tags` field shape.
		Tags: pq.StringArray{"pqc", "tls"},
	}
}

func sampleComment() models.TicketComment {
	author := uuid.New()
	return models.TicketComment{
		ID:        uuid.New(),
		TicketID:  uuid.New(),
		AuthorID:  &author,
		Content:   "Confirmed in production change window.",
		CreatedAt: time.Now().UTC(),
	}
}

func sampleStats() *models.TicketStats {
	return &models.TicketStats{
		ByStatus:   map[string]int{"open": 4, "resolved": 1},
		ByCategory: map[string]int{"remediation": 3, "compliance": 2},
		Overdue:    1,
		Total:      5,
	}
}

func sampleProgress() *models.TicketProgress {
	return &models.TicketProgress{
		PeriodDays:         30,
		Summary:            map[string]int{"open": 4, "resolved": 1, "overdue": 1},
		AvgResolutionHours: 18.5,
		Trend: []models.TicketTrendPoint{
			{Date: "2026-05-01", Opened: 2, Resolved: 0},
			{Date: "2026-05-02", Opened: 1, Resolved: 1},
		},
		ByCategory: map[string]map[string]int{
			"remediation": {"open": 3, "resolved": 1},
		},
	}
}

const aTicketUUID = "22222222-2222-2222-2222-222222222222"

// --- the contract tests ----------------------------------------------------

func TestContract_ListTickets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{
		listTickets: []models.Ticket{sampleTicket(), sampleTicket()},
		listTotal:   2,
	})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/tickets", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketListResponse", w.Body.Bytes())
}

// Empty list still validates: handler's service layer returns a non-nil empty
// slice, so the response is `"tickets": []` (not `null`). Guard against the
// scopes-slice regression where empty collections serialized as `null`.
func TestContract_ListTickets_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{
		listTickets: []models.Ticket{},
		listTotal:   0,
	})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/tickets", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketListResponse", w.Body.Bytes())
}

// Spec-quirk regression: a malformed UUID filter is silently dropped, the
// handler still returns 200 (not 400).
func TestContract_ListTickets_200_badUUIDFilterSilentlyDropped(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{
		listTickets: []models.Ticket{sampleTicket()},
		listTotal:   1,
	})
	w := do(eng, http.MethodGet,
		"/api/v1/compliance-engine/tickets?assigned_to=not-a-uuid", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketListResponse", w.Body.Bytes())
}

func TestContract_ListTickets_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{listErr: errors.New("db down")})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/tickets", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateTicket_201(t *testing.T) {
	sv := loadSpec(t)
	tk := sampleTicket()
	eng := newTicketEngine(&stubTicketStore{createResult: &tk})
	body := strings.NewReader(`{"title":"Rotate weak cert","category":"remediation"}`)
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/tickets", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketCreatedResponse", w.Body.Bytes())
}

// Spec-quirk regression: explicit empty-string title fails the
// `input.Title == ""` check (not the struct binding), so we get 400 with the
// "Title is required" wording — distinct from the malformed-JSON 400.
func TestContract_CreateTicket_400_missingTitle(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{})
	body := strings.NewReader(`{}`)
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/tickets", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateTicket_400_malformedJSON(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{})
	body := strings.NewReader(`{not-json`)
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/tickets", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateTicket_500_serviceFailure(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{createErr: errors.New("db down")})
	body := strings.NewReader(`{"title":"Rotate cert"}`)
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/tickets", body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTicket_200(t *testing.T) {
	sv := loadSpec(t)
	tk := sampleTicket()
	eng := newTicketEngine(&stubTicketStore{getResult: &tk})
	w := do(eng, http.MethodGet,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketResponse", w.Body.Bytes())
}

func TestContract_GetTicket_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{})
	w := do(eng, http.MethodGet,
		"/api/v1/compliance-engine/tickets/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTicket_404(t *testing.T) {
	sv := loadSpec(t)
	// Service returns (nil, nil) for "not found" — the handler maps that to 404.
	eng := newTicketEngine(&stubTicketStore{getResult: nil, getErr: nil})
	w := do(eng, http.MethodGet,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTicket_200(t *testing.T) {
	sv := loadSpec(t)
	tk := sampleTicket()
	eng := newTicketEngine(&stubTicketStore{updateResult: &tk})
	body := strings.NewReader(`{"status":"in_progress"}`)
	w := do(eng, http.MethodPut,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketUpdatedResponse", w.Body.Bytes())
}

// Spec-quirk regression: not-found is detected by `err.Error() ==
// "ticket not found"` — exact string match.
func TestContract_UpdateTicket_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{updateErr: errors.New("ticket not found")})
	body := strings.NewReader(`{"status":"closed"}`)
	w := do(eng, http.MethodPut,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID, body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteTicket_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{})
	w := do(eng, http.MethodDelete,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_DeleteTicket_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{deleteErr: errors.New("ticket not found")})
	w := do(eng, http.MethodDelete,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTicketStats_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{statsResult: sampleStats()})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/tickets/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketStatsResponse", w.Body.Bytes())
}

func TestContract_GetTicketProgress_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{progressResult: sampleProgress()})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/tickets/progress", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketProgressResponse", w.Body.Bytes())
}

// Spec-quirk regression: non-numeric `days` falls back to 30, and a category
// filter is honored. We assert the response still conforms — the parsing
// quirk is documented on the path.
func TestContract_GetTicketProgress_200_paramsParsed(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{progressResult: sampleProgress()})
	w := do(eng, http.MethodGet,
		"/api/v1/compliance-engine/tickets/progress?days=abc&category=remediation", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketProgressResponse", w.Body.Bytes())
}

func TestContract_ListComments_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{
		commentsResult: []models.TicketComment{sampleComment()},
	})
	w := do(eng, http.MethodGet,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID+"/comments", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketCommentListResponse", w.Body.Bytes())
}

func TestContract_ListComments_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{commentsErr: errors.New("ticket not found")})
	w := do(eng, http.MethodGet,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID+"/comments", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_AddComment_201(t *testing.T) {
	sv := loadSpec(t)
	c := sampleComment()
	eng := newTicketEngine(&stubTicketStore{addCommentRes: &c})
	body := strings.NewReader(`{"content":"Confirmed in production change window."}`)
	w := do(eng, http.MethodPost,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID+"/comments", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TicketCommentCreatedResponse", w.Body.Bytes())
}

func TestContract_AddComment_400_missingContent(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{})
	body := strings.NewReader(`{}`)
	w := do(eng, http.MethodPost,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID+"/comments", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_AddComment_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newTicketEngine(&stubTicketStore{addCommentErr: errors.New("ticket not found")})
	body := strings.NewReader(`{"content":"hi"}`)
	w := do(eng, http.MethodPost,
		"/api/v1/compliance-engine/tickets/"+aTicketUUID+"/comments", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
