package api

// Contract test for the platform-admin impersonation HTTP surface
// (`/api/v1/auth-service/admin/impersonations*`) — admin-ui impersonation-api.ts.
//
// The handlers depend on the narrow impersonationService interface (the concrete
// *auth.AuthService satisfies it via auth/impersonation.go), so the real gin
// handlers run over an in-memory stub — no DB, no Redis, no JWT signing — and
// their bodies are asserted against api/openapi/auth-service.openapi.yaml.
//
// Reuses loadSpec / specValidator.assertConforms / do from cross_cutter_contract_test.go.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
)

const impBase = "/api/v1/auth-service"

// --- stub -------------------------------------------------------------------

type stubImpersonation struct {
	user      *models.User
	userErr   error
	token     string
	tokenErr  error
	events    []auth.ImpersonationEvent
	eventsErr error
}

func (s *stubImpersonation) GetUserByID(uuid.UUID) (*models.User, error) {
	return s.user, s.userErr
}
func (s *stubImpersonation) GenerateImpersonationToken(_, _ uuid.UUID, _, _, _, _, _, _, _ string, ttl time.Duration) (string, time.Time, string, error) {
	return s.token, time.Now().UTC().Add(ttl), "jti-test-123", s.tokenErr
}
func (s *stubImpersonation) RecordImpersonationStart(context.Context, auth.ImpersonationStartParams) error {
	return nil
}
func (s *stubImpersonation) RevokeJTI(context.Context, string, time.Duration) error { return nil }
func (s *stubImpersonation) RemainingImpersonationTTL(context.Context, string) (time.Duration, bool, error) {
	return 0, false, nil
}
func (s *stubImpersonation) RecordImpersonationStop(context.Context, string, string, string, string) error {
	return nil
}
func (s *stubImpersonation) ListImpersonationEvents(context.Context) ([]auth.ImpersonationEvent, error) {
	return s.events, s.eventsErr
}

// --- harness ----------------------------------------------------------------

// newImpersonationEngine mounts the real handlers with an actor context
// (userID + email) and, when svc != nil, the impersonation service in context.
func newImpersonationEngine(svc impersonationService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group(impBase)
	g.Use(func(c *gin.Context) {
		c.Set("userID", uuid.NewString())
		c.Set("email", "admin@example.com")
		if svc != nil {
			c.Set("authService", svc)
		}
		c.Next()
	})
	g.POST("/admin/impersonations", InitiateAdminImpersonation)
	g.POST("/admin/impersonations/stop", StopAdminImpersonation)
	g.GET("/admin/impersonations/audit", ListImpersonationAudit)
	return r
}

func sampleTargetUser(tenantID uuid.UUID) *models.User {
	return &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Email:    "target@example.com",
		Role:     "tenant_admin",
		IsActive: true,
	}
}

func initiateBody(tenantID, userID uuid.UUID) string {
	return `{"tenant_id":"` + tenantID.String() + `","user_id":"` + userID.String() + `","reason":"support investigation"}`
}

// --- initiate ---------------------------------------------------------------

func TestContract_InitiateImpersonation_200(t *testing.T) {
	sv := loadSpec(t)
	tenantID := uuid.New()
	user := sampleTargetUser(tenantID)
	eng := newImpersonationEngine(&stubImpersonation{user: user, token: "tok-abc"})
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations", strings.NewReader(initiateBody(tenantID, user.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ImpersonationResponse", w.Body.Bytes())
}

// Missing/short fields → binding 400.
func TestContract_InitiateImpersonation_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newImpersonationEngine(&stubImpersonation{})
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Target user belongs to a different tenant → 400.
func TestContract_InitiateImpersonation_400_tenantMismatch(t *testing.T) {
	sv := loadSpec(t)
	user := sampleTargetUser(uuid.New()) // different tenant than the body
	eng := newImpersonationEngine(&stubImpersonation{user: user, token: "tok"})
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations", strings.NewReader(initiateBody(uuid.New(), user.ID)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Inactive target user → 400.
func TestContract_InitiateImpersonation_400_inactive(t *testing.T) {
	sv := loadSpec(t)
	tenantID := uuid.New()
	user := sampleTargetUser(tenantID)
	user.IsActive = false
	eng := newImpersonationEngine(&stubImpersonation{user: user, token: "tok"})
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations", strings.NewReader(initiateBody(tenantID, user.ID)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_InitiateImpersonation_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newImpersonationEngine(&stubImpersonation{userErr: auth.ErrUserNotFound})
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations", strings.NewReader(initiateBody(uuid.New(), uuid.New())))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Token generation fails → 500.
func TestContract_InitiateImpersonation_500(t *testing.T) {
	sv := loadSpec(t)
	tenantID := uuid.New()
	user := sampleTargetUser(tenantID)
	eng := newImpersonationEngine(&stubImpersonation{user: user, tokenErr: context.DeadlineExceeded})
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations", strings.NewReader(initiateBody(tenantID, user.ID)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// No impersonation service in context → 500.
func TestContract_InitiateImpersonation_500_noSvc(t *testing.T) {
	sv := loadSpec(t)
	eng := newImpersonationEngine(nil)
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations", strings.NewReader(initiateBody(uuid.New(), uuid.New())))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- stop -------------------------------------------------------------------

func TestContract_StopImpersonation_204(t *testing.T) {
	eng := newImpersonationEngine(&stubImpersonation{})
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations/stop", strings.NewReader(`{"jti":"jti-test-123"}`))
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body for 204, got %s", w.Body.String())
	}
}

// Missing jti → 400.
func TestContract_StopImpersonation_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newImpersonationEngine(&stubImpersonation{})
	w := do(eng, http.MethodPost, impBase+"/admin/impersonations/stop", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- audit ------------------------------------------------------------------

func TestContract_ListImpersonationAudit_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newImpersonationEngine(&stubImpersonation{events: []auth.ImpersonationEvent{{
		OccurredAt:  time.Now().UTC(),
		EventType:   "impersonation_start",
		EventStatus: "success",
		IPAddress:   "10.0.0.1",
		UserAgent:   "Mozilla/5.0",
		EventData:   `{"actor_id":"x","jti":"jti-test-123"}`,
	}}})
	w := do(eng, http.MethodGet, impBase+"/admin/impersonations/audit", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ImpersonationAuditResponse", w.Body.Bytes())
}

// Empty trail → nil slice → `"events": null`.
func TestContract_ListImpersonationAudit_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newImpersonationEngine(&stubImpersonation{events: nil})
	w := do(eng, http.MethodGet, impBase+"/admin/impersonations/audit", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ImpersonationAuditResponse", w.Body.Bytes())
}

func TestContract_ListImpersonationAudit_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newImpersonationEngine(&stubImpersonation{eventsErr: context.DeadlineExceeded})
	w := do(eng, http.MethodGet, impBase+"/admin/impersonations/audit", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
