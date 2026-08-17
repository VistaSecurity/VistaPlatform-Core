package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

func newLoginAuditMiddleware(t *testing.T) *audithelpers.Middleware {
	t.Helper()
	cfg := audithelpers.DefaultConfig()
	cfg.ServiceName = "auth-service"
	cfg.AuditServiceURL = "http://127.0.0.1:1"
	cfg.BatchSize = 1000
	cfg.FlushInterval = time.Hour
	cfg.Timeout = time.Millisecond
	cfg.RetryAttempts = 0
	cfg.UseNATS = false
	mw := audithelpers.NewMiddleware(cfg)
	t.Cleanup(mw.Stop)
	return mw
}

func newLoginAuditEngine(stub *stubAuthServiceStore, mw *audithelpers.Middleware) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("audit_middleware", mw)
		c.Next()
	})
	h := &AuthHandlers{authService: stub}
	grp.POST("/auth/login", h.Login)
	return r
}

func TestLogin_InvalidCredentialsKnownEmailAuditsTenantAndUser(t *testing.T) {
	email := "known-user@example.com"
	tenantID := uuid.New()
	userID := uuid.New()
	stub := &stubAuthServiceStore{
		loginErr: auth.ErrInvalidCredentials,
		emailUserResult: &models.User{
			ID:       userID,
			TenantID: tenantID,
			Email:    email,
		},
	}
	mw := newLoginAuditMiddleware(t)
	eng := newLoginAuditEngine(stub, mw)

	w := do(eng, http.MethodPost, "/api/v1/auth-service/auth/login",
		strings.NewReader(`{"email":"`+email+`","password":"WrongPass123!"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login status = %d, want 401; body=%s", w.Code, w.Body.String())
	}

	entries := mw.PendingEntries()
	if len(entries) != 1 {
		t.Fatalf("recorded %d audit entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry.TenantID == nil || *entry.TenantID != tenantID {
		t.Fatalf("TenantID = %v, want %s", entry.TenantID, tenantID)
	}
	if entry.UserID == nil || *entry.UserID != userID {
		t.Fatalf("UserID = %v, want %s", entry.UserID, userID)
	}
	if entry.UserEmail == nil || *entry.UserEmail != email {
		t.Fatalf("UserEmail = %v, want %q", entry.UserEmail, email)
	}
	if entry.EventType != "user.login_failed" || entry.EventCategory != "authentication" || entry.Action != "login_failed" {
		t.Fatalf("audit event = (%q, %q, %q), want user.login_failed/authentication/login_failed",
			entry.EventType, entry.EventCategory, entry.Action)
	}
	if entry.Success {
		t.Fatal("Success = true, want false")
	}
	if entry.ErrorMessage == nil || *entry.ErrorMessage != "Invalid credentials" {
		t.Fatalf("ErrorMessage = %v, want Invalid credentials", entry.ErrorMessage)
	}
	if !entry.RequiresAttention {
		t.Fatal("RequiresAttention = false, want true")
	}
}

func TestLogin_InvalidCredentialsUnknownEmailAuditsWithoutTenantContext(t *testing.T) {
	email := "unknown-user@example.com"
	stub := &stubAuthServiceStore{
		loginErr:     auth.ErrInvalidCredentials,
		emailUserErr: auth.ErrUserNotFound,
	}
	mw := newLoginAuditMiddleware(t)
	eng := newLoginAuditEngine(stub, mw)

	w := do(eng, http.MethodPost, "/api/v1/auth-service/auth/login",
		strings.NewReader(`{"email":"`+email+`","password":"WrongPass123!"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login status = %d, want 401; body=%s", w.Code, w.Body.String())
	}

	entries := mw.PendingEntries()
	if len(entries) != 1 {
		t.Fatalf("recorded %d audit entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry.TenantID != nil {
		t.Fatalf("TenantID = %v, want nil for unknown email", entry.TenantID)
	}
	if entry.UserID != nil {
		t.Fatalf("UserID = %v, want nil for unknown email", entry.UserID)
	}
	if entry.UserEmail == nil || *entry.UserEmail != email {
		t.Fatalf("UserEmail = %v, want %q", entry.UserEmail, email)
	}
	if entry.EventType != "user.login_failed" || entry.ErrorMessage == nil || *entry.ErrorMessage != "Invalid credentials" {
		t.Fatalf("audit entry did not preserve failed-login semantics: %+v", entry)
	}
}
