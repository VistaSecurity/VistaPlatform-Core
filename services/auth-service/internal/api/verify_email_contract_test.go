package api

// Contract tests for the email-verification surface used by the self-service
// signup front door:
//   POST /auth/verify-email      (token query param)
//   POST /auth/resend-verification
//
// Reuses loadSpec / assertConforms / do and the shared stubAuthServiceStore from
// cross_cutter_contract_test.go (same package).

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
)

func newVerifyEngine(stub *stubAuthServiceStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	h := &AuthHandlers{authService: stub}
	grp.POST("/auth/verify-email", h.VerifyEmail)
	grp.POST("/auth/resend-verification", h.ResendEmailVerification)
	return r
}

// --- POST /auth/verify-email ------------------------------------------------

func TestContract_VerifyEmail_200(t *testing.T) {
	sv := loadSpec(t)
	w := do(newVerifyEngine(&stubAuthServiceStore{}), http.MethodPost, "/api/v1/auth-service/auth/verify-email?token=good-token", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_VerifyEmail_400_missingToken(t *testing.T) {
	sv := loadSpec(t)
	w := do(newVerifyEngine(&stubAuthServiceStore{}), http.MethodPost, "/api/v1/auth-service/auth/verify-email", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// An invalid/expired token surfaces as 400 (distinguished only by the message).
func TestContract_VerifyEmail_400_invalidToken(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubAuthServiceStore{verifyEmailErr: auth.ErrExpiredToken}
	w := do(newVerifyEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/verify-email?token=stale", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /auth/resend-verification -----------------------------------------

func TestContract_ResendVerification_200(t *testing.T) {
	sv := loadSpec(t)
	// User not found / already verified all return the same 200 (anti-enumeration).
	stub := &stubAuthServiceStore{emailUserErr: auth.ErrUserNotFound}
	w := do(newVerifyEngine(stub), http.MethodPost, "/api/v1/auth-service/auth/resend-verification", strings.NewReader(`{"email":"someone@acme.com"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_ResendVerification_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	w := do(newVerifyEngine(&stubAuthServiceStore{}), http.MethodPost, "/api/v1/auth-service/auth/resend-verification", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
