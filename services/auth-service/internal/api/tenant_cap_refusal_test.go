package api

// Signup refused by the MSP soft cap: what the anonymous visitor sees, and
// what the operator's audit trail records (edition-licensing spec §3).
//
// The refusal is answered to someone signing up on the MSP's own —
// possibly white-labelled — portal. It must not carry the install's tenant
// counts (business-sensitive, and readable without authentication), the
// licence vendor's name, or a licensing instruction the visitor cannot act on.
// Those belong to the operator, so they go to audit instead.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

func newCapRefusalEngine(stub *stubAuthServiceStore, mw *audithelpers.Middleware) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("audit_middleware", mw)
		c.Next()
	})
	h := &AuthHandlers{authService: stub}
	grp.POST("/auth/register", h.Register)
	grp.POST("/auth/register/complete", h.CompleteRegistration)
	return r
}

func TestSignup_TenantCapRefusal_GenericToVisitor_CountsToAudit(t *testing.T) {
	for _, path := range []string{"/auth/register", "/auth/register/complete"} {
		t.Run(path, func(t *testing.T) {
			sv := loadSpec(t)
			stub := &stubAuthServiceStore{registerErr: &entitlements.TenantCapExceededError{Licensed: 25, Current: 27}}
			mw := newLoginAuditMiddleware(t)
			w := do(newCapRefusalEngine(stub, mw), http.MethodPost, "/api/v1/auth-service"+path, strings.NewReader(validRegisterBody))

			if w.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error != entitlements.TenantCapPublicMessage {
				t.Errorf("visitor sees %q, want the generic %q", body.Error, entitlements.TenantCapPublicMessage)
			}
			raw := w.Body.String()
			for _, leak := range []string{"25", "27", "Vista", "licen"} {
				if strings.Contains(raw, leak) {
					t.Errorf("signup response leaks %q: %s", leak, raw)
				}
			}

			entries := mw.PendingEntries()
			if len(entries) != 1 {
				t.Fatalf("recorded %d audit entries, want 1", len(entries))
			}
			e := entries[0]
			if e.EventType != TenantCapRefusedEventType || e.EventCategory != "tenant" || e.Success || !e.RequiresAttention {
				t.Errorf("audit entry = %+v", e)
			}
			if e.ErrorMessage == nil || !strings.Contains(*e.ErrorMessage, "27 of 25") {
				t.Errorf("audit error message %v, want the operator-facing counts", e.ErrorMessage)
			}
			if e.Metadata["licensed_tenants"] != 25 || e.Metadata["current_tenants"] != 27 {
				t.Errorf("audit metadata %v", e.Metadata)
			}
			if e.UserEmail != nil {
				t.Errorf("audit records the refused visitor's email %q", *e.UserEmail)
			}
		})
	}
}
