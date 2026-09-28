package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

func TestSourceRefreshRequiresSignedMatchingTenant(t *testing.T) {
	t.Setenv("INTERNAL_AUTH_SECRET", "refresh-auth-test-key")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := &DeviceHandlers{}
	handler.RegisterSourceRefresh(router, nil)
	tenant := uuid.New()
	other := uuid.New()
	body, _ := json.Marshal(services.SourceRefreshRequest{TenantID: other})
	req := httptest.NewRequest(http.MethodPost, "/internal/enrichment/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenant.String())
	result := httptest.NewRecorder()
	router.ServeHTTP(result, req)
	if result.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", result.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/internal/enrichment/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenant.String())
	serviceauth.NewSigner("refresh-auth-test-key").SignRequest(req)
	result = httptest.NewRecorder()
	router.ServeHTTP(result, req)
	if result.Code != http.StatusBadRequest {
		t.Fatalf("signed mismatched tenant: %d", result.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/internal/enrichment/refresh/"+uuid.NewString()+"?tenant_id="+other.String(), nil)
	req.Header.Set("X-Tenant-ID", tenant.String())
	serviceauth.NewSigner("refresh-auth-test-key").SignRequest(req)
	result = httptest.NewRecorder()
	router.ServeHTTP(result, req)
	if result.Code != http.StatusBadRequest {
		t.Fatalf("poll mismatched tenant: %d", result.Code)
	}
}

// The refresh route authenticates by HMAC and carries the tenant in a header;
// the audit middleware reads the standard tenantID key after c.Next(), so the
// route must set it or every refresh is logged with no tenant.
func TestSourceRefreshRecordsTheTenantForAudit(t *testing.T) {
	t.Setenv("INTERNAL_AUTH_SECRET", "refresh-auth-test-key")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var seen any
	router.Use(func(c *gin.Context) {
		c.Next()
		seen, _ = c.Get("tenantID")
	})
	(&DeviceHandlers{}).RegisterSourceRefresh(router, nil)

	tenant := uuid.New()
	// A mismatched body is refused by the handler, after the auth step has
	// already named the tenant; the refusal does not matter here.
	body, _ := json.Marshal(services.SourceRefreshRequest{TenantID: uuid.New()})
	req := httptest.NewRequest(http.MethodPost, "/internal/enrichment/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenant.String())
	serviceauth.NewSigner("refresh-auth-test-key").SignRequest(req)
	router.ServeHTTP(httptest.NewRecorder(), req)

	if got, _ := seen.(uuid.UUID); got != tenant {
		t.Fatalf("tenantID in the audit context = %v, want %s", seen, tenant)
	}
}
