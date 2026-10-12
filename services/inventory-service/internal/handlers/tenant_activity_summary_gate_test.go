package handlers

// GET /inventory-service/tenant/:id/activity-summary names the tenant in the
// URL, so it must be reachable ONLY by a signed service call: a tenant user
// (or platform token) who learns another tenant's UUID must not read that
// tenant's counts. These drive the real JWTMiddleware in front of the real
// handler, so deleting the IsInternalCall gate turns the refusals red.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

type activityStore struct {
	stubAssetStore
	calls  int
	tenant uuid.UUID
}

func (s *activityStore) GetTenantActivitySummary(id uuid.UUID) (*services.TenantActivitySummary, error) {
	s.calls++
	s.tenant = id
	return &services.TenantActivitySummary{}, nil
}

func TestTenantActivitySummary_InternalOnly(t *testing.T) {
	useLiveTenantState(t)
	gin.SetMode(gin.TestMode)
	const secret = "activity-summary-gate-secret-0123456789"
	const jwtSecret = "test-secret-for-jwt-issuance-only-do-not-use"
	t.Setenv("INTERNAL_AUTH_SECRET", secret)
	internalVerifier = nil
	t.Cleanup(func() { internalVerifier = nil })

	cfg := &config.Config{JWT: config.JWTConfig{Secret: jwtSecret}}
	mint := func(tenant uuid.UUID, role string) string {
		userID := uuid.New()
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &JWTClaims{
			UserID: userID, TenantID: tenant, Email: "u@test.com", Role: role, Type: "access",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID.String(),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				Issuer:    "crypto-inventory-auth",
				Audience:  jwt.ClaimStrings{"crypto-inventory"},
				ID:        uuid.NewString(),
			},
		})
		s, err := tok.SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	newRouter := func(store *activityStore) *gin.Engine {
		r := gin.New()
		g := r.Group("/api/v1")
		g.Use(JWTMiddleware(cfg, nil))
		g.GET("/inventory-service/tenant/:id/activity-summary", NewAssetHandler(store, nil).GetTenantActivitySummary)
		return r
	}

	tenantA, tenantB := uuid.New(), uuid.New()
	pathB := "/api/v1/inventory-service/tenant/" + tenantB.String() + "/activity-summary"

	refused := map[string]func(*http.Request){
		"tenant A user reading tenant B":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+mint(tenantA, "tenant_admin")) },
		"tenant B's own admin":            func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+mint(tenantB, "tenant_admin")) },
		"platform super_admin token":      func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+mint(uuid.Nil, "super_admin")) },
		"unsigned X-Internal-Call header": func(r *http.Request) { r.Header.Set("X-Internal-Call", "true") },
	}
	for name, mutate := range refused {
		store := &activityStore{}
		req := httptest.NewRequest(http.MethodGet, pathB, nil)
		mutate(req)
		w := httptest.NewRecorder()
		newRouter(store).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401/403", name, w.Code)
		}
		if name == "tenant A user reading tenant B" && w.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", name, w.Code)
		}
		if store.calls != 0 {
			t.Errorf("%s reached the store %d times", name, store.calls)
		}
	}

	// Positive polarity: a signed service call (as tenant-health-service sends).
	store := &activityStore{}
	req := httptest.NewRequest(http.MethodGet, pathB, nil)
	req.Header.Set("X-Tenant-ID", tenantB.String())
	serviceauth.NewSigner(secret).SignRequest(req)
	w := httptest.NewRecorder()
	newRouter(store).ServeHTTP(w, req)
	if w.Code != http.StatusOK || store.calls != 1 || store.tenant != tenantB {
		t.Fatalf("signed call = %d (store calls %d, tenant %s), want 200 for %s", w.Code, store.calls, store.tenant, tenantB)
	}
}
