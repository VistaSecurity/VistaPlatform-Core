package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

// TestRequireAuth_TokenTypeRestriction asserts the security invariant
//: the local RequireAuth middleware defaults to access
// tokens only, with `AllowImpersonation()` as an explicit opt-in.
// Previously this middleware accepted both "access" and "impersonation"
// for every route, regressing from the shared middleware's opt-in
// pattern. A route that didn't intend to allow impersonation would
// silently accept it.
func TestRequireAuth_TokenTypeRestriction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: "test-secret-for-jwt-issuance-only-do-not-use"}
	jwtService := auth.NewJWTService(cfg.JWTSecret, 1*time.Hour, 24*time.Hour)

	userID := uuid.New()
	tenantID := uuid.New()

	accessToken, _, err := jwtService.GenerateTokens(userID, tenantID, "user@test.com", "tenant_admin")
	if err != nil {
		t.Fatalf("GenerateTokens: %v", err)
	}
	impersonationToken, _, _, err := jwtService.GenerateImpersonationToken(
		userID, tenantID, "user@test.com", "tenant_admin",
		uuid.New().String(), "admin@platform.com", "support investigation", "127.0.0.1", "test-agent",
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("GenerateImpersonationToken: %v", err)
	}

	cases := []struct {
		name       string
		options    []AuthOption
		token      string
		wantStatus int
	}{
		{
			name:       "default_accepts_access_token",
			options:    nil,
			token:      accessToken,
			wantStatus: http.StatusOK,
		},
		{
			name:       "default_rejects_impersonation_token",
			options:    nil,
			token:      impersonationToken,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "AllowImpersonation_accepts_access_token",
			options:    []AuthOption{AllowImpersonation()},
			token:      accessToken,
			wantStatus: http.StatusOK,
		},
		{
			name:       "AllowImpersonation_accepts_impersonation_token",
			options:    []AuthOption{AllowImpersonation()},
			token:      impersonationToken,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/protected", RequireAuth(cfg, jwtService, tc.options...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestRequireAuth_PasswordChangeRequiredGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: "test-secret-for-jwt-issuance-only-do-not-use"}
	jwtService := auth.NewJWTService(cfg.JWTSecret, 1*time.Hour, 24*time.Hour)

	userID := uuid.New()
	tenantID := uuid.Nil
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.JWTClaims{
		UserID:                 userID,
		TenantID:               tenantID,
		Email:                  "platform-admin@test.com",
		Role:                   "super_admin",
		Type:                   "access",
		PasswordChangeRequired: true,
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
	limitedToken, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{
			name:       "protected_auth_service_route_blocked",
			method:     http.MethodPost,
			path:       "/admin/impersonations",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "prefixed_protected_route_blocked",
			method:     http.MethodPost,
			path:       "/api/v1/auth-service/admin/impersonations",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "change_password_route_allowed",
			method:     http.MethodPost,
			path:       "/auth/change-password",
			wantStatus: http.StatusOK,
		},
		{
			name:       "prefixed_me_route_allowed",
			method:     http.MethodGet,
			path:       "/api/v1/auth-service/auth/me",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Handle(tc.method, tc.path, RequireAuth(cfg, jwtService), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+limitedToken)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}
