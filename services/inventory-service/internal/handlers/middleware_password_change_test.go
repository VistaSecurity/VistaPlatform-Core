package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Regression coverage for: inventory-service has its own local JWT
// middleware (not shared/middleware.RequireJWTAuth), so it needs its own
// pwd_change_required gate mirroring auth-service and audit-service.
func TestJWTMiddleware_PasswordChangeRequiredGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := "test-secret-for-jwt-issuance-only-do-not-use"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}
	userID := uuid.New()

	mintToken := func(passwordChangeRequired bool) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &JWTClaims{
			UserID:                 userID,
			TenantID:               uuid.Nil,
			Email:                  "platform-admin@test.com",
			Role:                   "super_admin",
			Type:                   "access",
			PasswordChangeRequired: passwordChangeRequired,
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
		signed, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("SignedString: %v", err)
		}
		return signed
	}

	cases := []struct {
		name                   string
		passwordChangeRequired bool
		path                   string
		wantStatus             int
	}{
		{
			name:                   "normal_token_reaches_protected_route",
			passwordChangeRequired: false,
			path:                   "/algorithms",
			wantStatus:             http.StatusOK,
		},
		{
			name:                   "limited_token_blocked_on_protected_route",
			passwordChangeRequired: true,
			path:                   "/algorithms",
			wantStatus:             http.StatusForbidden,
		},
		{
			name:                   "limited_token_blocked_on_prefixed_protected_route",
			passwordChangeRequired: true,
			path:                   "/api/v2/inventory-service/algorithms",
			wantStatus:             http.StatusForbidden,
		},
		{
			name:                   "limited_token_allowed_on_change_password_route",
			passwordChangeRequired: true,
			path:                   "/auth/change-password",
			wantStatus:             http.StatusOK,
		},
		{
			name:                   "limited_token_allowed_on_me_route",
			passwordChangeRequired: true,
			path:                   "/auth/me",
			wantStatus:             http.StatusOK,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			mw := JWTMiddleware(cfg, nil)
			r.Any(tc.path, mw, func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+mintToken(tc.passwordChangeRequired))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}
