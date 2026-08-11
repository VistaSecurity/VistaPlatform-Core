package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
)

func TestRequireAuth_PasswordChangeRequiredGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := "test-secret-for-jwt-issuance-only-do-not-use"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}
	userID := uuid.NewString()

	cases := []struct {
		name                   string
		passwordChangeRequired bool
		wantStatus             int
	}{
		{
			name:                   "normal_access_token_allowed",
			passwordChangeRequired: false,
			wantStatus:             http.StatusOK,
		},
		{
			name:                   "limited_access_token_rejected",
			passwordChangeRequired: true,
			wantStatus:             http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"user_id":             userID,
				"email":               "platform-admin@test.com",
				"role":                "super_admin",
				"type":                "access",
				"pwd_change_required": tc.passwordChangeRequired,
				"iss":                 "crypto-inventory-auth",
				"aud":                 "crypto-inventory",
				"sub":                 userID,
				"jti":                 uuid.NewString(),
				"iat":                 time.Now().Unix(),
				"nbf":                 time.Now().Add(-time.Minute).Unix(),
				"exp":                 time.Now().Add(time.Hour).Unix(),
			})
			signed, err := token.SignedString([]byte(secret))
			if err != nil {
				t.Fatalf("SignedString: %v", err)
			}

			r := gin.New()
			r.POST("/activity-logs/query", RequireAuth(cfg), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, "/activity-logs/query", nil)
			req.Header.Set("Authorization", "Bearer "+signed)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}
