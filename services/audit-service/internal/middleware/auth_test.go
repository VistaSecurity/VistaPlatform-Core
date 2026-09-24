package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type testRevocationChecker struct {
	revokedJTIs  map[string]bool
	revokedUsers map[uuid.UUID]bool
}

func (c testRevocationChecker) IsRevoked(_ context.Context, jti string) bool {
	return c.revokedJTIs[jti]
}

func (c testRevocationChecker) IsUserRevoked(_ context.Context, userID uuid.UUID) bool {
	return c.revokedUsers[userID]
}

func TestRequireAuth_PasswordChangeRequiredGate(t *testing.T) {
	useLiveTenantState(t)
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

func TestRequireAuth_RevokedTokensRejected(t *testing.T) {
	useLiveTenantState(t)
	gin.SetMode(gin.TestMode)
	secret := "test-secret-for-jwt-issuance-only-do-not-use"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}
	erasedUserID := uuid.New()
	revokedJTI := uuid.NewString()

	previous := revocationCheckerFromEnv
	revocationCheckerFromEnv = func() sharedmw.RevocationChecker {
		return testRevocationChecker{
			revokedJTIs:  map[string]bool{revokedJTI: true},
			revokedUsers: map[uuid.UUID]bool{erasedUserID: true},
		}
	}
	t.Cleanup(func() { revocationCheckerFromEnv = previous })

	mintToken := func(userID uuid.UUID, jti string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": userID.String(),
			"email":   "platform-admin@test.com",
			"role":    "super_admin",
			"type":    "access",
			"iss":     "crypto-inventory-auth",
			"aud":     "crypto-inventory",
			"sub":     userID.String(),
			"jti":     jti,
			"iat":     time.Now().Unix(),
			"nbf":     time.Now().Add(-time.Minute).Unix(),
			"exp":     time.Now().Add(time.Hour).Unix(),
		})
		signed, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("SignedString: %v", err)
		}
		return signed
	}

	cases := []struct {
		name       string
		userID     uuid.UUID
		jti        string
		wantStatus int
	}{
		{
			name:       "revoked jti rejected",
			userID:     uuid.New(),
			jti:        revokedJTI,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "revoked user rejected",
			userID:     erasedUserID,
			jti:        uuid.NewString(),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "live token allowed",
			userID:     uuid.New(),
			jti:        uuid.NewString(),
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/activity-logs", RequireAuth(cfg), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/activity-logs", nil)
			req.Header.Set("Authorization", "Bearer "+mintToken(tc.userID, tc.jti))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestRequireAuth_SurfacesPATScopesForDownstreamRBAC(t *testing.T) {
	useLiveTenantState(t)
	gin.SetMode(gin.TestMode)
	secret := "test-secret-for-jwt-issuance-only-do-not-use"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}
	userID := uuid.New()
	tenantID := uuid.New()

	previous := revocationCheckerFromEnv
	revocationCheckerFromEnv = func() sharedmw.RevocationChecker { return nil }
	t.Cleanup(func() { revocationCheckerFromEnv = previous })

	mintToken := func(scopes []string) string {
		claims := jwt.MapClaims{
			"user_id":   userID.String(),
			"tenant_id": tenantID.String(),
			"email":     "tenant-admin@test.com",
			"role":      "tenant_admin",
			"type":      "access",
			"iss":       "crypto-inventory-auth",
			"aud":       "crypto-inventory",
			"sub":       userID.String(),
			"jti":       uuid.NewString(),
			"iat":       time.Now().Unix(),
			"nbf":       time.Now().Add(-time.Minute).Unix(),
			"exp":       time.Now().Add(time.Hour).Unix(),
		}
		if scopes != nil {
			claims["token_type"] = "pat"
			claims["scopes"] = scopes
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("SignedString: %v", err)
		}
		return signed
	}

	newRouter := func(requiredPermission string) *gin.Engine {
		r := gin.New()
		r.GET("/activity-logs", RequireAuth(cfg), func(c *gin.Context) {
			if !sharedmw.PermissionWithinTokenScope(c, requiredPermission) {
				c.JSON(http.StatusForbidden, gin.H{"error": "outside scope"})
				return
			}
			c.Status(http.StatusOK)
		})
		return r
	}

	cases := []struct {
		name               string
		scopes             []string
		requiredPermission string
		wantStatus         int
	}{
		{
			name:               "scoped PAT allows permission inside audit scope",
			scopes:             []string{"audit.read"},
			requiredPermission: rbac.PermissionAuditRead,
			wantStatus:         http.StatusOK,
		},
		{
			name:               "scoped PAT denies permission outside token scope",
			scopes:             []string{"assets.read"},
			requiredPermission: rbac.PermissionAuditRead,
			wantStatus:         http.StatusForbidden,
		},
		{
			name:               "normal unscoped session remains unchanged",
			scopes:             nil,
			requiredPermission: rbac.PermissionAuditManage,
			wantStatus:         http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/activity-logs", nil)
			req.Header.Set("Authorization", "Bearer "+mintToken(tc.scopes))
			w := httptest.NewRecorder()
			newRouter(tc.requiredPermission).ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// liveTenants reports every tenant usable.
type liveTenants struct{}

func (liveTenants) Check(context.Context, uuid.UUID) (string, bool, error) { return "", false, nil }

// useLiveTenantState makes RequireAuth treat every tenant as live for one
// test. These tests are not about tenant state, and the default resolution is
// NOT "no check": it builds the real checker from DATABASE_URL, which the
// nightly test-backend job sets. There the random tenant ids minted here have
// no tenants row and are refused 403 tenant_deleted ( item 2) — which a
// status-only assertion can even mistake for the gate under test.
// tenant_state_integration_test.go covers the real resolution.
func useLiveTenantState(t *testing.T) {
	t.Helper()
	previous := tenantStateCheckerFromEnv
	tenantStateCheckerFromEnv = func() sharedmw.TenantStateChecker { return liveTenants{} }
	t.Cleanup(func() { tenantStateCheckerFromEnv = previous })
}
