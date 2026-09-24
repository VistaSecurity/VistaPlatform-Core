package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

// Regression coverage for: inventory-service has its own local JWT
// middleware (not shared/middleware.RequireJWTAuth), so it needs its own
// pwd_change_required gate mirroring auth-service and audit-service.
func TestJWTMiddleware_PasswordChangeRequiredGate(t *testing.T) {
	useLiveTenantState(t)
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

func TestJWTMiddleware_RevokedTokensRejected(t *testing.T) {
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
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &JWTClaims{
			UserID:   userID,
			TenantID: uuid.Nil,
			Email:    "platform-admin@test.com",
			Role:     "super_admin",
			Type:     "access",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID.String(),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				Issuer:    "crypto-inventory-auth",
				Audience:  jwt.ClaimStrings{"crypto-inventory"},
				ID:        jti,
			},
		})
		signed, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("SignedString: %v", err)
		}
		return signed
	}

	r := gin.New()
	r.GET("/algorithms", JWTMiddleware(cfg, nil), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

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
			req := httptest.NewRequest(http.MethodGet, "/algorithms", nil)
			req.Header.Set("Authorization", "Bearer "+mintToken(tc.userID, tc.jti))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestJWTMiddleware_SetsUserTypeFromTenantClaim(t *testing.T) {
	useLiveTenantState(t)
	gin.SetMode(gin.TestMode)
	secret := "test-secret-for-jwt-issuance-only-do-not-use"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}
	userID := uuid.New()

	mintToken := func(tenantID uuid.UUID) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &JWTClaims{
			UserID:   userID,
			TenantID: tenantID,
			Email:    "user@test.com",
			Role:     "platform_admin",
			Type:     "access",
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

	for _, tc := range []struct {
		name       string
		tenantID   uuid.UUID
		wantType   string
		wantStatus int
	}{
		{"platform token", uuid.Nil, sharedmw.UserTypePlatform, http.StatusOK},
		{"tenant token", uuid.New(), sharedmw.UserTypeTenant, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/algorithms", JWTMiddleware(cfg, nil), func(c *gin.Context) {
				if got := c.GetString(sharedmw.CtxKeyUserType); got != tc.wantType {
					t.Fatalf("userType = %q, want %q", got, tc.wantType)
				}
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/algorithms", nil)
			req.Header.Set("Authorization", "Bearer "+mintToken(tc.tenantID))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// liveTenants reports every tenant usable.
type liveTenants struct{}

func (liveTenants) Check(context.Context, uuid.UUID) (string, bool, error) { return "", false, nil }

// useLiveTenantState makes JWTMiddleware treat every tenant as live for one
// test. These tests pass a nil pool, and with no pool the middleware resolves
// the check from DATABASE_URL — which the nightly test-backend job sets. There
// the random tenant ids minted here have no tenants row and are refused 403
// tenant_deleted ( item 2). tenant_state_middleware_integration_test.go
// covers the real check.
func useLiveTenantState(t *testing.T) {
	t.Helper()
	previous := tenantStateChecker
	tenantStateChecker = func(*database.DB) sharedmw.TenantStateChecker { return liveTenants{} }
	t.Cleanup(func() { tenantStateChecker = previous })
}
