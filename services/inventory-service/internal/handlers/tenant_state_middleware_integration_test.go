package handlers

// DB-integration coverage for tenant suspension on inventory-service's OWN JWT
// middleware (RC-4 /). inventory-service does not use shared
// RequireJWTAuth, so the shared tests cannot vouch for it; this drives
// JWTMiddleware exactly as cmd/main.go builds it — JWTMiddleware(cfg, db) over
// the service's pool — against a real tenants row. Mutation: delete the
// EnforceTenantState call in JWTMiddleware and the suspended case answers 200.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_JWTMiddleware_RefusesSuspendedAndDeletedTenants(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	t.Setenv("TENANT_STATE_CACHE_TTL", "0s") // observe each state change on the next request

	gin.SetMode(gin.TestMode)
	const signingKeyForTest = "test-secret-for-jwt-issuance-only-do-not-use"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: signingKeyForTest}}
	r := gin.New()
	r.GET("/assets", JWTMiddleware(cfg, &database.DB{DB: sqlx.NewDb(app, "postgres")}), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	tenantID := testdb.NewTenant(t, owner)
	mint := func(tokenType string) string {
		userID := uuid.New()
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &JWTClaims{
			UserID: userID, TenantID: tenantID, Email: "u@example.test", Role: "viewer", Type: tokenType,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID.String(),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				Issuer:    "crypto-inventory-auth",
				Audience:  jwt.ClaimStrings{"crypto-inventory"},
				ID:        uuid.NewString(),
			},
		}).SignedString([]byte(signingKeyForTest))
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	get := func(token string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/assets", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body.Code
	}

	access := mint("access")
	if code, _ := get(access); code != http.StatusOK {
		t.Fatalf("live tenant = %d, want 200", code)
	}

	if _, err := owner.Exec(`UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	if code, c := get(access); code != http.StatusForbidden || c != "tenant_suspended" {
		t.Fatalf("suspended tenant = %d %q, want 403 tenant_suspended", code, c)
	}
	// Platform support may still look at a suspended tenant.
	if code, _ := get(mint("impersonation")); code != http.StatusOK {
		t.Fatalf("impersonation of a suspended tenant = %d, want 200", code)
	}

	if _, err := owner.Exec(`UPDATE tenants SET payment_status = 'active', deleted_at = NOW() WHERE id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	if code, c := get(access); code != http.StatusForbidden || c != "tenant_deleted" {
		t.Fatalf("soft-deleted tenant = %d %q, want 403 tenant_deleted", code, c)
	}
}
