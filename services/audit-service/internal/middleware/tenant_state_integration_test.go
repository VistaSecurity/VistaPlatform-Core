package middleware

// DB-integration coverage for tenant suspension on audit-service's OWN JWT
// middleware (RC-4 /). RequireAuth(cfg) takes no database handle, so the
// check has to resolve from DATABASE_URL exactly as in a pod — this test sets
// that variable and builds RequireAuth the way cmd/main.go does, with no stub.
// Mutation: delete the EnforceTenantState call in RequireAuth (or resolve the
// checker to nil) and the suspended case answers 200.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RequireAuth_RefusesSuspendedTenant(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	t.Setenv("DATABASE_URL", os.Getenv("TEST_DATABASE_URL"))
	t.Setenv("TENANT_STATE_CACHE_TTL", "0s")

	gin.SetMode(gin.TestMode)
	const signingKeyForTest = "test-secret-for-jwt-issuance-only-do-not-use"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: signingKeyForTest}}
	r := gin.New()
	r.GET("/activity-logs", RequireAuth(cfg), func(c *gin.Context) { c.Status(http.StatusOK) })

	tenantID := testdb.NewTenant(t, owner)
	userID := uuid.New()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID.String(), "tenant_id": tenantID.String(),
		"email": "u@example.test", "role": "viewer", "type": "access",
		"iss": "crypto-inventory-auth", "aud": "crypto-inventory", "sub": userID.String(),
		"jti": uuid.NewString(), "iat": time.Now().Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(signingKeyForTest))
	if err != nil {
		t.Fatal(err)
	}
	get := func() (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/activity-logs", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body.Code
	}

	if code, _ := get(); code != http.StatusOK {
		t.Fatalf("live tenant = %d, want 200", code)
	}
	if _, err := owner.Exec(`UPDATE tenants SET payment_status = 'canceled' WHERE id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	if code, c := get(); code != http.StatusForbidden || c != "tenant_suspended" {
		t.Fatalf("canceled tenant = %d %q, want 403 tenant_suspended", code, c)
	}
}
