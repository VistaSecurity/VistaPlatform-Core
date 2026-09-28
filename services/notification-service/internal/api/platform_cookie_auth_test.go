package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestPlatformRoutes_IgnoreTenantCookie drives the REAL router: the /platform
// groups must authenticate from the platform_* cookie pair only.
//
// admin-ui and web-ui share a parent COOKIE_DOMAIN, so admin-ui's requests also
// carry the tenant access_token. With the tenant-first RequireAuth, that tenant
// identity won: once its tenant was deleted, the bell poll answered 403
// tenant_deleted, admin-ui treated it as "session over", bounced to /login,
// found its platform session alive, bounced back — a reload loop several times
// a second. A tenant-only cookie must now be a clean 401.
func TestPlatformRoutes_IgnoreTenantCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "notification-platform-cookie-test-secret"
	t.Setenv("DATABASE_URL", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")

	// Never reached for a refused request; an unreachable DB makes any request
	// that DOES get past authentication fail in RBAC, not with a 401.
	db, err := sqlx.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	srv := &Server{config: &config.Config{JWTSecret: secret}, db: db}
	router := srv.SetupRouter()
	token := testdb.SignPlatformToken(t, secret, uuid.New(), "platform_admin")

	paths := []string{
		"/api/v1/notification-service/platform/notifications",
		"/api/v1/notification-service/platform/channels",
	}
	for _, path := range paths {
		t.Run("tenant cookie only/"+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("tenant access_token on a platform route: got %d, want 401 (body: %s)", w.Code, w.Body.String())
			}
		})
		t.Run("platform cookie/"+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: token})
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code == http.StatusUnauthorized {
				t.Fatalf("platform_access_token was refused authentication (body: %s)", w.Body.String())
			}
		})
	}
}
