package api

// DB-integration coverage for the cross-tenant operator endpoints. These
// routes used to trust the role-name claim after checking platform identity;
// a custom platform role therefore could not be granted access, while a user
// lacking the permission could pass by claiming platform_admin. Drive the real
// router and real platform_user_has_permission() in both directions.

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const tenantSecurityGateSecret = "tenant-security-gate-test"

func TestIntegration_TenantSecurityRoutes_PlatformPermissionGates(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	bypass := testdb.ConnectAsBypassRole(t, owner)
	target := testdb.NewTenant(t, owner)

	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: tenantSecurityGateSecret, JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rdb.Close() })
	router := SetupRouter(cfg, app, bypass, rdb, nil, EditionHooks{})
	prefix := "/api/v1/auth-service/admin/tenants/" + target.String()
	routes := []testdb.GatedRoute{
		{Method: http.MethodGet, Path: prefix + "/security-summary", Permission: sharedrbac.PermissionPlatformSecurity},
		{Method: http.MethodGet, Path: prefix + "/ui-config", Permission: sharedrbac.PermissionPlatformSettings},
		{Method: http.MethodPut, Path: prefix + "/ui-config", Permission: sharedrbac.PermissionPlatformSettings},
	}
	sign := func(user uuid.UUID, role string) string {
		return testdb.SignPlatformToken(t, tenantSecurityGateSecret, user, role)
	}
	testdb.CheckPlatformGates(t, owner, router, sign, routes)
}
