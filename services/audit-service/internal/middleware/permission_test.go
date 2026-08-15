package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// The tenant half of RequirePermission now asks the database
// (user_has_permission → tenant_role_permissions) instead of switching on the
// role NAME. These tests pin both answers: a role WITHOUT the grant is
// refused, a role WITH it passes — and, critically, that the answer comes from
// the grant rather than from the role string, since security_admin's audit read
// access is exactly what a careless migration would have dropped.

// tenantRequest drives one request through RequirePermission with a tenant
// identity already on the context (what RequireAuth would have set).
func tenantRequest(t *testing.T, db *sql.DB, role, permission string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/gated", func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("userType", UserTypeTenant)
		c.Set("role", role)
		c.Next()
	}, RequirePermission(db, permission), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gated", nil))
	return w
}

func TestRequirePermission_TenantGrantDecidesAccess(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		permission string
		granted    bool
		wantStatus int
	}{
		{
			// A viewer holds audit.read but never audit.manage: the write gate
			// must refuse it.
			name: "viewer_without_audit_manage_is_forbidden", role: "viewer",
			permission: rbac.PermissionAuditManage, granted: false, wantStatus: http.StatusForbidden,
		},
		{
			name: "tenant_admin_with_audit_manage_passes", role: "tenant_admin",
			permission: rbac.PermissionAuditManage, granted: true, wantStatus: http.StatusOK,
		},
		{
			// The regression most likely to slip: security_admin held
			// audit.read under the old hardcoded switch and must still resolve
			// it from tenant_role_permissions after the migration. seed.sql and
			// assignRolePermissions grant it by name — see
			// auth-service's TestSecurityAdminNameGrantFilterKeepsAuditRead.
			name: "security_admin_keeps_audit_read", role: "security_admin",
			permission: rbac.PermissionAuditRead, granted: true, wantStatus: http.StatusOK,
		},
		{
			// The grant, not the role name, is what decides. A tenant_admin
			// whose grant row was revoked is refused — under the old switch
			// the role name alone let it through any audit.* route.
			name: "role_name_alone_does_not_grant", role: "tenant_admin",
			permission: rbac.PermissionAuditRead, granted: false, wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()

			mock.ExpectQuery("user_has_permission").
				WillReturnRows(sqlmock.NewRows([]string{"user_has_permission"}).AddRow(tc.granted))

			w := tenantRequest(t, db, tc.role, tc.permission)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the permission check never reached the database: %v", err)
			}
		})
	}
}

// TestRequirePermission_PlatformStaysRoleBased pins the other half: platform
// admins carry a no-tenant token, so there is no tenant_role_permissions row to
// resolve and the branch stays role-based. It must never touch the database —
// an expectation-free mock fails if it does.
func TestRequirePermission_PlatformStaysRoleBased(t *testing.T) {
	cases := []struct {
		role       string
		permission string
		wantStatus int
	}{
		{"super_admin", rbac.PermissionAuditManage, http.StatusOK},
		{"platform_admin", rbac.PermissionAuditManage, http.StatusOK},
		{"support_admin", rbac.PermissionAuditRead, http.StatusOK},
		{"support_admin", rbac.PermissionAuditManage, http.StatusForbidden},
		{"", rbac.PermissionAuditRead, http.StatusForbidden},
	}

	gin.SetMode(gin.TestMode)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.role+"_"+tc.permission, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()

			r := gin.New()
			r.GET("/gated", func(c *gin.Context) {
				c.Set("userID", uuid.New())
				c.Set("userType", UserTypePlatform)
				c.Set("role", tc.role)
				c.Next()
			}, RequirePermission(db, tc.permission), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gated", nil))
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("platform branch queried the database: %v", err)
			}
		})
	}
}

// TestRequirePermission_UnauthenticatedIsRejected keeps the fail-closed default:
// no userType on the context means RequireAuth did not run.
func TestRequirePermission_UnauthenticatedIsRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	r := gin.New()
	r.GET("/gated", RequirePermission(db, rbac.PermissionAuditRead), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gated", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
