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

// platformRequest drives one request through RequirePermission with a PLATFORM
// identity (no tenant) on the context, as RequireAuth sets it for an operator.
func platformRequest(t *testing.T, db *sql.DB, userID uuid.UUID, role, permission string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/gated", func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("userType", UserTypePlatform)
		c.Set("role", role)
		c.Next()
	}, RequirePermission(db, permission), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/gated", nil))
	return w
}

// TestRequirePermission_PlatformGrantDecidesAccess pins the platform half: an
// operator's access is platform_user_has_permission() on the mapped PLATFORM
// permission, never the role name on the token. Under the old role switch the
// first row passed and the second row was refused regardless of the database.
func TestRequirePermission_PlatformGrantDecidesAccess(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		permission string
		wantAsked  string
		granted    bool
		wantStatus int
	}{
		{"platform_admin_name_without_grant_is_refused", "platform_admin", rbac.PermissionAuditManage, rbac.PermissionPlatformAuditManage, false, http.StatusForbidden},
		{"super_admin_name_without_grant_is_refused", "super_admin", rbac.PermissionAuditRead, rbac.PermissionPlatformAudit, false, http.StatusForbidden},
		{"support_agent_with_platform_audit_reads", "support_agent", rbac.PermissionAuditRead, rbac.PermissionPlatformAudit, true, http.StatusOK},
		{"custom_role_with_audit_manage_writes", "retention_steward", rbac.PermissionAuditManage, rbac.PermissionPlatformAuditManage, true, http.StatusOK},
		{"custom_role_without_audit_manage_is_refused", "retention_steward", rbac.PermissionAuditManage, rbac.PermissionPlatformAuditManage, false, http.StatusForbidden},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()

			userID := uuid.New()
			mock.ExpectQuery(`platform_user_has_permission`).
				WithArgs(userID, tc.wantAsked).
				WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(tc.granted))

			w := platformRequest(t, db, userID, tc.role, tc.permission)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the platform check did not ask for %s: %v", tc.wantAsked, err)
			}
		})
	}
}

// An audit permission with no platform counterpart refuses operators outright
// and never touches the database — the fail-closed default for a permission
// added without deciding who on the platform side may use it.
func TestRequirePermission_UnmappedPermissionRefusesPlatform(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	w := platformRequest(t, db, uuid.New(), "super_admin", "audit.export")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (body: %s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmapped permission queried the database: %v", err)
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
