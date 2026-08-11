package middleware

// Gate tests for RequirePermission — the tenant-permission middleware the
// router hands billing.read / billing.update (and every other tenant
// permission) to. Added with (billing.* enforcement): asserts the
// middleware 403s a caller whose role lacks the permission and passes a
// caller whose role grants it, driving the real RBAC service over sqlmock
// (the CheckPermission query runs inside WithTenantTx, so the mock mirrors
// the Begin / set_tenant_context / query / Commit prologue).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	rbacsvc "github.com/vistasecurity/vistaplatform/auth-service/internal/rbac"
)

const (
	permTestUserID   = "11111111-1111-1111-1111-111111111111"
	permTestTenantID = "22222222-2222-2222-2222-222222222222"
)

// newPermissionEngine builds a minimal chain shaped like the router's billing
// group: identity middleware (stands in for RequireAuth) → RequirePermission →
// terminal handler.
func newPermissionEngine(svc *rbacsvc.RBACService, permission string, setIdentity bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/billing/usage/current",
		func(c *gin.Context) {
			if setIdentity {
				c.Set("userID", permTestUserID)
				c.Set("tenantID", permTestTenantID)
			}
			c.Next()
		},
		RequirePermission(svc, permission),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)
	return r
}

// expectPermissionCheck arms the mock for one CheckPermission round trip
// returning `granted`.
func expectPermissionCheck(mock sqlmock.Sqlmock, granted bool) {
	tenantID := uuid.MustParse(permTestTenantID)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) > 0`).
		WithArgs(uuid.MustParse(permTestUserID), tenantID, "billing.read").
		WillReturnRows(sqlmock.NewRows([]string{"has_permission"}).AddRow(granted))
	mock.ExpectCommit()
}

func doPermissionRequest(t *testing.T, eng *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/usage/current", nil)
	eng.ServeHTTP(w, req)
	return w
}

func TestRequirePermission_403_WithoutPermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	expectPermissionCheck(mock, false)

	eng := newPermissionEngine(rbacsvc.NewRBACService(db), "billing.read", true)
	w := doPermissionRequest(t, eng)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "billing.read") {
		t.Fatalf("403 body should name the required permission; got %s", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestRequirePermission_200_WithPermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	expectPermissionCheck(mock, true)

	eng := newPermissionEngine(rbacsvc.NewRBACService(db), "billing.read", true)
	w := doPermissionRequest(t, eng)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestRequirePermission_401_WithoutIdentity(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// No userID/tenantID in context (unauthenticated) → 401 before any DB hit.
	eng := newPermissionEngine(rbacsvc.NewRBACService(db), "billing.read", false)
	w := doPermissionRequest(t, eng)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}
