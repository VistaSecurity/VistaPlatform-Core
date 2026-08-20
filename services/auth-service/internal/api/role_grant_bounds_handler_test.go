package api

// Fast (no-database) wiring coverage for the grant ceiling on the two
// user-mutation handlers, so the PR gate — which runs `make test-unit` and
// provisions no Postgres — fails if the guard is lifted out of a handler. The
// full four-site, both-directions coverage lives in
// role_grant_bounds_integration_test.go.
//
// These drive the real gin handler over sqlmock, mirroring the query sequence
// the ceiling issues. A handler that skips the ceiling runs on into queries
// these mocks do not expect and cannot answer 403, which is exactly the
// mutation signal wanted.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// expectCeilingDenial queues the ceiling's query sequence for roleName and
// answers it with "the role grants deniedPermission, the actor holds nothing".
func expectCeilingDenial(mock sqlmock.Sqlmock, tenantID, actorID uuid.UUID, roleName, deniedPermission string) {
	roleID := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT id FROM tenant_roles`).
		WithArgs(tenantID, roleName).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(roleID))
	// The ceiling resolves the role's owning tenant before reading its grants,
	// so a role id from another tenant can never reach the comparison.
	mock.ExpectQuery(`SELECT tenant_id FROM tenant_roles`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectQuery(`SELECT p\.id, p\.name`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(uuid.New(), deniedPermission))
	// The named role-delegation lookup. Callers pass a roleName that is not a
	// delegation grantee, so nothing is exempted and the ceiling below is the
	// unmodified one.
	mock.ExpectQuery(`SELECT name, is_system_role FROM tenant_roles`).
		WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "is_system_role"}).AddRow(roleName, true))
	mock.ExpectQuery(`SELECT DISTINCT p\.id`).
		WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectRollback()
}

func assertForbiddenPermissionNotHeld(t *testing.T, code int, body, site string) {
	t.Helper()
	if code != http.StatusForbidden {
		t.Fatalf("%s: status = %d, want 403 — the grant ceiling is not wired into this handler; body=%s", site, code, body)
	}
	if !strings.Contains(body, "permission_not_held") {
		t.Fatalf("%s: body = %s, want the permission_not_held refusal", site, body)
	}
}

// Pins users.go's CreateUser -> ensureRoleGrantableByName call site.
func TestCreateUser_403WhenRoleExceedsActorGrants(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.MustParse(aTenantID)
	actorID := uuid.MustParse(aUserID)
	expectCeilingDenial(mock, tenantID, actorID, "tenant_admin", "billing.read")

	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", aTenantID)
		c.Set("userID", aUserID)
		c.Next()
	})
	grp.POST("/users", CreateUser(db, db, nil))

	w := do(r, http.MethodPost, "/api/v1/auth-service/users",
		strings.NewReader(`{"email":"esc@example.com","password":"Str0ng!Passw0rd#2026","first_name":"E","last_name":"S","role":"tenant_admin"}`))

	assertForbiddenPermissionNotHeld(t, w.Code, w.Body.String(), "CreateUser")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

// Pins users.go's UpdateUser -> assignUserRole ceiling (UpdateUser has no
// separate pre-check; validateRoleGrantable inside assignUserRole is its only
// bound).
func TestUpdateUser_403WhenRoleExceedsActorGrants(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.MustParse(aTenantID)
	actorID := uuid.MustParse(aUserID)
	targetID := uuid.MustParse(aTargetUserID)

	// 1. verify the target belongs to the tenant
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT is_active FROM users`).
		WithArgs(targetID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"is_active"}).AddRow(true))
	mock.ExpectCommit()
	// 2. read the target's existing role
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT tr\.name`).
		WithArgs(targetID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("viewer"))
	mock.ExpectCommit()
	// 3. the ceiling, inside assignUserRole
	expectCeilingDenial(mock, tenantID, actorID, "tenant_admin", "billing.read")

	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", aTenantID)
		c.Set("userID", aUserID)
		c.Next()
	})
	grp.PUT("/users/:id", UpdateUser(db))

	w := do(r, http.MethodPut, "/api/v1/auth-service/users/"+aTargetUserID, strings.NewReader(`{"role":"tenant_admin"}`))

	assertForbiddenPermissionNotHeld(t, w.Code, w.Body.String(), "UpdateUser")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}
