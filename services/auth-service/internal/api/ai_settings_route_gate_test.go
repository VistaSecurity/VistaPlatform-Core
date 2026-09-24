package api

// The ROUTE gating of Settings → AI assistant, driven through the real
// SetupRouter.
//
// ai_settings_contract_test.go deliberately mounts the handlers with no
// middleware, so nothing in it can tell whether the router gates them at all.
// This file is the other half: delete either line in router.go and one of these
// goes red.
//
// The two halves are gated differently and that asymmetry is the thing under
// test:
//
//   - GET is authentication only. The body carries no credential and no
//     endpoint address; it is the answer to "why is there no written summary
//     here", which any member of the tenant can end up asking. Gating the
//     explanation on the permission to CHANGE the setting leaves everyone else
//     with a blank and no way to find out why.
//   - PUT is settings.update. The two switches are tenant configuration and
//     change what every capability does for everyone in the organization.
//
// Both polarities on the PUT, because a gate that refused everyone would look
// exactly like a working one from the refusal test alone.

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

// aiRouteRequest builds the REAL router over a sqlmock pool, mints an access
// token for userID/tenantID, and issues one request to /tenant/ai.
func aiRouteRequest(t *testing.T, db *sql.DB, method string, body io.Reader, userID, tenantID uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{JWTSecret: "test-secret-for-tenant-ai"}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	defer func() { _ = rdb.Close() }()

	router := SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})

	jwtService := auth.NewJWTService(cfg.JWTSecret, time.Hour, time.Hour)
	access, _, err := jwtService.GenerateTokens(userID, tenantID, "member@example.test", "viewer")
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	req := httptest.NewRequest(method, "/api/v1/auth-service/tenant/ai", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// expectSettingsUpdateCheck mocks RBACService.CheckPermission for
// settings.update, which runs inside WithTenantTx.
func expectSettingsUpdateCheck(mock sqlmock.Sqlmock, userID, tenantID uuid.UUID, granted bool) {
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM tenant_permissions`).
		WithArgs(userID, tenantID, "settings.update").
		WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(granted))
	mock.ExpectCommit()
}

// expectAIControlsRead mocks the RLS-scoped `config -> 'ai'` read.
func expectAIControlsRead(mock sqlmock.Sqlmock, tenantID uuid.UUID) {
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT config -> $2`)).
		WillReturnRows(sqlmock.NewRows([]string{"config"}).AddRow(nil))
	mock.ExpectCommit()
}

// TestTenantAIRoute_GetNeedsOnlyAuthentication.
//
// The mock queues the settings read and NOTHING else: if the route still
// carried RequirePermission, the permission query would run first, find no
// matching expectation, and the request would 500 instead of 200. That is what
// makes this a wiring assertion rather than a restatement of the handler test.
func TestTenantAIRoute_GetNeedsOnlyAuthentication(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	userID, tenantID := uuid.New(), uuid.New()
	expectLiveTenantState(mock, tenantID)
	expectAIControlsRead(mock, tenantID)

	w := aiRouteRequest(t, db, http.MethodGet, nil, userID, tenantID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — GET is authentication only; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"seams"`) {
		t.Fatalf("the response is not the status body: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestTenantAIRoute_GetRefusesAnUnauthenticatedCaller. The open read is open to
// the TENANT, not to the internet.
func TestTenantAIRoute_GetRefusesAnUnauthenticatedCaller(t *testing.T) {
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: "test-secret-for-tenant-ai"}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = rdb.Close() }()
	router := SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with no token; body=%s", w.Code, w.Body.String())
	}
}

// TestTenantAIRoute_PutRefusedWithoutSettingsUpdate is the wiring proof for the
// write: the request never reaches the handler (no settings read is mocked, so
// the handler would fail differently), and the refusal names the permission.
func TestTenantAIRoute_PutRefusedWithoutSettingsUpdate(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	userID, tenantID := uuid.New(), uuid.New()
	expectLiveTenantState(mock, tenantID)
	expectSettingsUpdateCheck(mock, userID, tenantID, false)

	w := aiRouteRequest(t, db, http.MethodPut,
		strings.NewReader(`{"assistant_disabled":true}`), userID, tenantID)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "settings.update") {
		t.Fatalf("403 body does not name the required permission: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations (did the middleware run?): %v", err)
	}
}

// The other polarity: with settings.update held the write goes through. Without
// this, a gate that refused everyone would pass the test above.
func TestTenantAIRoute_PutAllowedWithSettingsUpdate(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	userID, tenantID := uuid.New(), uuid.New()
	expectLiveTenantState(mock, tenantID)
	expectSettingsUpdateCheck(mock, userID, tenantID, true)
	expectAIControlsRead(mock, tenantID) // read-before-write
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO tenant_admin_settings`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE tenant_admin_settings`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := aiRouteRequest(t, db, http.MethodPut,
		strings.NewReader(`{"assistant_disabled":true}`), userID, tenantID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}
