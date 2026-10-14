package api

// POST /internal/resource-metrics is the ingest every metering service posts
// its API-call batches to (shared/middleware/resource-tracking) — moved here
// from resource-tracker-service by the retirement plan.
//
// Three properties, each pinned against the REAL SetupRouter so that deleting
// the wiring line in router.go goes red:
//
//  1. HMAC-only. An unsigned request is refused with 401 before the handler
//     runs (a request that reached the handler without a tenant header would
//     answer 400, and one with a header would touch the database, which the
//     mock would report as an unexpected call).
//  2. The tenant is the SIGNED header, and a body that names another tenant
//     is refused: the shared secret must not let one service bill another
//     tenant.
//  3. A signed, consistent request lands one RLS-scoped INSERT in
//     tenant_resource_usage, with unmeasured columns written as NULL.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const resourceMetricsPath = "/api/v1/auth-service/internal/resource-metrics"

func resourceMetricsRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	cfg := &config.Config{JWTSecret: "test-secret-for-resource-metrics"}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	router := SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})
	return router, mock, func() { _ = rdb.Close(); _ = db.Close() }
}

func postResourceMetrics(router *gin.Engine, body string, headerTenant string, sign bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, resourceMetricsPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if headerTenant != "" {
		req.Header.Set(serviceauth.HeaderTenantID, headerTenant)
	}
	if sign {
		serviceauth.NewSigner(gatesHMACSecret()).SignRequest(req)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestResourceMetricsRoute_UnsignedIs401(t *testing.T) {
	router, mock, cleanup := resourceMetricsRouter(t)
	defer cleanup()
	tenant := uuid.New()

	w := postResourceMetrics(router, `{"api_calls": 3}`, tenant.String(), false)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned POST: status %d, want 401 (RequireInternalOnly missing from the route?) body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database touched by a refused request: %v", err)
	}
}

func TestResourceMetricsRoute_BodyTenantMustMatchSignedHeader(t *testing.T) {
	router, mock, cleanup := resourceMetricsRouter(t)
	defer cleanup()
	signed, other := uuid.New(), uuid.New()

	w := postResourceMetrics(router, `{"tenant_id":"`+other.String()+`","api_calls": 3}`, signed.String(), true)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("contradicting body tenant: status %d, want 400 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "does not match") {
		t.Fatalf("refusal should name the mismatch, got %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database touched by a refused request: %v", err)
	}
}

func TestResourceMetricsRoute_SignedRequestInsertsOneRLSScopedRow(t *testing.T) {
	router, mock, cleanup := resourceMetricsRouter(t)
	defer cleanup()
	tenant := uuid.New()

	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM tenants`).
		WithArgs(tenant).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenant).WillReturnResult(sqlmock.NewResult(0, 0))
	// api_calls measured (7), everything else NOT measured → NULL, never 0.
	mock.ExpectExec(`INSERT INTO tenant_resource_usage`).
		WithArgs(sqlmock.AnyArg(), tenant, sqlmock.AnyArg(), int64(7), nil, nil, nil, nil, nil, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := postResourceMetrics(router, `{"api_calls": 7}`, tenant.String(), true)
	if w.Code != http.StatusOK {
		t.Fatalf("signed POST: status %d, want 200 body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected one RLS-scoped INSERT: %v", err)
	}
}

func TestResourceMetricsRoute_UnknownTenantIsDroppedNotStored(t *testing.T) {
	router, mock, cleanup := resourceMetricsRouter(t)
	defer cleanup()
	tenant := uuid.New()

	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM tenants`).
		WithArgs(tenant).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	w := postResourceMetrics(router, `{"api_calls": 7}`, tenant.String(), true)
	if w.Code != http.StatusOK {
		t.Fatalf("unknown tenant: status %d, want 200 (dropped, not an error the batcher retries) body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected database activity: %v", err)
	}
}

// Compile-time: the production store satisfies the seam the handler takes.
var _ resourceMetricsStore = (*resourceMetricsRepository)(nil)

// keep time imported for the store signature in case the seam grows.
var _ = time.Now
