package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	rtmiddleware "github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/service"
	"github.com/vistasecurity/vistaplatform/shared/costing"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// TestRecordResourceMetrics regression-tests the tenant-binding fix from P0-7
// (commit cd13068) on POST /api/v1/resource-tracker/metrics. The handler
// MUST take its trusted tenant from the HMAC-signed X-Tenant-ID header
// rather than from anywhere in the request body, and MUST reject body
// tenant_ids that contradict the header. Filed as.
//
// Each subtest builds the handler behind its real RequireInternalAuth
// middleware so the HMAC path (test 4) gets exercised end-to-end.
// `awsCostEnabled=false` and a TenantExists=false result let us drive
// the happy path through the service without mocking the full insert
// chain — the tenant_id binding is verified by sqlmock's WithArgs on
// the TenantExists query.

const testInternalSecret = "test-internal-auth-secret-do-not-use"

func newTestHandler(t *testing.T) (*ResourceHandlers, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}

	log := logrus.New()
	log.SetLevel(logrus.PanicLevel) // keep test output clean

	// Single sqlmock connection backs both the RLS-scoped (db) and the
	// cross-tenant bypass (bypassDB) handles; mock expectations are matched by
	// SQL text regardless of which handle issues them.
	repo := repository.NewResourceRepository(db, db)
	awsRepo := repository.NewAWSCostRepository(db, db, log)
	svc := service.NewResourceService(repo, awsRepo, nil, false, log)
	h := NewResourceHandlers(svc, nil, log)

	return h, mock, func() { _ = db.Close() }
}

func newTestRouter(h *ResourceHandlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	internal := r.Group("/api/v1/resource-tracker")
	internal.Use(rtmiddleware.RequireInternalAuth(testInternalSecret))
	internal.POST("/metrics", h.RecordResourceMetrics)
	return r
}

// signedRequest builds + HMAC-signs a POST /metrics request. tenantHeader
// is the value placed in X-Tenant-ID (and bound into the signature).
func signedRequest(t *testing.T, body any, tenantHeader string) *http.Request {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resource-tracker/metrics", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	if tenantHeader != "" {
		req.Header.Set("X-Tenant-ID", tenantHeader)
	}
	signer := serviceauth.NewSigner(testInternalSecret)
	signer.SignRequest(req)
	return req
}

// =============================================================================
// 1. Missing X-Tenant-ID → 400
// =============================================================================

func TestRecordResourceMetrics_MissingTenantHeader(t *testing.T) {
	h, mock, cleanup := newTestHandler(t)
	defer cleanup()
	r := newTestRouter(h)

	body := models.ResourceMetricsRequest{APICalls: costing.Int64(5)}
	// signedRequest with empty header to skip the X-Tenant-ID header
	// but still produce a valid HMAC for the no-tenant message variant.
	req := signedRequest(t, body, "")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

// =============================================================================
// 2. Malformed X-Tenant-ID → 400
// =============================================================================

func TestRecordResourceMetrics_MalformedTenantHeader(t *testing.T) {
	h, mock, cleanup := newTestHandler(t)
	defer cleanup()
	r := newTestRouter(h)

	body := models.ResourceMetricsRequest{APICalls: costing.Int64(5)}
	req := signedRequest(t, body, "not-a-uuid")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

// =============================================================================
// 3. Body tenant_id contradicts signed header → 400
// =============================================================================

func TestRecordResourceMetrics_BodyTenantContradictsHeader(t *testing.T) {
	h, mock, cleanup := newTestHandler(t)
	defer cleanup()
	r := newTestRouter(h)

	headerTenant := uuid.New()
	bodyTenant := uuid.New() // intentionally different

	body := models.ResourceMetricsRequest{
		TenantID: bodyTenant,
		APICalls: costing.Int64(5),
	}
	req := signedRequest(t, body, headerTenant.String())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

// =============================================================================
// 4. Invalid HMAC → 401 (middleware rejection, handler never reached)
// =============================================================================

func TestRecordResourceMetrics_InvalidHMACRejectedByMiddleware(t *testing.T) {
	h, mock, cleanup := newTestHandler(t)
	defer cleanup()
	r := newTestRouter(h)

	body := models.ResourceMetricsRequest{APICalls: costing.Int64(5)}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resource-tracker/metrics", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", uuid.New().String())

	// Sign with the WRONG secret — middleware must reject.
	wrongSigner := serviceauth.NewSigner("not-the-real-secret")
	wrongSigner.SignRequest(req)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

// =============================================================================
// 5. Valid signed call → 200 + req.TenantID bound to header value
// =============================================================================

func TestRecordResourceMetrics_ValidSignedCallBindsHeaderTenant(t *testing.T) {
	h, mock, cleanup := newTestHandler(t)
	defer cleanup()
	r := newTestRouter(h)

	headerTenant := uuid.New()

	// Drive the service through TenantExists only — when this returns
	// false the service early-returns nil without further DB work.
	// Asserting WithArgs(headerTenant) confirms the handler bound the
	// tenant from the signed header, not from the body (which is empty).
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM tenants WHERE id = \$1 AND deleted_at IS NULL\)`).
		WithArgs(headerTenant).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	body := models.ResourceMetricsRequest{APICalls: costing.Int64(42)}
	req := signedRequest(t, body, headerTenant.String())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("ExpectationsWereMet: %v", err)
	}
}

// =============================================================================
// GetAllTenantsResourceUsage pagination — total/total_pages must reflect the
// full match count, not the sliced current page (regression for the bug where
// `total` was read from the already-sliced `summaries`, pinning total_pages=1
// and breaking admin-ui multi-page navigation).
// =============================================================================

// newAllTenantsRouter wires GET /api/v1/resource-tracker/tenants behind a
// middleware that marks the call internal, so the handler's auth gate passes
// and we exercise only the pagination block.
func newAllTenantsRouter(h *ResourceHandlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/resource-tracker")
	g.Use(func(c *gin.Context) {
		c.Set("isInternalCall", true)
		c.Next()
	})
	g.GET("/tenants", h.GetAllTenantsResourceUsage)
	return r
}

// expectAllTenantsQuery mocks the main summaries query to return `n` tenant
// rows. The per-row cost/resource trend sub-queries are intentionally left
// unmocked — the handler ignores their errors (costTrend, _ := ...), so they
// resolve to empty trends without affecting the pagination math under test.
func expectAllTenantsQuery(mock sqlmock.Sqlmock, n int) {
	// No total_cost_usd column: cost is derived at read time from these
	// aggregates through shared/costing rather than read back from the stored
	// per-sample column.
	cols := []string{
		"tenant_id", "tenant_name", "total_api_calls", "total_db_queries",
		"avg_memory_mb", "avg_cpu_percent", "mean_storage_mb",
		"total_network_bytes",
	}
	rows := sqlmock.NewRows(cols)
	for i := 0; i < n; i++ {
		rows.AddRow(uuid.New(), "tenant", int64(1), int64(1), 1.0, 1.0, 1.0, int64(1))
	}
	mock.ExpectQuery("FROM tenants t").WillReturnRows(rows)
}

func TestGetAllTenantsResourceUsage_PaginationTotalsReflectFullCount(t *testing.T) {
	h, mock, cleanup := newTestHandler(t)
	defer cleanup()
	r := newAllTenantsRouter(h)

	// 25 total tenants, page 1, default limit 20 → page holds 20, but the
	// grand totals must report all 25 across 2 pages.
	expectAllTenantsQuery(mock, 25)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resource-tracker/tenants?page=1&limit=20", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Tenants    []json.RawMessage `json:"tenants"`
		Pagination struct {
			Page       int `json:"page"`
			Limit      int `json:"limit"`
			Total      int `json:"total"`
			TotalPages int `json:"total_pages"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if got := len(resp.Tenants); got != 20 {
		t.Errorf("page slice: expected 20 tenants, got %d", got)
	}
	if resp.Pagination.Total != 25 {
		t.Errorf("pagination.total: expected full count 25, got %d", resp.Pagination.Total)
	}
	if resp.Pagination.TotalPages != 2 {
		t.Errorf("pagination.total_pages: expected 2, got %d", resp.Pagination.TotalPages)
	}
}

// Bonus: matching body tenant_id is accepted (defense-in-depth assertion
// in the handler should not reject when body and header agree).
func TestRecordResourceMetrics_MatchingBodyTenantAccepted(t *testing.T) {
	h, mock, cleanup := newTestHandler(t)
	defer cleanup()
	r := newTestRouter(h)

	tenant := uuid.New()
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM tenants WHERE id = \$1 AND deleted_at IS NULL\)`).
		WithArgs(tenant).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	body := models.ResourceMetricsRequest{
		TenantID: tenant, // same as header — should be accepted
		APICalls: costing.Int64(7),
	}
	req := signedRequest(t, body, tenant.String())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("ExpectationsWereMet: %v", err)
	}
}
