package handlers

// Tests for the optional operator-scope tenant_id filter on the platform-admin
// cross-tenant sensors list (GET /admin/sensors), part of (move the
// operator tenant-scope from client-side filtering to server-side).
//
// Unlike device-interrogation-service's analogous /admin/jobs (which reaches its
// data through a jobStore interface a stub can capture), GetAdminSensors issues
// raw SQL through h.db directly. So instead of a stub store we drive it with
// go-sqlmock and assert on the SQL + bound args the handler actually sends:
//   - with ?tenant_id=<uuid> the query gains `AND s.tenant_id = $1` and binds it,
//   - without it the roll-up stays cross-tenant (no tenant arg / no extra clause),
//   - a malformed tenant_id is rejected with 400 before the DB is ever touched.

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// adminSensorRows returns an empty (but correctly-shaped) result set for the
// GetAdminSensors SELECT, so the handler's row loop runs without scanning.
func adminSensorRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "tenant_id", "name", "slug",
		"name", "description", "sensor_type", "platform", "version", "profile", "status",
		"air_gapped", "network_interfaces", "available_interfaces", "tags", "ip_address",
		"last_heartbeat", "created_at", "updated_at",
	})
}

func newAdminSensorsRouter(h *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/sensors", h.GetAdminSensors)
	return r
}

// The tenant_id query param on the cross-tenant admin list must flow through to
// the SQL (server-side narrowing) — not by shipping every tenant's rows to the
// client and filtering in the browser.
func TestGetAdminSensors_TenantScopeFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	h := &Handler{db: db, bypassDB: db}
	eng := newAdminSensorsRouter(h)

	aUUID := uuid.New().String()

	// The scoped path must add the tenant filter AND bind the tenant id as an arg.
	mock.ExpectQuery(regexp.QuoteMeta("AND s.tenant_id = $1")).
		WithArgs(aUUID).
		WillReturnRows(adminSensorRows())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/sensors?tenant_id="+aUUID, nil)
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for scoped list, got %d (%s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("scoped query expectation not met: %v", err)
	}
}

// Omitting tenant_id leaves the roll-up cross-tenant: no tenant arg is bound and
// the tenant filter clause is absent from the SQL.
func TestGetAdminSensors_NoTenantScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	h := &Handler{db: db, bypassDB: db}
	eng := newAdminSensorsRouter(h)

	// WithArgs() (zero args) is the load-bearing assertion: if the handler had
	// appended `AND s.tenant_id = $1` it would bind one arg and this expectation
	// would fail. The query regex just anchors on the stable FROM clause.
	// (Go's RE2 has no negative lookahead, so we prove "no filter" via the args.)
	mock.ExpectQuery(regexp.QuoteMeta("FROM sensors s")).
		WithArgs().
		WillReturnRows(adminSensorRows())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/sensors", nil)
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unscoped list, got %d (%s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unscoped query expectation not met: %v", err)
	}
}

// A malformed tenant_id is rejected with 400 before the DB is queried (so a bad
// value can't surface as a 500 from the typed tenant_id column).
func TestGetAdminSensors_InvalidTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	h := &Handler{db: db, bypassDB: db}
	eng := newAdminSensorsRouter(h)

	// No ExpectQuery: the DB must not be touched.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/sensors?tenant_id=not-a-uuid", nil)
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed tenant_id, got %d (%s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("DB should not be queried for a malformed tenant_id: %v", err)
	}
}
