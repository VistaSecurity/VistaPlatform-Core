package main

// #H5 — the /api/v1/discovery group carried RequireAuth + RequireTenant +
// trial_lock and NO permission check at all, so any authenticated tenant user
// (a read-only `viewer` included) could start scans, approve discovered assets
// into inventory and raise their own scan rate limits.
//
// This guards the WIRING, not the middleware. It drives the REAL router that
// main() builds — registerDiscoveryRoutes — over a sqlmock database, so
// deleting a RequireTenantPermission line from main.go fails these tests.
// A test that exercised RequireTenantPermission in isolation would stay green
// through exactly that deletion, which is the trap CLAUDE.md names.
//
// Both polarities are covered:
//
//   - refused: the permission check runs, returns false, the request gets 403
//     naming the permission, and the handler is never reached.
//   - allowed: the same route with the permission HELD passes the gate and
//     reaches the handler. Without this, a gate that refused everyone — the
//     same bug pointed the other way — would look correct.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
)

const gateTestJWTSecret = "test-secret-for-discovery-route-gate"

// mintToken builds the tenant access token the shared JWT middleware accepts.
func mintToken(t *testing.T, userID, tenantID uuid.UUID, role string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"user_id":   userID.String(),
		"tenant_id": tenantID.String(),
		"email":     "member@example.test",
		"role":      role,
		"type":      "access",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(gateTestJWTSecret))
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return signed
}

// gateRouter builds the REAL discovery router over a sqlmock DB.
func gateRouter(t *testing.T, db *sql.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	sx := sqlx.NewDb(db, "postgres")
	h := handlers.NewDiscoveryHandler(
		services.NewDiscoveryService(sx, sx),
		services.NewRateLimiter(sx),
		nil,
		nil,
	)
	router := gin.New()
	// Production builds this router with gin.Default(), which includes
	// Recovery. Keep it here so a handler reached WITHOUT its collaborators
	// wired (the "permission held" polarity below) yields a 500 rather than
	// taking the test process down — a 500 is still proof the gate was passed.
	router.Use(gin.Recovery())
	registerDiscoveryRoutes(router, h, db, gateTestJWTSecret)
	return router
}

// expectPermissionCheck mocks RBACService.CheckPermission — a single
// user_has_permission($user,$tenant,$permission) call. WithArgs pins the
// PERMISSION, so a route re-gated on the wrong one fails here rather than
// passing silently.
func expectPermissionCheck(mock sqlmock.Sqlmock, userID, tenantID uuid.UUID, permission string, granted bool) {
	mock.ExpectQuery(`user_has_permission`).
		WithArgs(userID, tenantID, permission).
		WillReturnRows(sqlmock.NewRows([]string{"user_has_permission"}).AddRow(granted))
}

func gateRequest(t *testing.T, method, path, body string, granted bool, permission string) (*httptest.ResponseRecorder, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	userID, tenantID := uuid.New(), uuid.New()
	// trial_lock runs ahead of the permission gate on mutating methods. It is
	// deliberately left unmocked: it fails OPEN on any resolver error, so the
	// unmatched query it issues passes the request through to the permission
	// gate, which is the thing under test. Matching is unordered so that stray
	// query cannot displace the expectation below.
	mock.MatchExpectationsInOrder(false)
	expectPermissionCheck(mock, userID, tenantID, permission, granted)

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+mintToken(t, userID, tenantID, "viewer"))
	w := httptest.NewRecorder()
	gateRouter(t, db).ServeHTTP(w, req)
	return w, mock
}

// discoveryRouteGates is the whole tenant-facing surface and the permission each
// route must demand. Adding a route without adding it here is not caught; adding
// a route and DELETING its gate is.
var discoveryRouteGates = []struct {
	method     string
	path       string
	body       string
	permission string
}{
	{http.MethodPost, "/api/v1/discovery/jobs", `{"targets":["10.0.0.1"],"protocols":["tls"],"ports":[443]}`, "discovery.create"},
	{http.MethodGet, "/api/v1/discovery/jobs", "", "discovery.read"},
	{http.MethodGet, "/api/v1/discovery/jobs/" + uuid.Nil.String(), "", "discovery.read"},
	{http.MethodPost, "/api/v1/discovery/jobs/" + uuid.Nil.String() + "/cancel", "{}", "discovery.update"},
	{http.MethodPost, "/api/v1/discovery/jobs/" + uuid.Nil.String() + "/retry", "{}", "discovery.update"},
	{http.MethodGet, "/api/v1/discovery/jobs/" + uuid.Nil.String() + "/status", "", "discovery.read"},
	{http.MethodGet, "/api/v1/discovery/jobs/" + uuid.Nil.String() + "/results", "", "discovery.read"},
	{http.MethodPost, "/api/v1/discovery/jobs/" + uuid.Nil.String() + "/approve", "{}", "assets.update"},
	{http.MethodPost, "/api/v1/discovery/jobs/" + uuid.Nil.String() + "/reject", "{}", "assets.update"},
	{http.MethodGet, "/api/v1/discovery/approvals", "", "discovery.read"},
	{http.MethodPost, "/api/v1/discovery/approvals/bulk-approve", "{}", "assets.update"},
	{http.MethodPost, "/api/v1/discovery/approvals/bulk-reject", "{}", "assets.update"},
	{http.MethodGet, "/api/v1/discovery/config/rate-limits", "", "discovery.read"},
	{http.MethodPut, "/api/v1/discovery/config/rate-limits", "{}", "discovery.manage"},
	{http.MethodGet, "/api/v1/discovery/config/alerts", "", "discovery.read"},
	{http.MethodPut, "/api/v1/discovery/config/alerts", "{}", "discovery.manage"},
}

// TestDiscoveryRoutes_RefuseCallerWithoutPermission — the viewer case from the
// finding. Every route 403s and names the permission it wanted.
func TestDiscoveryRoutes_RefuseCallerWithoutPermission(t *testing.T) {
	for _, r := range discoveryRouteGates {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			w, mock := gateRequest(t, r.method, r.path, r.body, false, r.permission)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), r.permission) {
				t.Fatalf("403 body does not name %s: %s", r.permission, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the permission check did not run — is the middleware wired? %v", err)
			}
		})
	}
}

// TestDiscoveryRoutes_AdmitCallerWithPermission is the other polarity. With the
// permission held the request passes the gate and reaches the handler, which
// then fails on its own unmocked queries — any status that is NOT 403 proves
// the gate was passed rather than that everything is refused.
func TestDiscoveryRoutes_AdmitCallerWithPermission(t *testing.T) {
	for _, r := range discoveryRouteGates {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			w, mock := gateRequest(t, r.method, r.path, r.body, true, r.permission)
			if w.Code == http.StatusForbidden {
				t.Fatalf("permission %s was HELD and the route still 403'd — the gate refuses everyone: %s",
					r.permission, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the permission check did not run — is the middleware wired? %v", err)
			}
		})
	}
}

// TestDiscoveryRoutes_OriginIsServerDerived is the other half of #H5: the
// options that select which authorization path a job is judged by were read
// straight out of caller-supplied JSON.
//
// It drives the REAL router. The observable is a query only the enrichment
// dispatch path issues — DiscoveryService.CreateJob looks up a replay by
// `metadata->'options'->>'identity_enrichment_request_id'` before anything
// else, and ONLY when that option survived the handler. So the whole path up
// to it (rate limiter included) is mocked, and the assertion is that this one
// expectation was NEVER matched.
//
// The assertion is self-verifying in both directions: if the stripping is
// removed the expectation IS matched and the first branch fires; if the mocks
// below drift out of date the unmet expectation names something else and the
// second branch fires. It cannot pass by accident.
func TestDiscoveryRoutes_OriginIsServerDerived(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)

	userID, tenantID := uuid.New(), uuid.New()
	expectPermissionCheck(mock, userID, tenantID, "discovery.create", true)

	// trial_lock's phase resolver. Mocked here (unlike in the gate tests above)
	// because it opens a transaction, and an unmocked BeginTx would consume one
	// of the rate limiter's below.
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM tenants t`).
		WillReturnRows(sqlmock.NewRows([]string{"is_trial", "trial_days_full", "trial_days_soft", "trial_start", "trial_end", "converted_to_paid"}).
			AddRow(false, nil, nil, nil, nil, nil))
	mock.ExpectCommit()

	// RateLimiter.CheckRateLimit — one tenant-scoped tx for the limit row, one
	// for the two job counts. Answer generously so the limiter passes.
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM discovery_rate_limits`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "scans_per_hour", "concurrent_jobs", "max_targets_per_job", "is_active", "created_at", "updated_at"}).
			AddRow(uuid.New(), tenantID, 1000, 1000, 1000, true, time.Now(), time.Now()))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`status IN \('queued', 'running'\)`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`INTERVAL '1 hour'`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectCommit()

	// The enrichment replay lookup, and the transaction it runs in. Reached
	// ONLY if the caller's identity_enrichment_request_id survived into the
	// service. Declared LAST on purpose: ExpectationsWereMet reports the first
	// unmatched expectation in declaration order, so when the stripping works
	// the failure it reports is this query by name.
	mock.ExpectQuery(`identity_enrichment_request_id`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "status", "created_at", "updated_at", "fp"}))
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WillReturnResult(sqlmock.NewResult(0, 0))

	body := `{"targets":["10.0.0.1"],"protocols":["tls"],"ports":[443],` +
		`"options":{"origin":"auto_scan","identity_enrichment_request_id":"` + uuid.New().String() + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/jobs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+mintToken(t, userID, tenantID, "viewer"))
	w := httptest.NewRecorder()
	gateRouter(t, db).ServeHTTP(w, req)

	err = mock.ExpectationsWereMet()
	if err == nil {
		t.Fatalf("a JWT caller's identity_enrichment_request_id reached the service — "+
			"server-authority job options are not being stripped (status %d, body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(err.Error(), "identity_enrichment_request_id") {
		t.Fatalf("something OTHER than the enrichment lookup went unmatched, so this test "+
			"proves nothing about stripping — fix the mocks: %v", err)
	}
}
