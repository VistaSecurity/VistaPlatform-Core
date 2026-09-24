package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// expectSensorTenantState queues the tenant-state read SensorAuth performs
// after authenticating a sensor (RC-4 /).
func expectSensorTenantState(mock sqlmock.Sqlmock, tenantID uuid.UUID, status string, deleted bool) {
	mock.ExpectQuery(`FROM tenants WHERE id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"payment_status", "deleted", "session_version"}).AddRow(status, deleted, 0))
}

// TestSensorAuth_RefusesSensorsOfBlockedTenants — a sensor of a suspended,
// canceled or deleted tenant is turned away with 403 and a machine-readable
// code before its heartbeat or discovery submission is handled, so nothing it
// observes is ingested. Driven on the legacy (no agent-mTLS) path, where the
// tenant has to be resolved from the sensor row; a live tenant passes.
// Mutation: delete the enforceSensorTenantState call in SensorAuth and the
// blocked cases reach the handler (204).
func TestSensorAuth_RefusesSensorsOfBlockedTenants(t *testing.T) {
	cases := []struct {
		name     string
		status   string
		deleted  bool
		wantHTTP int
		wantCode string
	}{
		{"suspended", "suspended", false, http.StatusForbidden, "tenant_suspended"},
		{"canceled", "canceled", false, http.StatusForbidden, "tenant_suspended"},
		{"deleted", "active", true, http.StatusForbidden, "tenant_deleted"},
		{"live", "trial", false, http.StatusNoContent, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			sensorID, tenantID := uuid.New(), uuid.New()
			mock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
				WithArgs(sensorID).
				WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
			expectSensorTenantState(mock, tenantID, tc.status, tc.deleted)

			r := gin.New()
			g := r.Group("/sensors")
			g.Use(SensorAuth(db, db, "", false))
			g.POST("/:sensor_id/heartbeat", func(c *gin.Context) { c.Status(http.StatusNoContent) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sensors/"+sensorID.String()+"/heartbeat", nil))
			var body struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != tc.wantHTTP || body.Code != tc.wantCode {
				t.Fatalf("status=%d code=%q, want %d %q; body=%s", w.Code, body.Code, tc.wantHTTP, tc.wantCode, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestSensorAuth_UnknownSensorLeftToHandler — a sensor id with no row is not
// this check's business; the handler answers for it exactly as before.
func TestSensorAuth_UnknownSensorLeftToHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sensorID := uuid.New()
	mock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}))

	r := gin.New()
	g := r.Group("/sensors")
	g.Use(SensorAuth(db, db, "", false))
	g.POST("/:sensor_id/heartbeat", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sensors/"+sensorID.String()+"/heartbeat", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("unknown sensor = %d, want it passed to the handler (204)", w.Code)
	}
}
