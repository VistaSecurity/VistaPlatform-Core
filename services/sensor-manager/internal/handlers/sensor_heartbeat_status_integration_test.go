package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// A heartbeat carrying any status the sensor model documents (healthy,
// degraded, unhealthy), any stored status, or an unknown one must succeed and
// leave sensors.status inside sensors_status_check. Runs against the
// real CHECK constraint.
//
// Mutation check: pass health.Status instead of storedStatusFromReported(...)
// to the UPDATE in UpdateSensorHealthWithIP; the documented values 500.
func TestIntegration_SensorHeartbeatAcceptsDocumentedHealthStatuses(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	h := newHeartbeatHandler(t, admin)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sensors/:sensor_id/heartbeat", h.Heartbeat)

	cases := []struct{ reported, wantStored string }{
		{"healthy", "active"},
		{"degraded", "active"},
		{"unhealthy", "error"},
		{"active", "active"},
		{"error", "error"},
		{"pending", "pending"},
		{"inactive", "inactive"},
		{"offline", "active"}, // "offline" never overwrites; the seeded row is active
		{"", "active"},
		{"surprise", "active"},
	}
	for _, tc := range cases {
		t.Run("reported_"+tc.reported, func(t *testing.T) {
			sensorID := seedSensor(t, admin, tenant) // starts 'active'
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/sensors/"+sensorID.String()+"/heartbeat",
				bytes.NewBufferString(`{"sensor_id":"`+sensorID.String()+`","status":"`+tc.reported+`"}`))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("heartbeat status %q = %d: %s", tc.reported, w.Code, w.Body.String())
			}
			var got string
			if err := admin.QueryRow(`SELECT status FROM public.sensors WHERE id = $1`, sensorID).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.wantStored {
				t.Errorf("reported %q: stored status = %q, want %q", tc.reported, got, tc.wantStored)
			}
		})
	}
}
