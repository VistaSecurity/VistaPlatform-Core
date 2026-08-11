package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_RequireSensorOutboundAccess covers the tenant resolution behind
// the sensor-cert-rotation fix. Rotation now runs under SensorAuth (no tenant
// JWT), so the handler must derive the owning tenant FROM the sensor:
//   - mTLS mode: use the tenant SensorAuth pinned to the context from the cert.
//   - fail-open mode: resolve the tenant from the trusted-path sensor_id via bypass.
//   - unknown sensor id: 404 (never mint/act for a non-existent sensor).
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
func TestIntegration_RequireSensorOutboundAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testdb.Connect(t)
	tenantA := testdb.NewTenant(t, db)

	sensorID := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO sensors (id, tenant_id, name, platform, version, profile)
		 VALUES ($1, $2, 'it-sensor', 'linux', '1.0', 'datacenter_host')`,
		sensorID, tenantA,
	); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}

	h := NewHandler(services.NewSensorService(db, db))

	newCtx := func(param string, ctxTenant *uuid.UUID) (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		c.Params = gin.Params{{Key: "sensor_id", Value: param}}
		if ctxTenant != nil {
			c.Set("tenantID", *ctxTenant)
		}
		return c, w
	}

	// Fail-open mode: no context tenant → resolve owning tenant from sensor_id.
	t.Run("fail-open resolves owning tenant", func(t *testing.T) {
		c, w := newCtx(sensorID.String(), nil)
		gotSensor, gotTenant, ok := h.requireSensorOutboundAccess(c)
		if !ok {
			t.Fatalf("resolution failed, code=%d body=%s", w.Code, w.Body.String())
		}
		if gotSensor != sensorID {
			t.Fatalf("sensor id = %s, want %s", gotSensor, sensorID)
		}
		if gotTenant != tenantA {
			t.Fatalf("resolved tenant = %s, want owning tenant %s", gotTenant, tenantA)
		}
	})

	// mTLS mode: SensorAuth pinned a (cert-derived) tenant → use it as-is.
	t.Run("mTLS mode uses context tenant", func(t *testing.T) {
		ctxTenant := uuid.New()
		c, _ := newCtx(sensorID.String(), &ctxTenant)
		_, gotTenant, ok := h.requireSensorOutboundAccess(c)
		if !ok || gotTenant != ctxTenant {
			t.Fatalf("context tenant not honored: ok=%v tenant=%s want %s", ok, gotTenant, ctxTenant)
		}
	})

	// Unknown sensor id → 404, no resolution.
	t.Run("unknown sensor is 404", func(t *testing.T) {
		c, w := newCtx(uuid.New().String(), nil)
		if _, _, ok := h.requireSensorOutboundAccess(c); ok {
			t.Fatal("resolution succeeded for a non-existent sensor")
		}
		if w.Code != http.StatusNotFound {
			t.Fatalf("unknown sensor = %d, want 404", w.Code)
		}
	})
}
