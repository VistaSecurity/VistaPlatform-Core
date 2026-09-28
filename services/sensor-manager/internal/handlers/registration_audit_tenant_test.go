package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// Sensor registration is the unauthenticated bootstrap: no auth middleware runs,
// so unless the handler records the tenant its registration key belongs to,
// the audit middleware logs every registration with no tenant — 13,730 of the
// ~23k unattributed rows on the dev cluster. The audit middleware reads the
// context after c.Next(); this capture does the same. Delete the c.Set in
// RegisterSensor and this fails.
func TestRegisterSensor_RecordsTheKeysTenantForAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenant := uuid.New()
	h := &Handler{
		sensorService: &stubLegacySensorService{pending: &models.PendingSensorRegistration{TenantID: tenant}},
		log:           logrus.New(),
	}

	var seen any
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Next()
		seen, _ = c.Get("tenantID")
	})
	// Later registration steps need real services; what matters here is the
	// context once the key has named its tenant, whatever the response.
	r.Use(gin.Recovery())
	r.POST("/api/v1/sensor-manager/sensors/register", h.RegisterSensor)

	body := `{"registration_key":"k","name":"s1","platform":"linux","version":"1","profile":"default","network_interfaces":["eth0"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor-manager/sensors/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)

	if got, _ := seen.(uuid.UUID); got != tenant {
		t.Fatalf("tenantID in the audit context = %v, want the registration key's tenant %s", seen, tenant)
	}
}
