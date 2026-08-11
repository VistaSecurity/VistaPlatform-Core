package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// requireSensorOutboundAccess resolves (sensor_id, owning tenant) for a
// SensorAuth-authenticated request (the sensor's own outbound calls), WITHOUT a
// tenant JWT. It is the counterpart to requireSensorAccess for the outbound
// surface:
//
//   - Under enforced sensor mTLS the tenant was already derived from the client
//     cert (CN == sensor_id, chain-verified) and pinned to the context by
//     SensorAuth — that value is authoritative and is used as-is.
//   - In the legacy fail-open mode SensorAuth sets only sensor_id, so the sensor
//     is trusted by its (path) sensor_id exactly like every other outbound
//     handler (heartbeat, discoveries), and the tenant is resolved from the
//     sensor row on the bypass connection.
//
// The tenant is always derived FROM the sensor, so there is no cross-tenant
// vector: a request can only ever act on the tenant that owns that sensor_id.
// In fail-open mode this trusts the path sensor_id like the rest of the outbound
// surface — enforced sensor mTLS (agentMtls) is what closes that gap.
func (h *Handler) requireSensorOutboundAccess(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	sensorID, err := uuid.Parse(c.Param("sensor_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sensor ID"})
		return uuid.Nil, uuid.Nil, false
	}
	// mTLS mode: SensorAuth already resolved + verified the tenant from the cert.
	if v, exists := c.Get("tenantID"); exists {
		if tid, ok := v.(uuid.UUID); ok && tid != uuid.Nil {
			return sensorID, tid, true
		}
	}
	// Fail-open mode: resolve the owning tenant from the trusted-path sensor_id.
	bypass := h.sensorService.GetBypassDB()
	if bypass == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "sensor lookup not supported"})
		return uuid.Nil, uuid.Nil, false
	}
	var tenantID uuid.UUID
	if err := bypass.QueryRowContext(c.Request.Context(),
		`SELECT tenant_id FROM sensors WHERE id = $1 AND deleted_at IS NULL`,
		sensorID,
	).Scan(&tenantID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Sensor not found"})
		return uuid.Nil, uuid.Nil, false
	}
	return sensorID, tenantID, true
}

// requireSensorAccess is the single tenant-ownership gate for every by-sensor-id
// route. RequireAuth/RequireTenant/RequireTenantPermission authorize the
// caller WITHIN their tenant but say nothing about which sensor UUID they may
// target; without this guard a tenant-A user with sensors.manage could read,
// command, delete, or break the mTLS of any tenant-B sensor by id.
//
// It parses :sensor_id, resolves the caller's tenant from context, and loads
// the sensor with a tenant-scoped query. A bad id is 400; a missing/cross-tenant
// sensor is 404 (not 403 — don't confirm the sensor exists for another tenant).
// The resolved sensor is returned so read handlers can reuse it.
func (h *Handler) requireSensorAccess(c *gin.Context) (*models.Sensor, uuid.UUID, bool) {
	sensorID, err := uuid.Parse(c.Param("sensor_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sensor ID"})
		return nil, uuid.Nil, false
	}

	tenantID, ok := h.tenantFromContext(c)
	if !ok {
		return nil, uuid.Nil, false
	}

	if h.repo == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "sensor lookup not supported"})
		return nil, uuid.Nil, false
	}

	sensor, err := h.repo.GetSensorByIDForTenant(c.Request.Context(), sensorID, tenantID)
	if err != nil || sensor == nil {
		// Tenant mismatch and genuine absence look identical to the caller.
		c.JSON(http.StatusNotFound, gin.H{"error": "Sensor not found"})
		return nil, uuid.Nil, false
	}
	return sensor, tenantID, true
}

// tenantFromContext reads the authenticated tenant id set by RequireTenant.
func (h *Handler) tenantFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	tenantID, ok := v.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	return tenantID, true
}
