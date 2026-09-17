package handlers

// Desired-state endpoints for sensors (feature).
//
// The HTTP behaviour is shared with device-interrogation-service via
// shared/agentconfig/confighttp; only sensor ownership lives here.
//
// This is NOT the same thing as the older UpdateSensorConfig endpoint next
// door. That one takes a handful of capture settings, queues a one-shot
// `update_config` command and persists none of them — so the platform cannot
// say what it asked for, a missed command is never re-sent, and the console can
// show a value that never took effect. Desired state inverts it: the platform
// records what the sensor SHOULD be, the sensor reports what it IS, and the
// difference is computed. The old endpoint stays for now so existing clients
// keep working.

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/confighttp"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/store"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// SensorConfigHandler serves the desired-state surface for sensors.
type SensorConfigHandler struct {
	inner *confighttp.Handler
	store *store.Store
	db    *sql.DB
}

func NewSensorConfigHandler(db *sql.DB) *SensorConfigHandler {
	s := store.New(db)
	h := &SensorConfigHandler{store: s, db: db}
	h.inner = confighttp.New(confighttp.Deps{
		Runtime:       agentconfig.RuntimeSensor,
		Store:         s,
		OwnerFrom:     h.ownerFrom,
		DeviceVersion: h.deviceVersion,
	})
	return h
}

// GetSensorDesiredConfig returns one sensor's effective settings and state.
func (h *SensorConfigHandler) GetSensorDesiredConfig(c *gin.Context) { h.inner.GetDevice(c) }

// PutSensorDesiredConfig replaces one sensor's override.
func (h *SensorConfigHandler) PutSensorDesiredConfig(c *gin.Context) { h.inner.PutDevice(c) }

// GetSensorFleetDefaults returns the tenant-wide sensor defaults.
func (h *SensorConfigHandler) GetSensorFleetDefaults(c *gin.Context) { h.inner.GetDefaults(c) }

// PutSensorFleetDefaults replaces the tenant-wide sensor defaults.
func (h *SensorConfigHandler) PutSensorFleetDefaults(c *gin.Context) { h.inner.PutDefaults(c) }

// GetSensorConfigHistory answers with who changed this sensor's configuration,
// when, and what moved. It is what makes the DNS decoder's recorded
// confirmation readable, which is the condition the owner attached to managing
// it at all.
func (h *SensorConfigHandler) GetSensorConfigHistory(c *gin.Context) { h.inner.GetHistory(c) }

// Exchange records a sensor's report and returns what it should be running.
// Called from the heartbeat, which is already authenticated as that sensor.
func (h *SensorConfigHandler) Exchange(c *gin.Context, tenantID, sensorID uuid.UUID, rep confighttp.ExchangeReport) (*confighttp.ExchangePayload, error) {
	return confighttp.Exchange(c, h.store, tenantID, store.SensorOwner(sensorID), rep)
}

// TenantForSensor resolves the tenant a sensor belongs to.
//
// The sensor-authenticated routes carry the sensor's identity, not a tenant, so
// the heartbeat has to look it up. On the bypass handle deliberately: there is
// no tenant in scope yet, which is exactly the case RLS cannot serve, and it is
// the same handle the rest of the sensor-outbound path already uses for this.
func TenantForSensor(c *gin.Context, bypassDB *sql.DB, sensorID uuid.UUID) (uuid.UUID, bool) {
	if bypassDB == nil {
		return uuid.Nil, false
	}
	var tenantID uuid.UUID
	err := bypassDB.QueryRowContext(c.Request.Context(),
		`SELECT tenant_id FROM sensors WHERE id = $1 AND deleted_at IS NULL`, sensorID).Scan(&tenantID)
	if err != nil {
		return uuid.Nil, false
	}
	return tenantID, true
}

// ownerFrom resolves the sensor this request addresses, refusing one that is
// not this tenant's.
//
// Inside WithTenantTx, for the reason the agent equivalent records: `sensors`
// is an RLS table and the service connects as a non-owner role wherever
// serviceRls is enabled, so a plain-pool query has no app.tenant_id, the policy
// evaluates against NULL, and every endpoint answers 404 for the tenant's OWN
// sensors. That shipped once on the agent side and passed a full integration
// suite, because the harness connects as the table owner.
func (h *SensorConfigHandler) ownerFrom(c *gin.Context, tenantID uuid.UUID) (store.Owner, bool) {
	sensorID, err := uuid.Parse(c.Param("sensor_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sensor ID"})
		return store.Owner{}, false
	}

	var found bool
	err = shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(c.Request.Context(),
			`SELECT EXISTS (SELECT 1 FROM sensors WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL)`,
			sensorID, tenantID).Scan(&found)
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return store.Owner{}, false
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Sensor not found"})
		return store.Owner{}, false
	}
	return store.SensorOwner(sensorID), true
}

// deviceVersion reports what this sensor last told us it was running. Empty on
// any failure: a version display that cannot be built is a missing badge, not a
// reason to fail the configuration read.
func (h *SensorConfigHandler) deviceVersion(c *gin.Context, tenantID uuid.UUID, owner store.Owner) string {
	var version sql.NullString
	err := shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(c.Request.Context(),
			`SELECT version FROM sensors WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
			owner.SensorID, tenantID).Scan(&version)
	})
	if err != nil {
		// Logged for the same reason as the agent equivalent: a silent empty
		// version is indistinguishable from a device that never reported one.
		log.Printf("sensor config: could not read version for sensor %s: %v", owner.SensorID, err)
		return ""
	}
	return version.String
}
