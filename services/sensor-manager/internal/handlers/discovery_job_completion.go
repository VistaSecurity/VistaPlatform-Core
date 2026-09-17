package handlers

// Dispatched discovery job completion.
//
// POST /api/v1/sensor-manager/sensors/:sensor_id/discovery-jobs/:job_id/complete
//
// Sits on the `sensors` group, so the caller is authenticated as the sensor
// (mTLS/HMAC, fail-closed under SensorMTLSRequired) — the same way its
// heartbeat and discovery batches are. The job's RESULTS do not come through
// here: the sensor submits them through the ordinary discovery batch route, so
// they reach inventory the way every passive observation does. This call only
// closes the job with the sensor's counts.

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// sensorJobCompleter is the slice of *services.DiscoveryJobService this
// handler needs, as an interface so the contract test can drive the real
// route without a database.
type sensorJobCompleter interface {
	CompleteSensorJob(ctx context.Context, tenantID, sensorID, jobID uuid.UUID, c sensordispatch.Completion) error
}

// sensorTenantResolver answers "which tenant owns this sensor" for the
// sensor-authenticated routes, which carry no tenant in their auth context.
// Production is TenantForSensor over the bypass handle (the tenant is the
// OUTPUT of the lookup, so no app.tenant_id can be set first).
type sensorTenantResolver func(c *gin.Context, sensorID uuid.UUID) (uuid.UUID, bool)

// CompleteDiscoveryJob handles the sensor's completion report for a job the
// platform dispatched to it.
func (h *Handler) CompleteDiscoveryJob(c *gin.Context) {
	sensorID, err := uuid.Parse(c.Param("sensor_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sensor ID format"})
		return
	}
	jobID, err := uuid.Parse(c.Param("job_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID format"})
		return
	}

	var completion sensordispatch.Completion
	if err := c.ShouldBindJSON(&completion); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if err := completion.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.jobCompleter == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Discovery job service unavailable"})
		return
	}
	resolve := h.sensorTenant
	if resolve == nil {
		resolve = func(c *gin.Context, id uuid.UUID) (uuid.UUID, bool) { return TenantForSensor(c, h.bypassDB, id) }
	}
	tenantID, ok := resolve(c, sensorID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Sensor not registered - re-registration required"})
		return
	}

	err = h.jobCompleter.CompleteSensorJob(c.Request.Context(), tenantID, sensorID, jobID, completion)
	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": "Discovery job completion recorded",
			"job_id":  jobID.String(),
		})
	case errors.Is(err, services.ErrJobNotAssignedToSensor):
		c.JSON(http.StatusNotFound, gin.H{"error": "Discovery job not found"})
	case errors.Is(err, services.ErrJobNotAwaitingSensor):
		// The report was kept as evidence; the verdict stands.
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		h.log.WithError(err).WithField("sensor_id", sensorID).WithField("job_id", jobID).
			Error("Failed to record discovery job completion")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record discovery job completion"})
	}
}
