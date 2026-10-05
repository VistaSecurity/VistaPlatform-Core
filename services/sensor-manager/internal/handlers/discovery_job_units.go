package handlers

// A planned scan's per-host reports ( WP2b).
//
// POST /api/v1/sensor-manager/sensors/:sensor_id/discovery-jobs/:job_id/units
//
// On the `sensors` group, like the completion callback beside it: the caller is
// authenticated as the sensor (mTLS/HMAC, fail-closed under
// SensorMTLSRequired). A sensor running a planned scan posts each host it
// finishes here — and an empty batch as a progress ping — and the platform
// stores the hosts as the job's work units (shared/jobunits), renews the job's
// progress lease, and answers whether to go on: 409 with a code means the job
// was cancelled or has ended and the sensor must stop.

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// maxUnitReportBytes bounds one report. A host's result carries its
// identified services, a TLS one with its certificate chain (PEM included), so
// a busy host is tens of kilobytes; a liveness batch of hundreds of silent
// hosts is smaller still. 32 MiB is far above both and still a bound.
const maxUnitReportBytes = 32 << 20

// sensorUnitRecorder is the slice of *services.DiscoveryJobService the units
// route needs, as an interface so the contract test drives the real route
// without a database.
type sensorUnitRecorder interface {
	RecordSensorUnits(ctx context.Context, tenantID, sensorID, jobID uuid.UUID, batch sensordispatch.UnitBatch) (sensordispatch.UnitBatchResponse, error)
}

// ReportDiscoveryJobUnits takes a planned scan's progress report.
func (h *Handler) ReportDiscoveryJobUnits(c *gin.Context) {
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
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUnitReportBytes)
	var batch sensordispatch.UnitBatch
	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	// A result the engine could not have produced is refused whole, before
	// anything is looked up: nothing half-stored.
	if err := batch.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.unitRecorder == nil {
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

	resp, err := h.unitRecorder.RecordSensorUnits(c.Request.Context(), tenantID, sensorID, jobID, batch)
	switch {
	case err == nil && resp.Stop():
		// Cancelled or ended: nothing in the batch was stored, and the code
		// tells the sensor to stop.
		c.JSON(http.StatusConflict, resp)
	case err == nil:
		c.JSON(http.StatusOK, resp)
	case errors.Is(err, services.ErrJobNotAssignedToSensor):
		c.JSON(http.StatusNotFound, gin.H{"error": "Discovery job not found"})
	case errors.Is(err, jobunits.ErrNotPlannedJob):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		h.log.WithError(err).WithField("sensor_id", sensorID).WithField("job_id", jobID).
			Error("Failed to record discovery job units")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record discovery job units"})
	}
}
