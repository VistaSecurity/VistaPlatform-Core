// Package handlers provides HTTP handlers for the sensor-manager service.
// This file contains handlers for outbound-only communication patterns,
// allowing sensors to poll for commands and submit data without requiring
// inbound firewall rules.
package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// Heartbeat handles sensor heartbeat and returns commands (outbound-only).
// This endpoint allows sensors to report their status and receive commands
// without requiring inbound firewall rules. The sensor initiates the connection.
func (h *Handler) Heartbeat(c *gin.Context) {
	sensorID := c.Param("sensor_id")

	var health models.SensorHealth
	if err := c.ShouldBindJSON(&health); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate sensor ID
	sensorUUID, err := uuid.Parse(sensorID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sensor ID format"})
		return
	}
	if health.SensorID != sensorUUID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sensor ID mismatch"})
		return
	}

	// Extract IP address from request
	clientIP := c.ClientIP()

	// Update sensor health in database with IP address
	err = h.sensorService.UpdateSensorHealthWithIP(sensorID, &health, &clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update sensor health",
		})
		return
	}

	// Get pending commands for this sensor
	commands, err := h.sensorService.GetPendingCommands(sensorID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve commands",
		})
		return
	}

	// Mark commands as delivered
	if len(commands) > 0 {
		commandIDs := make([]string, len(commands))
		for i, cmd := range commands {
			commandIDs[i] = cmd.ID.String()
		}
		err = h.sensorService.MarkCommandsAsDelivered(sensorID, commandIDs)
		if err != nil {
			// Log error but don't fail the request
			h.log.WithError(err).WithFields(logrus.Fields{
				"sensor_id":   sensorID,
				"command_ids": commandIDs,
			}).Error("Failed to mark commands as delivered")
		}
	}

	response := models.SensorCommands{
		SensorID: sensorID,
		Commands: commands,
	}

	c.JSON(http.StatusOK, response)
}

// PollCommands handles sensor polling for commands (outbound-only).
// Sensors can poll this endpoint to check for pending commands without
// requiring the control plane to initiate connections.
func (h *Handler) PollCommands(c *gin.Context) {
	sensorID := c.Param("sensor_id")

	// Get pending commands for this sensor
	commands, err := h.sensorService.GetPendingCommands(sensorID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve commands",
		})
		return
	}

	// Mark commands as delivered
	if len(commands) > 0 {
		commandIDs := make([]string, len(commands))
		for i, cmd := range commands {
			commandIDs[i] = cmd.ID.String()
		}
		err = h.sensorService.MarkCommandsAsDelivered(sensorID, commandIDs)
		if err != nil {
			// Log error but don't fail the request
			h.log.WithError(err).WithFields(logrus.Fields{
				"sensor_id":   sensorID,
				"command_ids": commandIDs,
			}).Error("Failed to mark commands as delivered")
		}
	}

	response := models.SensorCommands{
		SensorID: sensorID,
		Commands: commands,
	}

	c.JSON(http.StatusOK, response)
}

// AcknowledgeCommand handles command acknowledgments from sensors.
// This allows sensors to confirm they have received and processed commands,
// enabling proper command lifecycle management.
func (h *Handler) AcknowledgeCommand(c *gin.Context) {
	sensorID := c.Param("sensor_id")
	commandID := c.Param("command_id")

	var response models.CommandResponse
	if err := c.ShouldBindJSON(&response); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate sensor ID
	if response.SensorID.String() != sensorID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sensor ID mismatch"})
		return
	}

	// Update command status in database
	err := h.sensorService.AcknowledgeCommand(sensorID, commandID, &response)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to acknowledge command",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Command acknowledgment received",
	})
}

// GetWebhookConfig returns webhook configuration for sensors
func (h *Handler) GetWebhookConfig(c *gin.Context) {
	sensorID := c.Param("sensor_id")

	// Load webhook configuration from database
	webhookConfig, err := h.sensorService.GetWebhookConfig(sensorID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve webhook config",
		})
		return
	}

	c.JSON(http.StatusOK, webhookConfig)
}

// SubmitAirGappedExport handles air-gapped export submissions
func (h *Handler) SubmitAirGappedExport(c *gin.Context) {
	sensorID := c.Param("sensor_id")

	var export models.AirGappedExport
	if err := c.ShouldBindJSON(&export); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate sensor ID
	if export.SensorID.String() != sensorID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sensor ID mismatch"})
		return
	}

	// Store air-gapped export in database
	err := h.sensorService.StoreAirGappedExport(&export)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to store air-gapped export",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "success",
		"message":   "Air-gapped export received",
		"export_id": export.ExportID,
		"records":   len(export.Data),
	})
}

// SubmitDiscoveries handles submission of discovery batches from sensors
func (h *Handler) SubmitDiscoveries(c *gin.Context) {
	// The URL path sensor_id is the authoritative identifier.
	// It is validated by the mTLS client certificate at the middleware layer,
	// so we trust it over any sensor_id value present in the JSON body.
	sensorID := c.Param("sensor_id")

	pathUUID, err := uuid.Parse(sensorID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sensor ID in URL path"})
		return
	}

	var batch models.DiscoveryBatch
	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Override body sensor ID with the authoritative URL path value.
	// This prevents a sensor from attributing discoveries to a different sensor ID.
	batch.SensorID = pathUUID

	// Store discoveries in database
	err = h.sensorService.StoreDiscoveries(&batch)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Sensor not registered - re-registration required"})
			return
		}
		h.log.WithFields(logrus.Fields{
			"sensor_id": sensorID,
			"batch_id":  batch.BatchID,
			"count":     len(batch.Discoveries),
		}).WithError(err).Error("Failed to store discoveries")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to store discoveries",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "success",
		"message":  "Discoveries received",
		"count":    len(batch.Discoveries),
		"batch_id": batch.BatchID,
	})
}

// ReportHealth handles legacy health reports from sensors
func (h *Handler) ReportHealth(c *gin.Context) {
	sensorID := c.Param("sensor_id")

	var health models.SensorHealth
	if err := c.ShouldBindJSON(&health); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if health.SensorID.String() != sensorID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sensor ID mismatch"})
		return
	}

	// Store health status and update last seen timestamp
	err := h.sensorService.UpdateSensorHealth(sensorID, &health)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update sensor health",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Health report received",
	})
}

// GetSensorConfig returns configuration for a sensor (legacy endpoint)
func (h *Handler) GetSensorConfig(c *gin.Context) {
	sensorID := c.Param("sensor_id")

	// Load sensor-specific configuration from database
	config, err := h.sensorService.GetSensorConfig(sensorID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve sensor config",
		})
		return
	}

	c.JSON(http.StatusOK, config)
}
