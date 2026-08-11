package handlers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/certificates"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/api"
)

// UpdateSensorInterfacesRequest represents a request to update sensor network interfaces
type UpdateSensorInterfacesRequest struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// UpdateSensorConfigRequest represents a request to update sensor configuration
type UpdateSensorConfigRequest struct {
	AirGapped        *bool    `json:"air_gapped,omitempty"`
	ScanInterval     *int     `json:"scan_interval,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Description      *string  `json:"description,omitempty"`
	ActiveProbing    *bool    `json:"active_probing,omitempty"`
	NetworkDiscovery *bool    `json:"network_discovery,omitempty"`
	// DedupTTLMinutes sets the rest period (minutes) between re-reporting the
	// same observation.  When set, an update_config command is queued for the
	// sensor to apply immediately on next checkin.
	DedupTTLMinutes *int `json:"dedup_ttl_minutes,omitempty"`
	// ReportingInterval (seconds) sets the sensor's data-send cadence. Must be one
	// of models.AllowedReportingIntervals; queues an update_config command the
	// sensor applies (and reports back) on its next checkin.
	ReportingInterval *int `json:"reporting_interval,omitempty"`
}

// UpdateTenantCaptureDefaultsRequest represents a tenant-wide capture defaults update
type UpdateTenantCaptureDefaultsRequest struct {
	// DedupTTLMinutes sets the observation rest period (minutes) for all active
	// sensors belonging to this tenant.  Must be between 1 and 1440 (24 hours).
	DedupTTLMinutes int `json:"dedup_ttl_minutes" binding:"required,min=1,max=1440"`
}

// RegenerateCertificatesResponse represents the response for certificate regeneration
type RegenerateCertificatesResponse struct {
	SensorID     string `json:"sensor_id"`
	ClientCert   string `json:"client_cert"`
	ClientKey    string `json:"client_key"`
	ServerCACert string `json:"server_ca_cert"`
	ExpiresAt    string `json:"expires_at"`
	Message      string `json:"message"`
}

// UpdateSensorInterfaces updates the network interfaces for a sensor
func (h *Handler) UpdateSensorInterfaces(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID

	var req UpdateSensorInterfacesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Update interfaces
	currentInterfaces := sensor.NetworkInterfaces
	newInterfaces := make([]string, 0, len(currentInterfaces))

	// Add new interfaces
	for _, iface := range req.Add {
		if !slices.Contains(currentInterfaces, iface) {
			newInterfaces = append(newInterfaces, iface)
		}
	}

	// Keep existing interfaces that aren't being removed
	for _, iface := range currentInterfaces {
		if !slices.Contains(req.Remove, iface) {
			newInterfaces = append(newInterfaces, iface)
		}
	}

	// Update sensor
	sensor.NetworkInterfaces = newInterfaces
	sensor.UpdatedAt = time.Now()

	err := h.sensorService.UpdateSensor(sensor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update sensor interfaces"})
		return
	}

	// Queue an update_interfaces command so the sensor applies the new monitored
	// set (and restarts capture) on its next checkin.
	if h.repo != nil {
		cmd := &models.SensorCommand{
			ID:          uuid.New(),
			SensorID:    sensorID,
			CommandType: "update_interfaces",
			Payload:     map[string]interface{}{"interfaces": newInterfaces},
			Status:      "pending",
			CreatedAt:   time.Now(),
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if err := h.repo.CreateCommand(ctx, cmd); err != nil {
			h.log.WithError(err).WithField("sensor_id", sensorID).
				Warn("Failed to queue update_interfaces command for sensor")
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Sensor interfaces updated successfully",
		"interfaces": newInterfaces,
	})
}

// UpdateSensorConfig updates the configuration for a sensor
func (h *Handler) UpdateSensorConfig(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID

	var req UpdateSensorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Reporting interval must be one of the allowed presets.
	if req.ReportingInterval != nil && !models.IsAllowedReportingInterval(*req.ReportingInterval) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":           "Invalid reporting_interval; must be one of the allowed presets",
			"allowed_seconds": models.AllowedReportingIntervals,
		})
		return
	}

	// Update fields if provided
	if req.AirGapped != nil {
		sensor.AirGapped = *req.AirGapped
	}
	if req.Description != nil {
		sensor.Description = req.Description
	}
	if req.Tags != nil {
		sensor.Tags = req.Tags
	}

	sensor.UpdatedAt = time.Now()

	err := h.sensorService.UpdateSensor(sensor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update sensor config"})
		return
	}

	// If capture/reporting config fields were changed, queue an update_config
	// command so the sensor picks up the new settings on its next heartbeat.
	if h.repo != nil && (req.ActiveProbing != nil || req.NetworkDiscovery != nil || req.DedupTTLMinutes != nil || req.ReportingInterval != nil) {
		configPayload := map[string]interface{}{}

		capturePayload := map[string]interface{}{}
		if req.ActiveProbing != nil {
			capturePayload["active_probing"] = *req.ActiveProbing
		}
		if req.NetworkDiscovery != nil {
			capturePayload["network_discovery"] = *req.NetworkDiscovery
		}
		if req.DedupTTLMinutes != nil {
			capturePayload["dedup_ttl_minutes"] = *req.DedupTTLMinutes
		}
		if len(capturePayload) > 0 {
			configPayload["capture_config"] = capturePayload
		}
		// reporting_interval is a top-level config field (the sensor reads it at
		// config root, not under capture_config).
		if req.ReportingInterval != nil {
			configPayload["reporting_interval"] = *req.ReportingInterval
		}

		cmd := &models.SensorCommand{
			ID:          uuid.New(),
			SensorID:    sensorID,
			CommandType: "update_config",
			Payload: map[string]interface{}{
				"config": configPayload,
			},
			Status:    "pending",
			CreatedAt: time.Now(),
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if err := h.repo.CreateCommand(ctx, cmd); err != nil {
			h.log.WithError(err).WithField("sensor_id", sensorID).
				Warn("Failed to queue update_config command for sensor")
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Sensor configuration updated successfully",
		"sensor": gin.H{
			"id":          sensor.ID,
			"air_gapped":  sensor.AirGapped,
			"description": sensor.Description,
			"tags":        sensor.Tags,
			"updated_at":  sensor.UpdatedAt,
		},
	})
}

// RegenerateSensorCertificates regenerates mTLS certificates for a sensor
func (h *Handler) RegenerateSensorCertificates(c *gin.Context) {
	sensor, tenantID, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}

	if h.sensorService == nil || h.sensorService.GetDB() == nil || h.sensorService.GetBypassDB() == nil || h.encryptionKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Certificate service unavailable"})
		return
	}

	csrPEM, sensorKeyPEM, err := h.generateSensorCSR(sensor.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate sensor certificate request"})
		return
	}

	caManager := certificates.NewCAManager(h.sensorService.GetDB(), h.sensorService.GetBypassDB())
	ca, err := caManager.GetOrCreateActiveCA(tenantID, h.encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get CA certificate"})
		return
	}

	// Update sensor metadata before issuing the replacement. Once the new cert
	// is persisted as active, avoid any later fail-fast work that could prevent
	// the caller from receiving the replacement bundle.
	sensor.UpdatedAt = time.Now()
	err = h.sensorService.UpdateSensor(sensor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update sensor"})
		return
	}

	certService := certificates.NewCertificateService(h.sensorService.GetDB(), h.sensorService.GetBypassDB(), h.encryptionKey)
	sensorCertPEM, err := certService.IssueCertificate(tenantID, sensor.ID, csrPEM)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate sensor certificate"})
		return
	}

	certificateExpiresAt := time.Now().AddDate(1, 0, 0)
	serialNumber := ""
	if block, _ := pem.Decode([]byte(sensorCertPEM)); block != nil {
		if cert, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
			certificateExpiresAt = cert.NotAfter
			serialNumber = cert.SerialNumber.String()
		}
	}
	if serialNumber != "" {
		if err := certService.RevokeCertificatesExcept(sensor.ID, serialNumber, "manual"); err != nil && h.log != nil {
			h.log.WithError(err).WithField("sensor_id", sensor.ID).Warn("failed to revoke previous sensor certificates after admin regeneration")
		}
	}

	response := RegenerateCertificatesResponse{
		SensorID:     sensor.ID.String(),
		ClientCert:   sensorCertPEM,
		ClientKey:    sensorKeyPEM,
		ServerCACert: advertisedServerCACert(ca.CACertPEM),
		ExpiresAt:    certificateExpiresAt.Format(time.RFC3339),
		Message:      "Certificates regenerated successfully",
	}

	c.JSON(http.StatusOK, response)
}

// UpdateTenantCaptureDefaults applies capture configuration defaults (e.g. dedup TTL)
// to all active sensors belonging to the authenticated tenant.  This is used by
// the Sensor Configuration page to propagate tenant-wide settings without having
// to iterate sensors individually from the frontend.
func (h *Handler) UpdateTenantCaptureDefaults(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant not identified"})
		return
	}
	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid tenant ID type"})
		return
	}

	var req UpdateTenantCaptureDefaultsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request body")
		return
	}

	if h.sensorServiceV2 == nil || h.repo == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "sensor service not available"})
		return
	}

	sensors, err := h.sensorServiceV2.ListSensors(c.Request.Context(), tenantID)
	if err != nil {
		h.log.WithError(err).Error("Failed to list sensors for tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sensors"})
		return
	}

	queued := 0
	for _, sensor := range sensors {
		if sensor.Status != "active" && sensor.Status != "healthy" {
			continue
		}
		cmd := &models.SensorCommand{
			ID:          uuid.New(),
			SensorID:    sensor.ID,
			CommandType: "update_config",
			Payload: map[string]interface{}{
				"config": map[string]interface{}{
					"capture_config": map[string]interface{}{
						"dedup_ttl_minutes": req.DedupTTLMinutes,
					},
				},
			},
			Status:    "pending",
			CreatedAt: time.Now(),
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		if err := h.repo.CreateCommand(ctx, cmd); err != nil {
			h.log.WithError(err).WithField("sensor_id", sensor.ID).
				Warn("Failed to queue update_config for sensor")
		} else {
			queued++
		}
		cancel()
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Tenant capture defaults applied",
		"sensors_queued": queued,
	})
}
