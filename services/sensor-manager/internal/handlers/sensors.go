package handlers

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// GetSensors lists sensors for the current tenant
func (h *Handler) GetSensors(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Prefer V2 service when available
	if h.sensorServiceV2 != nil {
		sensors, err := h.sensorServiceV2.ListSensors(c.Request.Context(), tenantID)
		if err != nil {
			// Log error for debugging but return empty list instead of 500
			// This allows the UI to load even if database is temporarily unavailable
			log.Printf("⚠️  Error listing sensors for tenant %s: %v", tenantID, err)
			c.JSON(http.StatusOK, gin.H{"sensors": []interface{}{}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"sensors": sensors})
		return
	}

	// Fallback: empty list when legacy service is in use without list support
	c.JSON(http.StatusOK, gin.H{"sensors": []interface{}{}})
}

// GetSensorStats returns basic stats for sensors for the current tenant
func (h *Handler) GetSensorStats(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Default stats — keys must match web-ui SensorStats (sensors-api.ts) and Operations dashboard.
	stats := gin.H{
		"total_sensors":     0,
		"active_sensors":    0,
		"inactive_sensors":  0,
		"error_sensors":     0,
		"pending_sensors":   0,
		"total_discoveries": 0,
		"total_packets":     0,
		"total_errors":      0,
		"last_updated":      time.Now().UTC(),
	}

	if h.sensorServiceV2 != nil {
		sensors, err := h.sensorServiceV2.ListSensors(c.Request.Context(), tenantID)
		if err != nil {
			// Log error for debugging but return default stats instead of 500
			// This allows the UI to load even if database is temporarily unavailable
			log.Printf("⚠️  Error getting sensor stats for tenant %s: %v", tenantID, err)
			c.JSON(http.StatusOK, stats)
			return
		}
		total := len(sensors)
		active, inactive, offlineN, errN, pending := 0, 0, 0, 0, 0
		for _, s := range sensors {
			switch s.Status {
			case "active":
				active++
			case "pending":
				pending++
			case "error":
				errN++
			case "offline":
				offlineN++
			case "inactive":
				inactive++
			default:
				// Unknown status — count as inactive so it is visible in breakdown, not as "active"
				inactive++
			}
		}
		stats["total_sensors"] = total
		stats["active_sensors"] = active
		stats["inactive_sensors"] = inactive + offlineN
		stats["error_sensors"] = errN
		stats["pending_sensors"] = pending
	}

	c.JSON(http.StatusOK, stats)
}

// GetPlatformSensorStats returns aggregate sensor stats across all tenants
// This endpoint is for platform monitoring and doesn't require tenant context
func (h *Handler) GetPlatformSensorStats(c *gin.Context) {
	// Platform monitoring query - acceptable to query sensor data directly
	// since this is the sensor-manager's own domain data
	var stats struct {
		ActiveSensors int `json:"active_sensors"`
		TotalSensors  int `json:"total_sensors"`
	}

	query := `
		SELECT 
			COALESCE(COUNT(*) FILTER (WHERE last_heartbeat > NOW() - INTERVAL '5 minutes'), 0) as active_sensors,
			COALESCE(COUNT(*), 0) as total_sensors
		FROM sensors
		WHERE deleted_at IS NULL
	`

	// RLS: cross-tenant — runs on the bypass role. These are platform-wide
	// counts over every tenant's sensors, so there is no app.tenant_id to set.
	// On the RLS-scoped handle both counts come back 0 with no error.
	if h.bypassDB == nil {
		c.JSON(http.StatusOK, stats)
		return
	}
	err := h.bypassDB.QueryRowContext(c.Request.Context(), query).Scan(&stats.ActiveSensors, &stats.TotalSensors)
	if err != nil {
		log.Printf("Error fetching platform sensor stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to fetch sensor stats",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetSensor returns sensor details by ID
func (h *Handler) GetSensor(c *gin.Context) {
	// The guard resolves the sensor with a tenant-scoped query, so it both
	// authorizes access and gives us the row to return.
	sensor, tenantID, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}

	// The host's full address inventory rides the single-sensor read (the fleet
	// list neither needs nor fetches it). Supplementary detail: a failure here
	// must not turn a working sensor page into an error. sensorService is nil in
	// the v2-only construction (NewHandlerWithService), so it is checked rather
	// than assumed.
	if h.sensorService != nil {
		addrs, err := h.sensorService.ListSensorAddresses(c.Request.Context(), tenantID, sensor.ID)
		if err != nil {
			h.log.WithError(err).WithField("sensor_id", sensor.ID).
				Warn("Failed to load recorded host addresses")
		} else {
			sensor.Addresses = addrs
		}
	}

	c.JSON(http.StatusOK, sensor)
}

// UpdateSensorStatus updates a sensor's status
func (h *Handler) UpdateSensorStatus(c *gin.Context) {
	sensor, tenantID, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}

	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if h.sensorServiceV2 == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "status update not supported"})
		return
	}

	if err := h.sensorServiceV2.UpdateSensorStatus(c.Request.Context(), sensor.ID, tenantID, req.Status); err != nil {
		h.logErr(c, err, "update sensor status", sensor.ID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "status updated"})
}

// DeleteSensor soft deletes a sensor
func (h *Handler) DeleteSensor(c *gin.Context) {
	sensor, tenantID, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}

	if h.sensorServiceV2 == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "delete not supported"})
		return
	}

	if err := h.sensorServiceV2.DeleteSensor(c.Request.Context(), sensor.ID, tenantID); err != nil {
		h.logErr(c, err, "delete sensor", sensor.ID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "sensor deleted"})
}

// CreateSensorCommand creates a command for a sensor
func (h *Handler) CreateSensorCommand(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID

	var req struct {
		CommandType string                 `json:"command_type" binding:"required"`
		Payload     map[string]interface{} `json:"payload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	cmd := &models.SensorCommand{
		ID:          uuid.New(),
		SensorID:    sensorID,
		CommandType: req.CommandType,
		Payload:     req.Payload,
		Status:      "pending",
		CreatedAt:   time.Now(),
	}
	// Use context with timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	// Use type assertion to underlying repository method signature
	// Create a minimal wrapper to satisfy the interface without exposing internal types
	if err := h.repo.CreateCommand(ctx, cmd); err != nil {
		h.logErr(c, err, "create sensor command", sensorID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"command": cmd})
}

// GetSensorCommands lists pending/delivered/acknowledged commands for a sensor
func (h *Handler) GetSensorCommands(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	commands, err := h.repo.GetRecentCommands(ctx, sensorID, 50)
	if err != nil {
		h.logErr(c, err, "get sensor commands", sensorID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"commands": commands})
}

// GetSensorHealth returns latest health metrics for a sensor
func (h *Handler) GetSensorHealth(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	metrics, err := h.repo.GetLatestHealthMetrics(ctx, sensorID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no health metrics found"})
		return
	}
	c.JSON(http.StatusOK, metrics)
}

// GetSensorHealthHistory returns historical health metrics for a sensor
func (h *Handler) GetSensorHealthHistory(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID

	// Get query parameters
	sinceStr := c.Query("since")
	limitStr := c.Query("limit")

	// Default to last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	if sinceStr != "" {
		if parsedTime, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = parsedTime
		}
	}

	// Default limit to 100
	limit := 100
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
			if limit > 1000 {
				limit = 1000 // Cap at 1000
			}
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	history, err := h.repo.GetHealthMetricsHistory(ctx, sensorID, since, limit)
	if err != nil {
		h.logErr(c, err, "get sensor health history", sensorID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query health history"})
		return
	}

	metrics := make([]models.SensorHealthMetrics, 0, len(history))
	for _, m := range history {
		metrics = append(metrics, *m)
	}

	c.JSON(http.StatusOK, gin.H{
		"metrics": metrics,
		"count":   len(metrics),
		"since":   since.Format(time.RFC3339),
	})
}

// GetSensorDiscoveries returns recent discovery batches for a sensor
func (h *Handler) GetSensorDiscoveries(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID

	// Get limit from query parameter, default to 50
	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	rows, err := h.repo.ListSensorDiscoveries(c.Request.Context(), sensorID, limit)
	if err != nil {
		h.logErr(c, err, "list sensor discoveries", sensorID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query discoveries"})
		return
	}

	discoveries := make([]map[string]interface{}, 0, len(rows))
	for _, d := range rows {
		discovery := map[string]interface{}{
			"id":         d.ID.String(),
			"sensor_id":  d.SensorID.String(),
			"batch_id":   d.BatchID,
			"protocol":   d.Protocol,
			"dest_ip":    d.DestIP,
			"port":       d.Port,
			"confidence": d.Confidence,
			"timestamp":  d.Timestamp.Format(time.RFC3339),
			"created_at": d.CreatedAt.Format(time.RFC3339),
		}

		// Promote selected metadata fields to top-level if present.
		if sourceIP, ok := d.Metadata["source_ip"].(string); ok {
			discovery["source_ip"] = sourceIP
		}
		if version, ok := d.Metadata["version"].(string); ok {
			discovery["version"] = version
		}
		if cipherSuite, ok := d.Metadata["cipher_suite"].(string); ok {
			discovery["cipher_suite"] = cipherSuite
		}
		if keySize, ok := d.Metadata["key_size"].(float64); ok {
			discovery["key_size"] = int(keySize)
		}

		discoveries = append(discoveries, discovery)
	}

	c.JSON(http.StatusOK, gin.H{
		"discoveries": discoveries,
		"count":       len(discoveries),
	})
}

// GetSensorDiscoveryCounts returns discovery counts for all sensors belonging to the tenant
// This is used to show tenant-specific discovery counts for both tenant-deployed and system sensors
func (h *Handler) GetSensorDiscoveryCounts(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	if h.sensorService == nil || h.sensorService.GetDB() == nil {
		c.JSON(http.StatusOK, gin.H{"counts": map[string]int{}})
		return
	}

	// Query discovery counts grouped by sensor_id for this tenant
	// This returns counts for both tenant-deployed sensors and system sensors
	// because system sensors record discoveries with the tenant's ID
	query := `
		SELECT s.id, COUNT(sd.id) as discovery_count
		FROM sensors s
		LEFT JOIN sensor_discoveries sd ON s.id = sd.sensor_id AND sd.tenant_id = $1
		WHERE s.tenant_id = $1 AND s.deleted_at IS NULL
		GROUP BY s.id`

	// Both `sensors` and `sensor_discoveries` are RLS-scoped and the caller's
	// tenant is already in hand, so this runs inside WithTenantTx. Unwrapped on
	// the crypto_app handle it returns no rows and the UI shows every sensor with
	// a discovery count of zero.
	counts := make(map[string]int)
	err := shareddatabase.WithTenantTx(c.Request.Context(), h.sensorService.GetDB(), tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(c.Request.Context(), query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var sensorID uuid.UUID
			var count int

			if e := rows.Scan(&sensorID, &count); e != nil {
				continue // Skip invalid rows
			}

			counts[sensorID.String()] = count
		}
		return rows.Err()
	})
	if err != nil {
		log.Printf("⚠️  Error querying discovery counts for tenant %s: %v", tenantID, err)
		c.JSON(http.StatusOK, gin.H{"counts": map[string]int{}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"counts": counts})
}
