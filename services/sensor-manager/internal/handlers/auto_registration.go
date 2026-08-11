package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/certificates"
)

// AutoRegisterSensorRequest represents an auto-registration request from a platform service
type AutoRegisterSensorRequest struct {
	SensorID    string   `json:"sensor_id" binding:"required"` // Fixed sensor ID (e.g., "platform-discovery-sensor")
	TenantID    string   `json:"tenant_id" binding:"required"` // Tenant ID to register for
	CSR         string   `json:"csr" binding:"required"`       // Certificate Signing Request (PEM format)
	Name        string   `json:"name,omitempty"`               // Optional: sensor name (defaults to service name)
	Description string   `json:"description,omitempty"`        // Optional: sensor description
	Platform    string   `json:"platform,omitempty"`           // Optional: platform (defaults to "platform")
	Version     string   `json:"version,omitempty"`            // Optional: version (defaults to "system")
	Profile     string   `json:"profile,omitempty"`            // Optional: profile (defaults to "discovery")
	Tags        []string `json:"tags,omitempty"`               // Optional: tags
}

// AutoRegisterSensorResponse represents the response to an auto-registration request
type AutoRegisterSensorResponse struct {
	SensorID             string `json:"sensor_id"`
	TenantID             string `json:"tenant_id"`
	ClientCert           string `json:"client_cert"`            // Signed certificate
	ServerCACert         string `json:"server_ca_cert"`         // CA certificate for trust
	CertificateExpiresAt string `json:"certificate_expires_at"` // Certificate expiration timestamp
	Message              string `json:"message"`
}

// AutoRegisterSensor handles auto-registration of platform sensors using bootstrap mTLS certificate authentication
// This endpoint is called by platform services (e.g., cluster-sensor-service) to register themselves
// as sensors for a specific tenant. It bypasses the normal registration key flow.
func (h *Handler) AutoRegisterSensor(c *gin.Context) {
	// Get service name from context (set by BootstrapAuth middleware)
	serviceName, exists := c.Get("serviceName")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Service name not found in context"})
		return
	}

	serviceNameStr, ok := serviceName.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid service name type"})
		return
	}

	// Validate service is authorized for sensor registration
	// Both cluster-sensor-service and device-interrogation-service can register
	allowedServices := map[string]bool{
		"cluster-sensor-service":       true,
		"device-interrogation-service": true,
	}
	if !allowedServices[serviceNameStr] {
		c.JSON(http.StatusForbidden, gin.H{
			"error":        "Service not authorized for sensor registration",
			"service_name": serviceNameStr,
		})
		return
	}

	var req AutoRegisterSensorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Parse tenant ID
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id format"})
		return
	}

	// Parse sensor ID (must be a valid UUID)
	sensorID, err := uuid.Parse(req.SensorID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sensor_id format"})
		return
	}

	// Validate CSR
	if req.CSR == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSR is required"})
		return
	}

	// Parse and validate CSR
	csrBlock, _ := pem.Decode([]byte(req.CSR))
	if csrBlock == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CSR format"})
		return
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse CSR"})
		return
	}

	// Validate CSR signature
	if err := csr.CheckSignature(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSR signature validation failed"})
		return
	}

	// Validate CSR Common Name matches sensor ID
	if csr.Subject.CommonName != sensorID.String() {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("CSR Common Name '%s' does not match sensor_id '%s'", csr.Subject.CommonName, sensorID.String()),
		})
		return
	}

	// Set defaults
	name := req.Name
	if name == "" {
		name = "Platform Discovery Sensor"
	}
	platform := req.Platform
	if platform == "" {
		platform = "platform"
	}
	version := req.Version
	if version == "" {
		version = "system"
	}
	profile := req.Profile
	if profile == "" {
		profile = "discovery"
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{"system", "discovery", "platform"}
	}

	// Initialize certificate service
	if h.encryptionKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption key not configured"})
		return
	}

	certService := certificates.NewCertificateService(h.sensorService.GetDB(), h.sensorService.GetBypassDB(), h.encryptionKey)

	// Issue certificate from CSR
	certPEM, err := certService.IssueCertificate(tenantID, sensorID, req.CSR)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to issue certificate from CSR",
		})
		return
	}

	// Get CA certificate
	caManager := certificates.NewCAManager(h.sensorService.GetDB(), h.sensorService.GetBypassDB())
	ca, err := caManager.GetOrCreateActiveCA(tenantID, h.encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get CA certificate",
		})
		return
	}

	// Get certificate expiration
	cert, err := certService.GetCertificate(sensorID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get issued certificate",
		})
		return
	}

	// Check if sensor already exists
	existingSensor, err := h.sensorService.GetSensor(sensorID)
	if err == nil && existingSensor != nil {
		// Sensor exists, update it
		existingSensor.Name = name
		if req.Description != "" {
			existingSensor.Description = &req.Description
		}
		existingSensor.Platform = platform
		existingSensor.Version = version
		existingSensor.Profile = profile
		existingSensor.Tags = tags
		existingSensor.Status = "active"
		existingSensor.LastHeartbeat = &time.Time{}
		*existingSensor.LastHeartbeat = time.Now()

		if err := h.sensorService.UpdateSensor(existingSensor); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update existing sensor",
			})
			return
		}
	} else {
		// Sensor doesn't exist, create it directly in the database
		query := `
			INSERT INTO sensors (id, tenant_id, name, sensor_type, description, platform, version, profile, status, network_interfaces, tags, created_at, updated_at, last_heartbeat)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				platform = EXCLUDED.platform,
				version = EXCLUDED.version,
				profile = EXCLUDED.profile,
				status = EXCLUDED.status,
				tags = EXCLUDED.tags,
				updated_at = EXCLUDED.updated_at,
				last_heartbeat = EXCLUDED.last_heartbeat
		`

		now := time.Now()
		var descriptionPtr *string
		if req.Description != "" {
			descriptionPtr = &req.Description
		}

		_, err = h.sensorService.GetDB().Exec(
			query,
			sensorID,
			tenantID,
			name,
			profile,
			descriptionPtr,
			platform,
			version,
			profile,
			"active",
			pq.Array([]string{}),
			pq.Array(tags),
			now,
			now,
			now,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create sensor",
			})
			return
		}
	}

	// Return response
	response := AutoRegisterSensorResponse{
		SensorID:             sensorID.String(),
		TenantID:             tenantID.String(),
		ClientCert:           certPEM,
		ServerCACert:         ca.CACertPEM,
		CertificateExpiresAt: cert.ExpiresAt.Format(time.RFC3339),
		Message:              "Platform sensor registered successfully",
	}

	c.JSON(http.StatusOK, response)
}
