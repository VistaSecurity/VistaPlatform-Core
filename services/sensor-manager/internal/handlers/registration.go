// Package handlers provides HTTP handlers for the sensor-manager service.
// This file contains handlers for sensor registration and pending sensor management,
// including registration key generation, IP validation, and mTLS certificate creation.
package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/certificates"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

// platformServerCACert returns the platform/mesh CA PEM to advertise to
// sensors as the SERVER trust anchor ( follow-up) when fail-closed sensor
// mTLS is enabled (AGENT_MTLS_REQUIRED). The sensor's passthrough listener
// presents the per-service mesh cert (platform-CA-signed), so the sensor must
// trust the platform CA — not the per-tenant CA that issued its client cert.
// Returns "" when mTLS isn't enforced or the CA file isn't readable, so the
// caller falls back to the legacy per-tenant CA.
func platformServerCACert() string {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("AGENT_MTLS_REQUIRED"))); v != "true" && v != "1" {
		return ""
	}
	path := os.Getenv("PLATFORM_CA_CERT_PATH")
	if path == "" {
		path = "/app/certs/ca.crt"
	}
	pem, err := os.ReadFile(path)
	if err != nil || len(pem) == 0 {
		return ""
	}
	return string(pem)
}

func advertisedServerCACert(clientIssuerCACertPEM string) string {
	if pca := platformServerCACert(); pca != "" {
		return pca
	}
	return clientIssuerCACertPEM
}

// advertisedControlPlaneURL returns the mTLS passthrough URL the sensor should
// switch to after registration. Registration itself happens on the
// edge-terminated public host (the sensor holds no client cert yet, and the
// passthrough listener requires one at the handshake); every subsequent call
// must instead reach the dedicated passthrough listener so the client cert
// arrives intact. The chart derives AGENT_MTLS_ADVERTISED_URL from
// agentMtls.backends.sensor-manager.dnsName + agentMtls.port. Empty when
// fail-closed mTLS isn't enforced — the sensor keeps its configured URL.
func advertisedControlPlaneURL() string {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("AGENT_MTLS_REQUIRED"))); v != "true" && v != "1" {
		return ""
	}
	return strings.TrimSpace(os.Getenv("AGENT_MTLS_ADVERTISED_URL"))
}

// RegistrationRequest represents a sensor registration request
type RegistrationRequest struct {
	RegistrationKey   string   `json:"registration_key" binding:"required"`
	Name              string   `json:"name" binding:"required"`
	Description       string   `json:"description"`
	Platform          string   `json:"platform" binding:"required"`
	Version           string   `json:"version" binding:"required"`
	Profile           string   `json:"profile" binding:"required"`
	NetworkInterfaces []string `json:"network_interfaces" binding:"required"`
	// AvailableInterfaces is the host's full NIC inventory, reported at
	// registration so the platform's interface picker is populated immediately
	// (without waiting for the first heartbeat). Optional for back-compat.
	AvailableInterfaces []string `json:"available_interfaces"`
	// IPAddress is the sensor's own view of its host address. Optional: a sensor
	// that cannot determine its address must be able to say so. It previously
	// sent the literal "127.0.0.1" to satisfy a required field, which recorded a
	// confident falsehood; an empty value now records NULL instead.
	IPAddress string   `json:"ip_address"`
	Tags      []string `json:"tags"`
	// ReportingInterval (seconds) is the sensor's configured data-send cadence,
	// reported so the platform records its real value from the start. Optional
	// for back-compat with older sensors.
	ReportingInterval *int `json:"reporting_interval,omitempty"`
	// CSR-based registration fields (optional for backward compatibility)
	CSR      string `json:"csr,omitempty"`       // Certificate Signing Request (PEM format)
	SensorID string `json:"sensor_id,omitempty"` // Proposed sensor ID (UUID string) for CSR CN
}

// RegistrationResponse represents the response to a registration request
type RegistrationResponse struct {
	SensorID             string          `json:"sensor_id"`
	RegistrationKey      string          `json:"registration_key"`
	ClientCert           string          `json:"client_cert"`                      // Signed certificate (CSR-based) or cert+key (legacy)
	ClientKey            string          `json:"client_key,omitempty"`             // Only in legacy flow, omitted in CSR flow
	ServerCACert         string          `json:"server_ca_cert"`                   // CA certificate for trust
	CertificateExpiresAt string          `json:"certificate_expires_at,omitempty"` // Certificate expiration timestamp
	ControlPlaneURL      string          `json:"control_plane_url"`
	ReportingInterval    int             `json:"reporting_interval"`
	Features             map[string]bool `json:"features"`
	Message              string          `json:"message"`
}

// AdminSettings represents admin configuration
type AdminSettings struct {
	KeyExpirationMinutes int  `json:"key_expiration_minutes"`
	MaxPendingSensors    int  `json:"max_pending_sensors"`
	RequireIPValidation  bool `json:"require_ip_validation"`
}

// AdminSettings represents admin configuration
var adminSettings = AdminSettings{
	KeyExpirationMinutes: 60,
	MaxPendingSensors:    50,
	RequireIPValidation:  false, // Default to disabled - IP validation is easily circumvented in modern networks
}

// CreatePendingSensor creates a new pending sensor registration
// This endpoint is called from the web UI to generate a registration key
// for a sensor that will be installed later. The key is time-limited
// and bound to a specific IP address for security.
func (h *Handler) CreatePendingSensor(c *gin.Context) {
	// Get tenant ID from context
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(400, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(400, gin.H{"error": "Invalid tenant ID"})
		return
	}

	var req struct {
		Name              string   `json:"name" binding:"required"`       // Human-readable sensor name
		IPAddress         string   `json:"ip_address" binding:"required"` // IP address for validation
		Tags              []string `json:"tags"`                          // Optional tags for grouping
		Profile           string   `json:"profile" binding:"required"`    // Deployment profile
		NetworkInterfaces []string `json:"network_interfaces"`            // Interfaces to monitor
		Description       string   `json:"description"`                   // Optional description
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Operator-supplied expected address — stays required. This is the value the
	// enrolling sensor's self-report is cross-checked against.
	if net.ParseIP(req.IPAddress) == nil {
		c.JSON(400, gin.H{"error": "Invalid IP address format"})
		return
	}

	// Check if sensor service is initialized
	if h.sensorService == nil {
		c.JSON(500, gin.H{"error": "Sensor service not initialized"})
		return
	}

	// Check if we've reached the maximum pending sensors
	count, err := h.sensorService.CountPendingSensors(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to check pending sensors count"})
		return
	}
	if count >= adminSettings.MaxPendingSensors {
		c.JSON(400, gin.H{"error": "Maximum pending sensors reached"})
		return
	}

	// Generate cryptographically random registration key
	// Format: REG-{32-char-hex} (e.g., REG-a1b2c3d4e5f6...)
	keyBytes := make([]byte, 16) // 16 bytes = 32 hex characters
	if _, err := rand.Read(keyBytes); err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate registration key"})
		return
	}
	key := fmt.Sprintf("REG-%s", hex.EncodeToString(keyBytes))

	// Create pending sensor
	pendingSensor := &models.PendingSensorRegistration{
		ID:                uuid.New(),
		TenantID:          tenantID,
		RegistrationKey:   key,
		Name:              req.Name,
		IPAddress:         req.IPAddress,
		Tags:              req.Tags,
		Profile:           req.Profile,
		NetworkInterfaces: req.NetworkInterfaces,
		Description:       &req.Description,
		ExpiresAt:         time.Now().Add(time.Duration(adminSettings.KeyExpirationMinutes) * time.Minute),
		Status:            "pending",
	}

	// Save to database
	err = h.sensorService.CreatePendingSensor(pendingSensor)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23514" { // check_violation (e.g. unknown profile)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid profile for pending registration. Supported profiles include datacenter_host, cloud_instance, end_user_machine, air_gapped, and device_interrogation (for the device interrogation agent).",
			})
			return
		}
		if h.log != nil {
			h.log.WithError(err).Error("Failed to create pending sensor")
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create pending sensor"})
		return
	}

	c.JSON(200, gin.H{
		"pending_sensor": pendingSensor,
		"installation_command": fmt.Sprintf(
			"sudo ./install-sensor.sh --key %s --ip %s --name %s --profile %s",
			key, req.IPAddress, req.Name, req.Profile,
		),
	})
}

// RegisterSensor handles sensor registration with IP validation
// This endpoint is called by the sensor during installation to register
// with the control plane. It validates the registration key, checks IP
// address binding, and returns mTLS certificates for secure communication.
func (h *Handler) RegisterSensor(c *gin.Context) {
	var req RegistrationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		h.log.WithError(err).Error("Failed to bind registration request JSON")
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Validate the sensor's self-reported address when it reports one. Empty is
	// allowed — see RegistrationRequest.IPAddress — but a malformed value is a
	// bug worth rejecting rather than storing.
	if req.IPAddress != "" && net.ParseIP(req.IPAddress) == nil {
		c.JSON(400, gin.H{"error": "Invalid IP address format"})
		return
	}

	// Check if sensor service is initialized
	if h.sensorService == nil {
		c.JSON(500, gin.H{"error": "Sensor service not initialized"})
		return
	}

	// Get pending sensor from database
	// This lookup validates the registration key and retrieves the tenant_id
	// The tenant_id from the registration key is the source of truth for tenant assignment
	pendingSensor, err := h.sensorService.GetPendingSensorByKey(req.RegistrationKey)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid or expired registration key"})
		return
	}

	// Security: Verify that the registration key's tenant_id is valid
	// This ensures the sensor is permanently tied to the correct tenant
	if pendingSensor.TenantID == uuid.Nil {
		c.JSON(400, gin.H{"error": "Invalid registration key: missing tenant association"})
		return
	}

	// Check if key has expired
	if time.Now().After(pendingSensor.ExpiresAt) {
		c.JSON(400, gin.H{"error": "Registration key has expired"})
		return
	}

	// Check if key has already been used
	if pendingSensor.Status == "used" {
		c.JSON(400, gin.H{"error": "Registration key has already been used"})
		return
	}

	// Cross-check the enrolling sensor's self-reported address against the one
	// the operator expected when they created the key. This catches the honest
	// mistakes it can catch — key redeemed on the wrong host, a stale key, a
	// copy-paste slip — and is logged on every registration so the mismatch is
	// visible even when enforcement is off.
	//
	// It is NOT an authentication control, and must not be mistaken for one:
	// the reported address is supplied by the caller, so anyone redeeming a
	// stolen key can simply claim the expected value. Authentication is the
	// per-agent client certificate issued from the tenant's CA (see
	// middleware.SensorAuth), which is cryptographic and revocable.
	//
	// The previous implementation also compared c.ClientIP(). That could never
	// work: behind an ingress, NAT, or kube-proxy the connection source is a
	// proxy or node address, never the sensor's. Its escape hatch was a stub
	// (isIPInSameSubnet returned ip1 == ip2), so enabling enforcement rejected
	// every registration in any Kubernetes install. Both are gone.
	if req.IPAddress != "" && pendingSensor.IPAddress != req.IPAddress {
		h.log.WithFields(logrus.Fields{
			"sensor_name": req.Name,
			"expected_ip": pendingSensor.IPAddress,
			"reported_ip": req.IPAddress,
			"enforced":    adminSettings.RequireIPValidation,
		}).Warn("Enrolling sensor reports a different address than the operator expected")

		if adminSettings.RequireIPValidation {
			c.JSON(400, gin.H{"error": "IP address does not match the registered IP address"})
			return
		}
	}

	// Determine sensor ID: use proposed ID from CSR if provided, otherwise generate new one
	var sensorID uuid.UUID
	if req.SensorID != "" {
		// Sensor proposed an ID in CSR
		var err error
		sensorID, err = uuid.Parse(req.SensorID)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid sensor_id format in request"})
			return
		}
	} else {
		// Legacy flow: generate sensor ID
		sensorID = uuid.New()
	}

	var sensorCertPEM string
	var sensorKeyPEM string
	var caCertPEM string
	var certExpiresAt time.Time

	// Create sensor registration object for service layer
	sensorRegistration := &models.SensorRegistration{
		RegistrationKey:     req.RegistrationKey,
		SensorName:          req.Name,
		SensorType:          req.Profile,
		Profile:             req.Profile,
		Platform:            req.Platform,
		IPAddress:           req.IPAddress,
		Version:             req.Version,
		Description:         req.Description,
		Tags:                req.Tags,
		NetworkInterfaces:   req.NetworkInterfaces,
		AvailableInterfaces: req.AvailableInterfaces,
		Capabilities:        req.NetworkInterfaces,
		ReportingInterval:   req.ReportingInterval, // sensor's reported data-send cadence (seconds)
		SensorID:            &sensorID,             // Pass pre-generated sensor ID
		Metadata: map[string]interface{}{
			"description": req.Description,
			"platform":    req.Platform,
			"tags":        req.Tags,
		},
	}

	// Enforce the tenant's subscription sensor cap before registering.
	// The tenant is resolved from the registration key (pendingSensor.TenantID),
	// not from an auth context, so the shared limit middleware can't gate this
	// route — call the service directly here, before the insert. Skipped only
	// when no DB is wired (validation-only unit tests).
	if db := h.sensorService.GetDB(); db != nil {
		limits := sharedservices.NewLimitEnforcementService(db)
		result, err := limits.CheckSensorLimit(pendingSensor.TenantID)
		if err != nil {
			h.log.WithError(err).Error("Failed to check sensor limit")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check sensor limit"})
			return
		}
		if !result.Allowed {
			c.JSON(http.StatusPaymentRequired, gin.H{
				"error":          result.Message,
				"current_usage":  result.CurrentUsage,
				"limit":          result.Limit,
				"upgrade_prompt": result.UpgradePrompt,
			})
			return
		}
	}

	// Register sensor in database FIRST (before issuing certificate)
	// The sensor record must exist before storing the certificate due to foreign key constraint
	sensor, err := h.sensorService.RegisterSensor(sensorRegistration)
	if err != nil {
		h.log.WithError(err).Error("Failed to register sensor in database")
		c.JSON(500, gin.H{
			"error": "Failed to register sensor",
		})
		return
	}

	h.log.WithFields(map[string]interface{}{
		"sensor_id": sensor.ID.String(),
		"name":      sensor.Name,
		"tenant_id": sensor.TenantID.String(),
	}).Info("Sensor registered successfully")

	// Verify sensor ID matches (should always match since we pass it)
	if sensor.ID != sensorID {
		// This should never happen, but log if it does
		h.log.WithFields(map[string]interface{}{
			"expected_sensor_id": sensorID.String(),
			"actual_sensor_id":   sensor.ID.String(),
		}).Warn("Sensor ID mismatch between request and persisted record")
		sensorID = sensor.ID // Use actual ID from database
	}

	// Verify sensor record exists in database before issuing certificate
	// This ensures the committed transaction is visible to the certificate service.
	// Uses the bypass handle: registration is a pre-tenant-resolution bootstrap
	// path (the sensor was created on bypassDB), so this verify-by-id read must
	// also bypass RLS — on the crypto_app handle with no app.tenant_id set it
	// would fail closed (0 rows) and 500 even though the row exists.
	var verifySensorID uuid.UUID
	verifyErr := h.sensorService.GetBypassDB().QueryRow("SELECT id FROM sensors WHERE id = $1", sensorID).Scan(&verifySensorID)
	if verifyErr != nil {
		c.JSON(500, gin.H{
			"error":   "Sensor record not found after creation",
			"details": fmt.Sprintf("Sensor ID %s was not found in database: %v", sensorID.String(), verifyErr),
		})
		return
	}

	// Small delay to ensure transaction commit is fully visible across all connections
	// This handles potential connection pooling and transaction isolation edge cases
	time.Sleep(100 * time.Millisecond)

	// Double-check sensor exists with a fresh query (ensures visibility)
	var verifySensorID2 uuid.UUID
	verifyErr2 := h.sensorService.GetBypassDB().QueryRow("SELECT id FROM sensors WHERE id = $1", sensorID).Scan(&verifySensorID2)
	if verifyErr2 != nil {
		c.JSON(500, gin.H{
			"error":   "Sensor record not found after verification delay",
			"details": fmt.Sprintf("Sensor ID %s was not found in database after delay: %v", sensorID.String(), verifyErr2),
		})
		return
	}

	// Now that sensor record exists and is verified (twice), issue and store certificate
	// Check if CSR is provided (new CSR-based flow)
	if req.CSR != "" {
		// CSR-based registration flow
		// Initialize certificate service with encryption key from handler
		// Use the same database connection pool to ensure visibility
		certService := certificates.NewCertificateService(h.sensorService.GetDB(), h.sensorService.GetBypassDB(), h.encryptionKey)

		// Issue certificate from CSR (sensor record now exists and verified, so foreign key constraint will be satisfied)
		certPEM, err := certService.IssueCertificate(pendingSensor.TenantID, sensorID, req.CSR)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to issue certificate from CSR"})
			return
		}

		sensorCertPEM = certPEM
		sensorKeyPEM = "" // Private key never sent in CSR flow

		// Get CA certificate for the tenant
		caManager := certificates.NewCAManager(h.sensorService.GetDB(), h.sensorService.GetBypassDB())
		ca, err := caManager.GetActiveCA(pendingSensor.TenantID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get CA certificate"})
			return
		}
		caCertPEM = ca.CACertPEM

		// Get certificate expiration from stored certificate
		cert, err := certService.GetCertificate(sensorID)
		if err == nil && cert != nil {
			certExpiresAt = cert.ExpiresAt
		} else {
			// Default to 1 year from now if we can't retrieve it
			certExpiresAt = time.Now().AddDate(1, 0, 0)
		}
	} else {
		// Legacy flow: generate certificates (backward compatibility)
		caCertPEM, caKeyPEM, err := h.generateCACertificate()
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to generate CA certificate"})
			return
		}

		sensorCertPEM, sensorKeyPEM, err = h.generateSensorCertificate(sensorID, caCertPEM, caKeyPEM)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to generate sensor certificate"})
			return
		}

		// Legacy flow: default expiration
		certExpiresAt = time.Now().AddDate(1, 0, 0)
	}

	// Create sensor configuration based on profile
	features := getProfileFeatures(req.Profile)
	reportingInterval := getProfileReportingInterval(req.Profile)

	// follow-up: server-trust switch. caCertPEM above is the sensor's
	// CLIENT-cert issuer (per-tenant CA). With fail-closed sensor mTLS the
	// sensor connects to the dedicated passthrough listener, whose SERVER cert
	// is the per-service mesh cert (platform-CA-signed, NOT the tenant CA).
	// Advertise the platform CA as the sensor's server trust anchor so server
	// verification succeeds; the sensor keeps presenting its per-tenant client
	// cert. Falls back to the tenant CA when mTLS isn't enforced or the
	// platform CA isn't mounted.
	response := RegistrationResponse{
		SensorID:             sensorID.String(),
		RegistrationKey:      req.RegistrationKey,
		ClientCert:           sensorCertPEM,
		ClientKey:            sensorKeyPEM, // Empty string in CSR flow, populated in legacy flow
		ServerCACert:         advertisedServerCACert(caCertPEM),
		CertificateExpiresAt: certExpiresAt.Format(time.RFC3339),
		ControlPlaneURL:      advertisedControlPlaneURL(),
		ReportingInterval:    reportingInterval,
		Features:             features,
		Message:              "Sensor registered successfully",
	}

	c.JSON(200, response)
}

// GetPendingSensors returns all pending sensor registrations
func (h *Handler) GetPendingSensors(c *gin.Context) {
	// Get tenant ID from context
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(400, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(400, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Prefer V2 service when available
	if h.sensorServiceV2 != nil {
		pending, err := h.sensorServiceV2.ListPendingSensors(c.Request.Context(), tenantID)
		if err != nil {
			// Return empty array for any error to prevent UI breakage
			// This gracefully handles missing tables, database errors, etc.
			// Log the error for debugging
			h.log.WithError(err).WithField("tenant_id", tenantID).Warn("GetPendingSensors error (returning empty array)")
			c.JSON(200, gin.H{"pending_sensors": []models.PendingSensorRegistration{}})
			return
		}

		// Convert to response format - ensure we always return an array
		responseSensors := []models.PendingSensorRegistration{}
		for _, sensor := range pending {
			// Check if expired
			if time.Now().After(sensor.ExpiresAt) && sensor.Status == "pending" {
				sensor.Status = "expired"
			}
			responseSensors = append(responseSensors, *sensor)
		}

		c.JSON(200, gin.H{"pending_sensors": responseSensors})
		return
	}

	// Fallback to legacy service
	if h.sensorService == nil {
		c.JSON(500, gin.H{"error": "Sensor service not initialized"})
		return
	}

	// Get pending sensors from database
	sensors, err := h.sensorService.GetPendingSensors(tenantID)
	if err != nil {
		// Return empty array for any error to prevent UI breakage
		// This gracefully handles missing tables, database errors, etc.
		// Log the error for debugging
		h.log.WithError(err).WithField("tenant_id", tenantID).Warn("GetPendingSensors error (returning empty array)")
		c.JSON(200, gin.H{"pending_sensors": []models.PendingSensorRegistration{}})
		return
	}

	// Convert to response format - ensure we always return an array
	responseSensors := []models.PendingSensorRegistration{}
	for _, sensor := range sensors {
		// Check if expired
		if time.Now().After(sensor.ExpiresAt) && sensor.Status == "pending" {
			sensor.Status = "expired"
		}
		responseSensors = append(responseSensors, sensor)
	}

	c.JSON(200, gin.H{"pending_sensors": responseSensors})
}

// DeletePendingSensor deletes a pending sensor registration
func (h *Handler) DeletePendingSensor(c *gin.Context) {
	// Get tenant ID from context
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(400, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(400, gin.H{"error": "Invalid tenant ID"})
		return
	}

	key := c.Param("key")
	if key == "" {
		c.JSON(400, gin.H{"error": "Registration key is required"})
		return
	}

	// Prefer V2 service when available
	if h.sensorServiceV2 != nil {
		err := h.sensorServiceV2.DeletePendingSensor(c.Request.Context(), tenantID, key)
		if err != nil {
			if err.Error() == "pending sensor not found" || err.Error() == "pending sensor does not belong to tenant" {
				c.JSON(404, gin.H{"error": "Pending sensor not found"})
				return
			}
			c.JSON(500, gin.H{"error": "Internal server error"})
			return
		}
		c.JSON(200, gin.H{"message": "Pending sensor deleted successfully"})
		return
	}

	// Fallback to legacy service
	if h.sensorService == nil {
		c.JSON(500, gin.H{"error": "Sensor service not initialized"})
		return
	}

	// Legacy service doesn't validate tenant, but RLS should protect us
	err := h.sensorService.DeletePendingSensor(key)
	if err != nil {
		c.JSON(404, gin.H{"error": "Pending sensor not found"})
		return
	}

	c.JSON(200, gin.H{"message": "Pending sensor deleted successfully"})
}

// GetAdminSettings returns current admin settings
func (h *Handler) GetAdminSettings(c *gin.Context) {
	c.JSON(200, adminSettings)
}

// UpdateAdminSettings updates admin settings
func (h *Handler) UpdateAdminSettings(c *gin.Context) {
	var newSettings AdminSettings
	if err := c.ShouldBindJSON(&newSettings); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Validate settings
	if newSettings.KeyExpirationMinutes < 5 || newSettings.KeyExpirationMinutes > 1440 {
		c.JSON(400, gin.H{"error": "Key expiration must be between 5 and 1440 minutes"})
		return
	}

	if newSettings.MaxPendingSensors < 1 || newSettings.MaxPendingSensors > 1000 {
		c.JSON(400, gin.H{"error": "Max pending sensors must be between 1 and 1000"})
		return
	}

	adminSettings = newSettings
	c.JSON(200, gin.H{"message": "Admin settings updated successfully"})
}

// Helper functions

func getProfileFeatures(profile string) map[string]bool {
	features := map[string]bool{
		"tls_analysis":         true,
		"ssh_analysis":         true,
		"certificate_analysis": true,
		"active_probing":       false,
		"network_discovery":    false,
		"air_gapped_export":    false,
	}

	switch profile {
	case "datacenter_host":
		features["active_probing"] = true
		features["network_discovery"] = true
	case "cloud_instance":
		features["active_probing"] = true
	case "end_user_machine":
		// Minimal features
	case "air_gapped":
		features["air_gapped_export"] = true
		features["active_probing"] = false
		features["network_discovery"] = false
	}

	return features
}

func getProfileReportingInterval(profile string) int {
	switch profile {
	case "datacenter_host":
		return 30 // 30 seconds
	case "cloud_instance":
		return 60 // 1 minute
	case "end_user_machine":
		return 300 // 5 minutes
	case "air_gapped":
		return 3600 // 1 hour
	default:
		return 60
	}
}

// generateCACertificate generates a CA certificate for mTLS
func (h *Handler) generateCACertificate() (string, string, error) {
	// Generate private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"VistaPlatform"},
			OrganizationalUnit: []string{"VistaPlatform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			StreetAddress:      []string{""},
			PostalCode:         []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}

	// Encode CA certificate
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Encode CA private key
	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})

	return string(caCertPEM), string(caKeyPEM), nil
}

// generateSensorCertificate generates a client certificate for a sensor
// NOTE: This is the legacy method. New CSR-based flow uses CertificateService.IssueCertificate
// This is kept for backward compatibility during migration
func (h *Handler) generateSensorCertificate(sensorID uuid.UUID, caCertPEM, caKeyPEM string) (string, string, error) {
	// Parse CA certificate
	caBlock, _ := pem.Decode([]byte(caCertPEM))
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return "", "", err
	}

	// Parse CA private key
	caKeyBlock, _ := pem.Decode([]byte(caKeyPEM))
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return "", "", err
	}

	// Generate sensor private key
	sensorKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Create sensor certificate template
	// IMPORTANT: Use sensor ID (UUID string) as CN, not sensor name
	// This matches what middleware expects (sensor_auth.go line 41)
	sensorIDStr := sensorID.String()
	sensorTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:       []string{"VistaPlatform"},
			OrganizationalUnit: []string{"VistaPlatform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			StreetAddress:      []string{""},
			PostalCode:         []string{""},
			CommonName:         sensorIDStr, // Use sensor ID, not name
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{},
		DNSNames:    []string{sensorIDStr},
	}

	// Create sensor certificate
	sensorCertDER, err := x509.CreateCertificate(rand.Reader, &sensorTemplate, caCert, &sensorKey.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}

	// Encode sensor certificate
	sensorCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: sensorCertDER,
	})

	// Encode sensor private key
	sensorKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(sensorKey),
	})

	return string(sensorCertPEM), string(sensorKeyPEM), nil
}

// generateSensorCSR creates a fresh private key and CSR for server-side admin
// reissue. The returned key is sent once to the admin flow, while the CSR is
// signed through CertificateService so the cert is tenant-CA-signed and stored.
func (h *Handler) generateSensorCSR(sensorID uuid.UUID) (string, string, error) {
	sensorKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	sensorIDStr := sensorID.String()
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"VistaPlatform"},
			OrganizationalUnit: []string{"VistaPlatform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			CommonName:         sensorIDStr,
		},
		DNSNames: []string{sensorIDStr},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, sensorKey)
	if err != nil {
		return "", "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(sensorKey),
	})

	return string(csrPEM), string(keyPEM), nil
}
